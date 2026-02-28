/*
 * msFuzz Unpacking Harness
 * 
 * Automated unpacker for VMProtect and similar packers using msFuzz/kAFL infrastructure.
 * Leverages Intel PT tracing and hypervisor transparency to extract unpacked code.
 *
 * Based on: https://github.com/0dayResearchLab/kafl.targets/blob/master/windows_x86_64/src/driver/vuln_test.c
 * 
 * Usage: unpack_harness.exe <packed_executable.exe> [timeout_ms] [dump_mode]
 *   timeout_ms: Wait time for unpacking (default: 5000ms)
 *   dump_mode:  0 = dump all executable sections (default)
 *               1 = dump entire process memory
 *               2 = dump only .text section
 *
 * Copyright 2024 0dayResearchLab
 * SPDX-License-Identifier: MIT
 */

#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include "nyx_api.h"

/* Configuration */
#define DEFAULT_TIMEOUT_MS      5000
#define MAX_DUMP_SIZE           (64 * 1024 * 1024)  /* 64MB max dump */
#define INFO_SIZE               (128 << 10)         /* 128KB info string */

/* Dump modes */
#define DUMP_MODE_EXECUTABLE    0
#define DUMP_MODE_FULL          1
#define DUMP_MODE_TEXT_ONLY     2

/* PE parsing helpers */
#define RVA_TO_VA(base, rva) ((LPVOID)((UINT_PTR)(base) + (rva)))

typedef struct {
    UINT64 base_address;
    UINT64 size;
    char name[64];
    DWORD characteristics;
} section_info_t;

typedef struct {
    HANDLE process;
    HANDLE thread;
    DWORD pid;
    UINT64 image_base;
    UINT64 entry_point;
    UINT64 original_entry_point;  /* OEP - detected during unpacking */
    UINT64 size_of_image;
    section_info_t sections[64];
    int section_count;
} target_process_t;

/* Global state */
static target_process_t g_target = {0};
static int g_dump_mode = DUMP_MODE_EXECUTABLE;
static DWORD g_timeout_ms = DEFAULT_TIMEOUT_MS;
static char g_output_prefix[MAX_PATH] = "unpacked";

/*
 * Initialize agent handshake with kAFL/Nyx host
 * This must be called before any tracing operations
 */
void init_agent_handshake(void) {
    hprintf("[+] Unpacker: Initiating fuzzer handshake...\n");

    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

    /* Submit our CR3 */
    // kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    /* Tell kAFL we're running in 64bit mode */
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

    /* Request information on available (host) capabilities */
    volatile host_config_t host_config;
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
    
    if (host_config.host_magic != NYX_HOST_MAGIC ||
        host_config.host_version != NYX_HOST_VERSION) {
        habort("Host config magic/version mismatch!\n");
    }

    hprintf("\thost_config.bitmap_size: 0x%lx\n", host_config.bitmap_size);
    hprintf("\thost_config.payload_buffer_size: 0x%lx\n", host_config.payload_buffer_size);

    /* Submit agent configuration */
    volatile agent_config_t agent_config = {0};
    agent_config.agent_magic = NYX_AGENT_MAGIC;
    agent_config.agent_version = NYX_AGENT_VERSION;
    agent_config.agent_tracing = 0;           /* trace by host */
    agent_config.agent_ijon_tracing = 0;      /* no IJON */
    agent_config.agent_non_reload_mode = 1;   /* single-shot unpacking */
    agent_config.coverage_bitmap_size = host_config.bitmap_size;

    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);
    
    hprintf("[+] Unpacker: Handshake complete\n");
}

/*
 * Set Intel PT IP filter range to target process's usermode address space
 * This enables coverage collection for the unpacking process
 */
void set_ip_range_usermode(UINT64 base, UINT64 size, int index) {
    uint64_t buffer[3];
    buffer[0] = base;
    buffer[1] = base + size;
    buffer[2] = index;
    
    kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (UINT64)buffer);
    hprintf("[+] Unpacker: IP range %d set to 0x%llx - 0x%llx\n", index, base, base + size);
}

/*
 * 32-bit 타겟 프로세스에서 DLL 베이스 주소를 찾는 함수
 * ASLR 특성상 시스템 DLL(kernel32.dll, ntdll.dll)은 64비트 하네스의 32비트 버전을 찾으면 됨
 * (Windows의 SysWOW64 시스템 DLL은 부팅 시 모든 프로세스에서 동일한 베이스를 가짐)
 */
DWORD find_module_base_32(HANDLE hProcess, DWORD pid, const char* module_name) {
    // SUSPENDED 상태의 WOW64(32-bit) 프로세스는 Ldr 초기화 전이라 CreateToolhelp32Snapshot이 실패함.
    // 하지만 ASLR 특성상 ntdll.dll과 kernel32.dll의 32비트 베이스는 우리(64비트)가 32비트 모듈을 
    // 로드해봐도 알 수 있음. (다만 하네스가 64비트이므로 시스템 경로의 32비트 dll을 매핑해봐야 함)
    
    // 간이 구현: 대상 프로세스의 32-bit PEB를 읽어 매핑된 32비트 ntdll.dll 베이스를 알아내거나, 
    // ResumeThread 후 잠시 대기했다가 다시 SuspendThread 후 Snaphot을 찍는 방법이 가장 확실함.
    
    // 하지만, 여기서는 가장 안정적인 방법으로: 하네스에서 ResumeThread를 먼저 하고 Sleep 한 다음 
    // 훅을 설치하도록 구조를 변경할 예정이므로 기존 코드는 임시로 실패를 반환하지 않고 대기 루프를 돌게 함.
    
    MODULEENTRY32 me32;
    HANDLE hSnap = INVALID_HANDLE_VALUE;
    int retries = 50; // 최대 5초 대기 (100ms * 50)
    
    while (retries-- > 0) {
        hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hSnap != INVALID_HANDLE_VALUE) {
            break;
        }
        Sleep(100); // Ldr 초기화를 기다림
    }
    
    if (hSnap == INVALID_HANDLE_VALUE) {
        hprintf("[-] CreateToolhelp32Snapshot failed after retries: 0x%X\n", GetLastError());
        return 0;
    }
    
    me32.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(hSnap, &me32)) {
        CloseHandle(hSnap);
        return 0;
    }
    
    do {
        if (_stricmp(me32.szModule, module_name) == 0) {
            DWORD base = (DWORD)(UINT_PTR)me32.modBaseAddr;
            hprintf("[+] Found 32-bit %s at 0x%08x (size: 0x%x)\n", 
                    module_name, base, me32.modBaseSize);
            CloseHandle(hSnap);
            return base;
        }
    } while (Module32Next(hSnap, &me32));
    
    CloseHandle(hSnap);
    hprintf("[-] Module %s not found in 32-bit process\n", module_name);
    return 0;
}

/*
 * 32-bit PE의 Export Table을 파싱해서 함수 주소를 찾는 함수
 * hProcess: 타겟 프로세스 핸들
 * dll_base: DLL의 베이스 주소 (32-bit)
 * func_name: 찾을 함수 이름
 */
DWORD find_export_in_remote_32(HANDLE hProcess, DWORD dll_base, const char* func_name) {
    BYTE header[4096];
    SIZE_T br;
    
    if (!ReadProcessMemory(hProcess, (LPCVOID)(UINT_PTR)dll_base, header, sizeof(header), &br)) {
        hprintf("[-] Failed to read DLL header at 0x%08x\n", dll_base);
        return 0;
    }
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)header;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    
    /* 32-bit PE: IMAGE_NT_HEADERS32 */
    PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)(header + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        hprintf("[-] Not a 32-bit PE (magic: 0x%x)\n", nt->OptionalHeader.Magic);
        return 0;
    }
    
    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (export_rva == 0) return 0;
    
    /* Export Directory 읽기 */
    BYTE* export_buf = (BYTE*)VirtualAlloc(NULL, export_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!export_buf) return 0;
    
    if (!ReadProcessMemory(hProcess, (LPCVOID)(UINT_PTR)(dll_base + export_rva), 
                           export_buf, export_size, &br)) {
        VirtualFree(export_buf, 0, MEM_RELEASE);
        return 0;
    }
    
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)export_buf;
    
    /* Name, Ordinal, Function 테이블의 RVA (export directory 기준으로 offset 계산) */
    DWORD names_rva = exports->AddressOfNames;
    DWORD ordinals_rva = exports->AddressOfNameOrdinals;
    DWORD functions_rva = exports->AddressOfFunctions;
    
    /* 각 테이블을 읽기 */
    DWORD num_names = exports->NumberOfNames;
    DWORD* name_rvas = (DWORD*)VirtualAlloc(NULL, num_names * 4, MEM_COMMIT, PAGE_READWRITE);
    WORD* ordinals = (WORD*)VirtualAlloc(NULL, num_names * 2, MEM_COMMIT, PAGE_READWRITE);
    DWORD num_funcs = exports->NumberOfFunctions;
    DWORD* func_rvas = (DWORD*)VirtualAlloc(NULL, num_funcs * 4, MEM_COMMIT, PAGE_READWRITE);
    
    ReadProcessMemory(hProcess, (LPCVOID)(UINT_PTR)(dll_base + names_rva), 
                      name_rvas, num_names * 4, &br);
    ReadProcessMemory(hProcess, (LPCVOID)(UINT_PTR)(dll_base + ordinals_rva), 
                      ordinals, num_names * 2, &br);
    ReadProcessMemory(hProcess, (LPCVOID)(UINT_PTR)(dll_base + functions_rva), 
                      func_rvas, num_funcs * 4, &br);
    
    DWORD result = 0;
    char name_buf[256];
    
    for (DWORD i = 0; i < num_names; i++) {
        if (ReadProcessMemory(hProcess, (LPCVOID)(UINT_PTR)(dll_base + name_rvas[i]), 
                              name_buf, sizeof(name_buf), &br)) {
            name_buf[255] = '\0';
            if (strcmp(name_buf, func_name) == 0) {
                WORD ordinal = ordinals[i];
                result = dll_base + func_rvas[ordinal];
                break;
            }
        }
    }
    
    VirtualFree(name_rvas, 0, MEM_RELEASE);
    VirtualFree(ordinals, 0, MEM_RELEASE);
    VirtualFree(func_rvas, 0, MEM_RELEASE);
    VirtualFree(export_buf, 0, MEM_RELEASE);
    
    return result;
}

/*
 * Resolve and submit Windows API addresses for hook-based detection.
 * System DLLs share the same base address across all processes in a
 * boot session, so our own GetProcAddress results are valid for the child.
 */
void setup_api_hooks(void) {
    /* 
     * 중요: 프로세스가 SUSPENDED 상태에서는 DLL이 아직 로드 안 되었을 수 있음!
     * ResumeThread → Sleep → SuspendThread 후, 또는 NtResumeProcess 후 호출해야 함
     * 또는 CreateProcess 이후 프로세스 초기화가 완료된 시점에 호출
     */
    
    /* 32-bit 타겟의 kernel32.dll / ntdll.dll 베이스 주소 찾기 */
    DWORD k32_base = find_module_base_32(g_target.process, g_target.pid, "kernel32.dll");
    DWORD ntdll_base = find_module_base_32(g_target.process, g_target.pid, "ntdll.dll");
    
    if (!k32_base || !ntdll_base) {
        hprintf("[-] Failed to find 32-bit DLL bases. Skipping API hooks.\n");
        return;
    }
    
    /* 32-bit Export Table에서 함수 주소 추출 */
    typedef struct {
        const char* dll_name;
        DWORD dll_base;
        const char* func_name;
    } hook_target_t;
    
    hook_target_t targets[] = {
        {"kernel32.dll", k32_base, "GetProcAddress"},
        {"kernel32.dll", k32_base, "VirtualAlloc"},
        {"kernel32.dll", k32_base, "VirtualProtect"},
        {"kernel32.dll", k32_base, "WriteProcessMemory"},
        {"kernel32.dll", k32_base, "LoadLibraryA"},
        {"kernel32.dll", k32_base, "LoadLibraryW"},
        {"ntdll.dll",    ntdll_base, "NtProtectVirtualMemory"},
        {"ntdll.dll",    ntdll_base, "NtWriteVirtualMemory"},
    };
    
    int num_targets = sizeof(targets) / sizeof(targets[0]);
    
    /* 하나의 struct에 모든 hook을 채움 */
    static kafl_api_hook_t hook_data __attribute__((aligned(4096)));
    memset((void*)&hook_data, 0, sizeof(hook_data));
    hook_data.num_hooks = 0;
    
    for (int i = 0; i < num_targets && i < MAX_API_HOOKS; i++) {
        DWORD addr = find_export_in_remote_32(g_target.process, targets[i].dll_base, targets[i].func_name);
        if (addr) {
            hprintf("[+] Hook target: %s!%s @ 0x%08x (32-bit)\n", 
                    targets[i].dll_name, targets[i].func_name, addr);
            hook_data.addresses[hook_data.num_hooks] = (uint64_t)addr;
            snprintf((char*)hook_data.names[hook_data.num_hooks], 64, "%s!%s",
                     targets[i].dll_name, targets[i].func_name);
            hook_data.num_hooks++;
        } else {
            hprintf("[-] Failed to resolve %s!%s\n", 
                    targets[i].dll_name, targets[i].func_name);
        }
    }
    
    if (hook_data.num_hooks > 0) {
        hprintf("[+] Installing %llu API hooks via hypercall...\n", hook_data.num_hooks);
        kAFL_hypercall(HYPERCALL_KAFL_HOOK_API, (uintptr_t)&hook_data);
    }
    /*
    static kafl_api_hook_t hook_data __attribute__((aligned(4096)));
    memset(&hook_data, 0, sizeof(hook_data));
    struct {
        const char *dll;
        const char *func;
    } apis[] = {
        {"kernel32.dll", "GetProcAddress"},
        {"kernel32.dll", "VirtualAlloc"},
        {"kernel32.dll", "VirtualProtect"},
        {"kernel32.dll", "WriteProcessMemory"},
        {"kernel32.dll", "LoadLibraryA"},
        {"kernel32.dll", "LoadLibraryW"},
        {"ntdll.dll",    "NtProtectVirtualMemory"},
        {"ntdll.dll",    "NtWriteVirtualMemory"},
    };
    int count = sizeof(apis) / sizeof(apis[0]);
    int valid = 0;
    for (int i = 0; i < count && valid < MAX_API_HOOKS; i++) {
        HMODULE mod = GetModuleHandleA(apis[i].dll);
        if (!mod) {
            mod = LoadLibraryA(apis[i].dll);
        }
        if (!mod) {
            hprintf("[-] Cannot load %s\n", apis[i].dll);
            continue;
        }
        FARPROC addr = GetProcAddress(mod, apis[i].func);
        if (!addr) {
            hprintf("[-] Cannot find %s!%s\n", apis[i].dll, apis[i].func);
            continue;
        }
        hook_data.addresses[valid] = (uint64_t)addr;
        snprintf(hook_data.names[valid], 64, "%s!%s", apis[i].dll, apis[i].func);
        hprintf("[+] Hook: %s @ 0x%llx\n", hook_data.names[valid], (uint64_t)addr);
        valid++;
    }
    hook_data.num_hooks = valid;
    if (valid > 0) {
        hprintf("[+] Submitting %d API hooks to hypervisor...\n", valid);
        kAFL_hypercall(HYPERCALL_KAFL_HOOK_API, (uintptr_t)&hook_data);
        hprintf("[+] API hooks installed\n");
    } else {
        hprintf("[-] No API hooks resolved\n");
    }
    */
}

/*
 * Dump memory region to host filesystem via hypercall
 */
void dump_memory_to_host(const char* filename, LPVOID data, SIZE_T size) {
    static kafl_dump_file_t dump_info __attribute__((aligned(4096)));
    
    dump_info.file_name_str_ptr = (uint64_t)filename;
    dump_info.data_ptr = (uint64_t)data;
    dump_info.bytes = size;
    dump_info.append = 0;
    
    kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (UINT64)&dump_info);
    hprintf("[+] Unpacker: Dumped %llu bytes to %s\n", (unsigned long long)size, filename);
}

/*
 * Parse PE headers of target process to extract section information
 */
BOOL parse_pe_headers(HANDLE hProcess, UINT64 base_addr) {
    BYTE header_buffer[4096];
    SIZE_T bytes_read;
    
    if (!ReadProcessMemory(hProcess, (LPCVOID)base_addr, header_buffer, sizeof(header_buffer), &bytes_read)) {
        hprintf("[-] Failed to read PE headers: 0x%X\n", GetLastError());
        return FALSE;
    }
    
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)header_buffer;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        hprintf("[-] Invalid DOS signature\n");
        return FALSE;
    }
    
    PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)(header_buffer + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        hprintf("[-] Invalid NT signature\n");
        return FALSE;
    }
    
    /* Magic으로 32/64-bit 판별 */
    WORD pe_magic = *(WORD*)(header_buffer + dos_header->e_lfanew + 
                             sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    
    DWORD entry_point_rva;
    WORD num_sections;
    PIMAGE_SECTION_HEADER section;
    
    if (pe_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        /* 32-bit PE */
        hprintf("[+] Detected 32-bit PE\n");
        PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)(header_buffer + dos_header->e_lfanew);
        if (nt32->Signature != IMAGE_NT_SIGNATURE) return FALSE;
        
        entry_point_rva = nt32->OptionalHeader.AddressOfEntryPoint;
        num_sections = nt32->FileHeader.NumberOfSections;
        section = (PIMAGE_SECTION_HEADER)((BYTE*)&nt32->OptionalHeader + 
                   nt32->FileHeader.SizeOfOptionalHeader);
    } else if (pe_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        /* 64-bit PE */
        hprintf("[+] Detected 64-bit PE\n");
        PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)(header_buffer + dos_header->e_lfanew);
        if (nt64->Signature != IMAGE_NT_SIGNATURE) return FALSE;
        
        entry_point_rva = nt64->OptionalHeader.AddressOfEntryPoint;
        num_sections = nt64->FileHeader.NumberOfSections;
        section = IMAGE_FIRST_SECTION(nt64);
    } else {
        hprintf("[-] Unknown PE magic: 0x%x\n", pe_magic);
        return FALSE;
    }
    
    g_target.image_base = base_addr;
    g_target.entry_point = base_addr + nt_headers->OptionalHeader.AddressOfEntryPoint;
    g_target.size_of_image = nt_headers->OptionalHeader.SizeOfImage;
    
    hprintf("[+] Image base: 0x%llx\n", g_target.image_base);
    hprintf("[+] Entry point: 0x%llx\n", g_target.entry_point);
    
    /* Parse sections */
    section = IMAGE_FIRST_SECTION(nt_headers);
    g_target.section_count = nt_headers->FileHeader.NumberOfSections;
    
    hprintf("[+] Found %d sections:\n", g_target.section_count);
    
    for (int i = 0; i < g_target.section_count && i < 64; i++) {
        g_target.sections[i].base_address = base_addr + section[i].VirtualAddress;
        g_target.sections[i].size = section[i].Misc.VirtualSize;
        g_target.sections[i].characteristics = section[i].Characteristics;
        memcpy(g_target.sections[i].name, section[i].Name, 8);
        g_target.sections[i].name[8] = '\0';
        
        hprintf("    [%d] %s: 0x%llx - 0x%llx (0x%X)\n", 
                i, 
                g_target.sections[i].name,
                g_target.sections[i].base_address,
                g_target.sections[i].base_address + g_target.sections[i].size,
                g_target.sections[i].characteristics);
    }
    
    return TRUE;
}

/*
 * Dump process memory based on selected dump mode
 */
void dump_process_memory(void) {
    char filename[MAX_PATH];
    BYTE* buffer = NULL;
    SIZE_T bytes_read;
    
    buffer = (BYTE*)VirtualAlloc(NULL, MAX_DUMP_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        hprintf("[-] Failed to allocate dump buffer\n");
        return;
    }
    
    switch (g_dump_mode) {
        case DUMP_MODE_EXECUTABLE:
            /* Dump all executable sections */
            for (int i = 0; i < g_target.section_count; i++) {
                if (g_target.sections[i].characteristics & IMAGE_SCN_MEM_EXECUTE) {
                    SIZE_T section_size = g_target.sections[i].size;
                    if (section_size > MAX_DUMP_SIZE) {
                        section_size = MAX_DUMP_SIZE;
                    }
                    
                    if (ReadProcessMemory(g_target.process, 
                                         (LPCVOID)g_target.sections[i].base_address,
                                         buffer, 
                                         section_size, 
                                         &bytes_read)) {
                        snprintf(filename, sizeof(filename), "%s_%s_0x%llx.bin", 
                                g_output_prefix, 
                                g_target.sections[i].name,
                                g_target.sections[i].base_address);
                        dump_memory_to_host(filename, buffer, bytes_read);
                    } else {
                        hprintf("[-] Failed to read section %s: 0x%X\n", 
                               g_target.sections[i].name, GetLastError());
                    }
                }
            }
            break;
            
        case DUMP_MODE_FULL:
            /* Dump entire image */
            {
                UINT64 total_size = 0;
                for (int i = 0; i < g_target.section_count; i++) {
                    UINT64 section_end = g_target.sections[i].base_address + 
                                        g_target.sections[i].size - g_target.image_base;
                    if (section_end > total_size) {
                        total_size = section_end;
                    }
                }
                
                if (total_size > MAX_DUMP_SIZE) {
                    total_size = MAX_DUMP_SIZE;
                }
                
                if (ReadProcessMemory(g_target.process, 
                                     (LPCVOID)g_target.image_base,
                                     buffer, 
                                     (SIZE_T)total_size, 
                                     &bytes_read)) {
                    snprintf(filename, sizeof(filename), "%s_full_0x%llx.bin", 
                            g_output_prefix, g_target.image_base);
                    dump_memory_to_host(filename, buffer, bytes_read);
                } else {
                    hprintf("[-] Failed to read full image: 0x%X\n", GetLastError());
                }
            }
            break;
            
        case DUMP_MODE_TEXT_ONLY:
            /* Dump only .text section */
            for (int i = 0; i < g_target.section_count; i++) {
                if (strcmp(g_target.sections[i].name, ".text") == 0 ||
                    strcmp(g_target.sections[i].name, "CODE") == 0) {
                    SIZE_T section_size = g_target.sections[i].size;
                    if (section_size > MAX_DUMP_SIZE) {
                        section_size = MAX_DUMP_SIZE;
                    }
                    
                    if (ReadProcessMemory(g_target.process, 
                                         (LPCVOID)g_target.sections[i].base_address,
                                         buffer, 
                                         section_size, 
                                         &bytes_read)) {
                        snprintf(filename, sizeof(filename), "%s_text_0x%llx.bin", 
                                g_output_prefix, g_target.sections[i].base_address);
                        dump_memory_to_host(filename, buffer, bytes_read);
                    }
                    break;
                }
            }
            break;
    }
    
    /* Also dump PE header for reconstruction */
    if (ReadProcessMemory(g_target.process, 
                         (LPCVOID)g_target.image_base,
                         buffer, 
                         4096, 
                         &bytes_read)) {
        snprintf(filename, sizeof(filename), "%s_header.bin", g_output_prefix);
        dump_memory_to_host(filename, buffer, bytes_read);
    }
    
    VirtualFree(buffer, 0, MEM_RELEASE);
}

/*
 * Dump Intel PT trace data for offline analysis
 * This provides execution flow during unpacking
 */
void dump_pt_trace(void) {
    /* PT trace is collected by the host - we just signal completion */
    hprintf("[+] Intel PT trace collected by host\n");
}

/*
 * Main unpacking routine
 */
int main(int argc, char** argv) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    
    hprintf("===========================================\n");
    hprintf("  msFuzz Unpacking Harness v1.0\n");
    hprintf("  VMProtect / Packed Binary Analyzer\n");
    hprintf("===========================================\n\n");
    
    /* Parse arguments */
    if (argc < 2) {
        hprintf("Usage: %s <packed_exe> [timeout_ms] [dump_mode]\n", argv[0]);
        hprintf("  timeout_ms: Wait time for unpacking (default: 5000)\n");
        hprintf("  dump_mode:  0 = executable sections (default)\n");
        hprintf("              1 = full process memory\n");
        hprintf("              2 = .text section only\n");
        habort("No target specified\n");
        return 1;
    }
    
    char* target_exe = argv[1];
    
    if (argc >= 3) {
        g_timeout_ms = atoi(argv[2]);
    }
    
    if (argc >= 4) {
        g_dump_mode = atoi(argv[3]);
    }
    
    /* Extract output prefix from target filename */
    char* basename = strrchr(target_exe, '\\');
    if (basename) {
        basename++;
    } else {
        basename = target_exe;
    }
    snprintf(g_output_prefix, sizeof(g_output_prefix), "unpacked_%s", basename);
    /* Remove .exe extension if present */
    char* ext = strstr(g_output_prefix, ".exe");
    if (ext) *ext = '\0';
    ext = strstr(g_output_prefix, ".EXE");
    if (ext) *ext = '\0';
    
    hprintf("[+] Target: %s\n", target_exe);
    hprintf("[+] Timeout: %d ms\n", g_timeout_ms);
    hprintf("[+] Dump mode: %d\n", g_dump_mode);
    hprintf("[+] Output prefix: %s\n\n", g_output_prefix);
    
    /* Initialize kAFL/Nyx agent */
    init_agent_handshake();
    
    /* Create target process in suspended state */
    si.cb = sizeof(si);
    
    hprintf("[+] Creating target process (suspended)...\n");
    
    if (!CreateProcessA(
            target_exe,
            NULL,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED,  /* Suspended only - no debug flags for anti-debug evasion */
            NULL,
            NULL,
            &si,
            &pi)) {
        hprintf("[-] CreateProcess failed: 0x%X\n", GetLastError());
        habort("Failed to create target process\n");
        return 1;
    }
    
    g_target.process = pi.hProcess;
    g_target.thread = pi.hThread;
    g_target.pid = pi.dwProcessId;
    
    hprintf("[+] Process created: PID %d\n", g_target.pid);
    
    /* Get process base address via PEB */
    PROCESS_BASIC_INFORMATION pbi;
    ULONG len;
    
    if (NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, 
                                  &pbi, sizeof(pbi), &len) == 0) {
        UINT64 peb_addr = (UINT64)pbi.PebBaseAddress;
        UINT64 image_base;
        SIZE_T bytes_read;
        
        /* PEB.ImageBaseAddress is at offset 0x10 in 64-bit PEB */
        if (ReadProcessMemory(pi.hProcess, 
                             (LPCVOID)(peb_addr + 0x10), 
                             &image_base, 
                             sizeof(image_base), 
                             &bytes_read)) {
            hprintf("[+] Image base from PEB: 0x%llx\n", image_base);
            
            /* Parse PE headers */
            if (!parse_pe_headers(pi.hProcess, image_base)) {
                hprintf("[-] Failed to parse PE headers\n");
            }
    }
    
    /* Wait for target to initialize (ntdll Ldr to load kernel32.dll) */
    /* We resume, wait, and suspend to allow Ldr to do its job */
    hprintf("[+] Resuming briefly to allow DLL loading...\n");
    ResumeThread(pi.hThread);
    Sleep(100); // 100ms is usually enough for Ldr
    SuspendThread(pi.hThread);
    hprintf("[+] Process suspended again.\n");
    
    /* Setup API hooks */
    setup_api_hooks();
#if 0
    /* Submit child process CR3 for Intel PT filtering via vmcall injection */
    hprintf("[+] Submitting child process CR3 via vmcall injection...\n");
    {
        /*
         * Shellcode: vmcall(rax=0x1f, rbx=SUBMIT_CR3(5), rcx=0)
         * QEMU-Nyx patched handler reads env->cr[3] when arg=0,
         * so child's actual CR3 is captured automatically.
         * Ends with jmp $ (spin) so we can recapture the thread.
         */
        BYTE cr3_shellcode[] = {
            0x48, 0xB8, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* mov rax, 0x1f */
            0x48, 0xBB, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* mov rbx, 5 (SUBMIT_CR3) */
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* mov rcx, 0 */
            0x0F, 0x01, 0xC1,                                              /* vmcall */
            0xEB, 0xFE                                                      /* jmp $ (spin) */
        };

        LPVOID sc_addr = VirtualAllocEx(pi.hProcess, NULL, sizeof(cr3_shellcode),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!sc_addr) {
            hprintf("[-] VirtualAllocEx for shellcode failed: 0x%X\n", GetLastError());
            habort("Failed to inject CR3 shellcode\n");
        }

        if (!WriteProcessMemory(pi.hProcess, sc_addr, cr3_shellcode,
                                sizeof(cr3_shellcode), NULL)) {
            hprintf("[-] WriteProcessMemory for shellcode failed: 0x%X\n", GetLastError());
            VirtualFreeEx(pi.hProcess, sc_addr, 0, MEM_RELEASE);
            habort("Failed to write CR3 shellcode\n");
        }

        CONTEXT orig_ctx = {0};
        orig_ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(pi.hThread, &orig_ctx);

        CONTEXT sc_ctx = orig_ctx;
        sc_ctx.Rip = (DWORD64)sc_addr;
        SetThreadContext(pi.hThread, &sc_ctx);

        /* Briefly resume to execute vmcall, then recapture */
        ResumeThread(pi.hThread);
        Sleep(100);
        SuspendThread(pi.hThread);

        /* Restore original context and free shellcode memory */
        SetThreadContext(pi.hThread, &orig_ctx);
        VirtualFreeEx(pi.hProcess, sc_addr, 0, MEM_RELEASE);
        hprintf("[+] Child CR3 submitted successfully\n");
    }
#endif
    
    /* Set IP range for Intel PT to cover unpacking stub and OEP */
    /* Range 0: Entire image for now (packer + unpacked code) */
    if (g_target.image_base && g_target.size_of_image > 0) {
        set_ip_range_usermode(g_target.image_base, g_target.size_of_image, 0);
        
        /* Verify entry point is with in IP range */
        if (g_target.entry_point < g_target.image_base || 
            g_target.entry_point >= g_target.image_base + g_target.size_of_image) {
            hprintf("[!] WARNING: Entry point 0x%llx is outside IP range 0x%llx - 0x%llx\n",
                    g_target.entry_point, g_target.image_base,
                    g_target.image_base + g_target.size_of_image);
        }
    }
    
    /* No debug detach needed - we don't use DEBUG_PROCESS */
    /* This avoids anti-debug detection by VMProtect */
    
    hprintf("[+] Starting Intel PT tracing...\n");
    /* Start tracing */
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    
    /* Resume target process - unpacking begins */
    hprintf("[+] Resuming target process - unpacking in progress...\n");
    ResumeThread(pi.hThread);
    
    /* Wait for unpacking to complete (timeout-based approach) */
    /* 
     * VMProtect and similar packers:
     * 1. Execute packer stub code
     * 2. Decrypt/decompress original code
     * 3. Fix imports
     * 4. Jump to OEP (Original Entry Point)
     * 
     * We wait for timeout to ensure unpacking is complete,
     * then dump the unpacked memory.
     */
    DWORD wait_result = WaitForSingleObject(pi.hProcess, g_timeout_ms);
    
    /* Stop tracing first */
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    hprintf("[+] Intel PT tracing stopped\n");

    if (wait_result == WAIT_OBJECT_0) {
        /* Process exited before timeout - still try to dump what we can */
        DWORD exit_code = 0;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        hprintf("[!] Process exited (code %d) before timeout\n", exit_code);
        hprintf("[!] Memory dump may be incomplete or unavailable\n");
    } else if (wait_result == WAIT_TIMEOUT) {
        /* Good - process still running, unpacking should be complete */
        hprintf("[+] Timeout reached - unpacking should be complete\n");
        SuspendThread(pi.hThread);
    }

    /* Dump unpacked memory */
    hprintf("[+] Dumping unpacked memory...\n");
    dump_process_memory();
    
    /* Dump trace info */
    dump_pt_trace();
    
    /* Cleanup */
    hprintf("[+] Cleanup and termination...\n");
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    hprintf("===========================================\n");
    hprintf("  Unpacking complete!\n");
    hprintf("  Check host for dumped files with prefix:\n");
    hprintf("    %s_*\n", g_output_prefix);
    hprintf("===========================================\n");
    
    return 0;
}
