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
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

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
    
    g_target.image_base = base_addr;
    g_target.entry_point = base_addr + nt_headers->OptionalHeader.AddressOfEntryPoint;
    
    hprintf("[+] Image base: 0x%llx\n", g_target.image_base);
    hprintf("[+] Entry point: 0x%llx\n", g_target.entry_point);
    
    /* Parse sections */
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
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
    }

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
    
    /* Set IP range for Intel PT to cover unpacking stub and OEP */
    /* Range 0: Entire image for now (packer + unpacked code) */
    if (g_target.image_base && g_target.section_count > 0) {
        UINT64 total_size = 0;
        for (int i = 0; i < g_target.section_count; i++) {
            UINT64 section_end = g_target.sections[i].base_address + 
                                g_target.sections[i].size - g_target.image_base;
            if (section_end > total_size) {
                total_size = section_end;
            }
        }
        set_ip_range_usermode(g_target.image_base, total_size, 0);
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
