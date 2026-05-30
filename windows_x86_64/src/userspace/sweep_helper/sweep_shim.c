/*
 * sweep_shim.c — native CLR-hosting shim for the force-JIT sweep.
 *
 * Built as sweep_helper.dll and injected into the (32-bit) target via a
 * remote LoadLibraryA thread.  A pure managed DLL cannot be driven by
 * LoadLibrary (no native DllMain), so this native shim bridges the gap:
 * on load it spins a worker thread that attaches to the target's
 * already-running CLR and invokes the managed entry point
 *
 *     SweepHelper.Sweeper.Sweep(string)   in  sweep_core.dll
 *
 * in the default AppDomain.  That managed method calls
 * RuntimeHelpers.PrepareMethod on every non-system method (incl. ctors),
 * forcing the JIT to compile method bodies that were never called — so the
 * hypervisor's compileMethod tap captures their decrypted IL.
 *
 * The CLR work runs on a fresh thread (NOT in DllMain) to avoid the loader
 * lock.  mscohost APIs are resolved dynamically from mscoree.dll (already
 * loaded in any .NET process), and the metahost interfaces are declared
 * inline because i686 MinGW ships no metahost.h / import lib.
 *
 * Build (32-bit, to match a 32-bit target):
 *   i686-w64-mingw32-gcc -shared -O2 -o bin/userspace/sweep_helper.dll \
 *       src/userspace/sweep_helper/sweep_shim.c -lole32 -Wall
 *
 * The managed sweep_core.dll (csc /platform:x86 /target:library) must sit
 * in the same directory as this shim.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
/* kAFL hprintf hypercall — routes shim diagnostics to the host's
 * hprintf_00.log.  A guest-side C:\ file cannot be retrieved by the harness,
 * but hprintf goes over VMCALL to the same aux buffer QEMU writes to disk.
 * nyx_api.h provides hprintf() / kAFL_hypercall() (32- and 64-bit). */
#include "nyx_api.h"

/* ── Minimal metahost / CLR-host COM definitions ──────────────────────
 * Only the vtable slots we actually call are typed; everything before them
 * is a void* placeholder so the slot offsets line up with the real vtable. */

typedef struct ICLRMetaHost    ICLRMetaHost;
typedef struct ICLRRuntimeInfo ICLRRuntimeInfo;
typedef struct ICLRRuntimeHost ICLRRuntimeHost;

typedef struct ICLRMetaHostVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICLRMetaHost *, REFIID, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICLRMetaHost *);
    ULONG   (STDMETHODCALLTYPE *Release)(ICLRMetaHost *);
    /* slot 3 */
    HRESULT (STDMETHODCALLTYPE *GetRuntime)(ICLRMetaHost *, LPCWSTR, REFIID, void **);
} ICLRMetaHostVtbl;
struct ICLRMetaHost { const ICLRMetaHostVtbl *lpVtbl; };

typedef struct ICLRRuntimeInfoVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICLRRuntimeInfo *, REFIID, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICLRRuntimeInfo *);
    ULONG   (STDMETHODCALLTYPE *Release)(ICLRRuntimeInfo *);
    void *GetVersionString;       /* slot 3  */
    void *GetRuntimeDirectory;    /* slot 4  */
    void *IsLoaded;               /* slot 5  */
    void *LoadErrorString;        /* slot 6  */
    void *LoadLibraryFn;          /* slot 7  */
    void *GetProcAddressFn;       /* slot 8  */
    /* slot 9 */
    HRESULT (STDMETHODCALLTYPE *GetInterface)(ICLRRuntimeInfo *, REFCLSID, REFIID, void **);
} ICLRRuntimeInfoVtbl;
struct ICLRRuntimeInfo { const ICLRRuntimeInfoVtbl *lpVtbl; };

typedef struct ICLRRuntimeHostVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICLRRuntimeHost *, REFIID, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICLRRuntimeHost *);
    ULONG   (STDMETHODCALLTYPE *Release)(ICLRRuntimeHost *);
    void *Start;                  /* slot 3  */
    void *Stop;                   /* slot 4  */
    void *SetHostControl;         /* slot 5  */
    void *GetCLRControl;          /* slot 6  */
    void *UnloadAppDomain;        /* slot 7  */
    void *ExecuteInAppDomain;     /* slot 8  */
    void *GetCurrentAppDomainId;  /* slot 9  */
    void *ExecuteApplication;     /* slot 10 */
    /* slot 11 */
    HRESULT (STDMETHODCALLTYPE *ExecuteInDefaultAppDomain)(
        ICLRRuntimeHost *, LPCWSTR pwzAssemblyPath, LPCWSTR pwzTypeName,
        LPCWSTR pwzMethodName, LPCWSTR pwzArgument, DWORD *pReturnValue);
} ICLRRuntimeHostVtbl;
struct ICLRRuntimeHost { const ICLRRuntimeHostVtbl *lpVtbl; };

typedef HRESULT (WINAPI *CLRCreateInstance_t)(REFCLSID, REFIID, LPVOID *);

/* Well-known CLR-hosting GUIDs (from metahost.h). */
static const GUID kCLSID_CLRMetaHost =
    {0x9280188d,0x0e8e,0x4867,{0xb3,0x0c,0x7f,0xa8,0x38,0x84,0xe8,0xde}};
static const GUID kIID_ICLRMetaHost =
    {0xD332DB9E,0xB9B3,0x4125,{0x82,0x07,0xA1,0x48,0x84,0xF5,0x32,0x16}};
static const GUID kIID_ICLRRuntimeInfo =
    {0xBD39D1D2,0xBA2F,0x486a,{0x89,0xB0,0xB4,0xB0,0xCB,0x46,0x68,0x91}};
static const GUID kCLSID_CLRRuntimeHost =
    {0x90F1A06E,0x7712,0x4762,{0x86,0xB5,0x7A,0x5E,0xBA,0x6B,0xDB,0x02}};
static const GUID kIID_ICLRRuntimeHost =
    {0x90F1A06C,0x7712,0x4762,{0x86,0xB5,0x7A,0x5E,0xBA,0x6B,0xDB,0x02}};

#define SWEEP_CORE_DLL   L"sweep_core.dll"
#define SWEEP_NAMESPACE  L"SweepHelper.Sweeper"
#define SWEEP_METHOD     L"Sweep"
#define CLR_VERSION      L"v4.0.30319"

static HINSTANCE g_self = NULL;

/* Attach to the running CLR and invoke the managed sweep once. */
static void run_sweep_once(void)
{
    hprintf("[SHIM] thread start (self=0x%08x)\n", (unsigned)(UINT_PTR)g_self);

    HMODULE mscoree = LoadLibraryW(L"mscoree.dll");
    if (!mscoree) { hprintf("[SHIM] mscoree load FAIL\n"); return; }
    CLRCreateInstance_t pCLRCreateInstance =
        (CLRCreateInstance_t)GetProcAddress(mscoree, "CLRCreateInstance");
    if (!pCLRCreateInstance) { hprintf("[SHIM] no CLRCreateInstance\n"); return; }

    ICLRMetaHost    *meta = NULL;
    ICLRRuntimeInfo *info = NULL;
    ICLRRuntimeHost *host = NULL;
    HRESULT hr;

    hr = pCLRCreateInstance(&kCLSID_CLRMetaHost, &kIID_ICLRMetaHost,
                            (LPVOID *)&meta);
    hprintf("[SHIM] CLRCreateInstance hr=0x%08x meta=0x%08x\n",
            (unsigned)hr, (unsigned)(UINT_PTR)meta);
    if (FAILED(hr) || !meta) return;

    hr = meta->lpVtbl->GetRuntime(meta, CLR_VERSION,
                                  &kIID_ICLRRuntimeInfo, (void **)&info);
    hprintf("[SHIM] GetRuntime hr=0x%08x info=0x%08x\n",
            (unsigned)hr, (unsigned)(UINT_PTR)info);
    if (FAILED(hr) || !info) goto out_meta;

    /* The target already started the CLR; GetInterface hands us the live
     * host without re-initialising it. */
    hr = info->lpVtbl->GetInterface(info, &kCLSID_CLRRuntimeHost,
                                    &kIID_ICLRRuntimeHost, (void **)&host);
    hprintf("[SHIM] GetInterface hr=0x%08x host=0x%08x\n",
            (unsigned)hr, (unsigned)(UINT_PTR)host);
    if (FAILED(hr) || !host) goto out_info;

    /* Build <dir-of-this-shim>\sweep_core.dll. */
    wchar_t core_path[MAX_PATH];
    DWORD n = GetModuleFileNameW(g_self, core_path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) goto out_host;
    wchar_t *sep = wcsrchr(core_path, L'\\');
    if (sep) sep[1] = L'\0';
    else     core_path[0] = L'\0';
    lstrcpynW(core_path + lstrlenW(core_path), SWEEP_CORE_DLL,
              MAX_PATH - lstrlenW(core_path));

    DWORD attr = GetFileAttributesW(core_path);
    hprintf("[SHIM] core_path exists=%d (attr=0x%08x), calling Execute...\n",
            attr != INVALID_FILE_ATTRIBUTES, (unsigned)attr);

    DWORD ret = 0;
    hr = host->lpVtbl->ExecuteInDefaultAppDomain(host, core_path,
        SWEEP_NAMESPACE, SWEEP_METHOD, L"", &ret);
    hprintf("[SHIM] ExecuteInDefaultAppDomain hr=0x%08x ret=%u\n",
            (unsigned)hr, (unsigned)ret);

out_host:
    host->lpVtbl->Release(host);
out_info:
    info->lpVtbl->Release(info);
out_meta:
    meta->lpVtbl->Release(meta);
    hprintf("[SHIM] done\n");
}

static DWORD WINAPI sweep_thread(LPVOID param)
{
    (void)param;
    run_sweep_once();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = inst;
        DisableThreadLibraryCalls(inst);
        /* Never host the CLR under the loader lock — hand it to a thread. */
        HANDLE t = CreateThread(NULL, 0, sweep_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
