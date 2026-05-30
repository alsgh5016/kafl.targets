/*
 * sweep_shim.c — native CLR-hosting shim for the force-JIT sweep.
 *
 * Built as sweep_helper.dll and injected into the (32-bit) target via a
 * remote LoadLibraryA thread.  A pure managed DLL cannot be driven by
 * LoadLibrary (no native DllMain), so this native shim bridges the gap:
 * on load it spins a worker thread that attaches to the target's
 * already-running CLR and invokes two managed entry points in sequence
 *
 *     SweepHelper.Sweeper.SweepCctors(string)     in  sweep_core.dll
 *     SweepHelper.Sweeper.SweepForceJit(string)
 *
 * in the default AppDomain.  SweepCctors runs each module's <Module>.cctor
 * (installing ConfuserEx's decryptor / JIT hook); SweepForceJit then calls
 * RuntimeHelpers.PrepareMethod on every non-system method (incl. ctors),
 * forcing the JIT to compile method bodies that were never called — so the
 * hypervisor's compileMethod tap captures their decrypted IL.  Each pass runs
 * under a Vectored-Exception-Handler guard so a hard fault is contained
 * instead of killing the target (see "Fault containment" below).
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
#include <setjmp.h>   /* fault containment: MinGW gcc has no __try/__except */
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
typedef struct IEnumUnknown     IEnumUnknown;

typedef struct IEnumUnknownVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IEnumUnknown *, REFIID, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IEnumUnknown *);
    ULONG   (STDMETHODCALLTYPE *Release)(IEnumUnknown *);
    /* slot 3 */
    HRESULT (STDMETHODCALLTYPE *Next)(IEnumUnknown *, ULONG celt,
                                      void **rgelt, ULONG *pceltFetched);
} IEnumUnknownVtbl;
struct IEnumUnknown { const IEnumUnknownVtbl *lpVtbl; };

typedef struct ICLRMetaHostVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICLRMetaHost *, REFIID, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICLRMetaHost *);
    ULONG   (STDMETHODCALLTYPE *Release)(ICLRMetaHost *);
    /* slot 3 */
    HRESULT (STDMETHODCALLTYPE *GetRuntime)(ICLRMetaHost *, LPCWSTR, REFIID, void **);
    void *GetVersionFromFile;          /* slot 4 */
    void *EnumerateInstalledRuntimes;  /* slot 5 */
    /* slot 6 */
    HRESULT (STDMETHODCALLTYPE *EnumerateLoadedRuntimes)(
        ICLRMetaHost *, HANDLE hndProcess, IEnumUnknown **ppEnumerator);
} ICLRMetaHostVtbl;
struct ICLRMetaHost { const ICLRMetaHostVtbl *lpVtbl; };

typedef struct ICLRRuntimeInfoVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICLRRuntimeInfo *, REFIID, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICLRRuntimeInfo *);
    ULONG   (STDMETHODCALLTYPE *Release)(ICLRRuntimeInfo *);
    /* slot 3 */
    HRESULT (STDMETHODCALLTYPE *GetVersionString)(ICLRRuntimeInfo *,
                                                  LPWSTR pwzBuffer,
                                                  DWORD *pcchBuffer);
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

#define SWEEP_CORE_DLL        L"sweep_core.dll"
#define SWEEP_NAMESPACE       L"SweepHelper.Sweeper"
#define SWEEP_METHOD_CCTORS   L"SweepCctors"    /* PASS 1: run <Module>.cctors */
#define SWEEP_METHOD_FORCEJIT L"SweepForceJit"  /* PASS 2: PrepareMethod sweep */
#define CLR_VERSION           L"v4.0.30319"

static HINSTANCE g_self = NULL;

/* ── Fault containment for the managed sweep ──────────────────────────────
 * The force-JIT sweep runs managed code (cctors, PrepareMethod) on this
 * injected worker thread.  On some ConfuserEx protections that faults with a
 * hard, uncatchable native access violation (0xC0000005) which — left
 * unhandled — kills the WHOLE target process, so its natural execution never
 * finishes and almost nothing is captured.
 *
 * MinGW gcc has no MSVC __try/__except, so we contain such faults with a
 * Vectored Exception Handler that longjmps back out of the offending call.
 * It is registered LAST (FirstHandler = FALSE) so the CLR's own VEH — which
 * turns genuine null derefs into managed NullReferenceExceptions — runs
 * first; we only catch faults the CLR declined (truly fatal), and only on our
 * sweep thread while a guarded call is in flight.
 *
 * Caveat: longjmp unwinds the native stack without running the CLR's frame
 * handlers, so any cctor/JIT lock held at fault time stays held — the main
 * thread could stall on a later cctor/JIT.  The upside is the process no
 * longer dies, so natural execution (which already recovers the payload on
 * these protections) can complete. */
static DWORD         g_sweep_tid        = 0;   /* worker TID; 0 = no guard */
static volatile LONG g_guard_armed      = 0;   /* 1 while inside a guarded call */
static jmp_buf       g_guard_jmp;
static DWORD         g_guard_fault_code = 0;

static LONG CALLBACK sweep_fault_veh(PEXCEPTION_POINTERS ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (g_guard_armed &&
        GetCurrentThreadId() == g_sweep_tid &&
        (code == EXCEPTION_ACCESS_VIOLATION    ||
         code == EXCEPTION_IN_PAGE_ERROR       ||
         code == EXCEPTION_ILLEGAL_INSTRUCTION ||
         code == EXCEPTION_PRIV_INSTRUCTION    ||
         code == EXCEPTION_STACK_OVERFLOW)) {
        g_guard_fault_code = code;
        g_guard_armed = 0;           /* disarm before unwinding */
        longjmp(g_guard_jmp, 1);     /* back to guarded_execute() setjmp */
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* Invoke one managed entry point under fault containment.  Returns the
 * HRESULT; on a contained hard fault sets *faulted = 1 and returns E_FAIL. */
static HRESULT guarded_execute(ICLRRuntimeHost *host, LPCWSTR core_path,
                               LPCWSTR method, DWORD *pret, int *faulted)
{
    *faulted = 0;
    g_guard_fault_code = 0;
    if (setjmp(g_guard_jmp) != 0) {
        *faulted = 1;
        hprintf("[SHIM] %ls FAULTED (contained) code=0x%08x\n",
                method, (unsigned)g_guard_fault_code);
        return E_FAIL;
    }
    g_guard_armed = 1;
    HRESULT hr = host->lpVtbl->ExecuteInDefaultAppDomain(
        host, core_path, SWEEP_NAMESPACE, method, L"", pret);
    g_guard_armed = 0;
    return hr;
}

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

    /* Attach to whatever CLR the target ACTUALLY loaded (v2 vs v4) instead of
     * hardcoding a version — a v4 host on a v2 target would mis-resolve the
     * default AppDomain.  Enumerate loaded runtimes and take the first that
     * yields an ICLRRuntimeHost. */
    IEnumUnknown *pEnum = NULL;
    hr = meta->lpVtbl->EnumerateLoadedRuntimes(meta, GetCurrentProcess(),
                                               &pEnum);
    hprintf("[SHIM] EnumerateLoadedRuntimes hr=0x%08x enum=0x%08x\n",
            (unsigned)hr, (unsigned)(UINT_PTR)pEnum);
    if (SUCCEEDED(hr) && pEnum) {
        ICLRRuntimeInfo *ri = NULL;
        ULONG fetched = 0;
        while (pEnum->lpVtbl->Next(pEnum, 1, (void **)&ri, &fetched) == S_OK
               && fetched == 1 && ri) {
            wchar_t ver[64];
            DWORD vlen = 64;
            ver[0] = L'\0';
            ri->lpVtbl->GetVersionString(ri, ver, &vlen);
            ICLRRuntimeHost *h = NULL;
            HRESULT gi = ri->lpVtbl->GetInterface(ri, &kCLSID_CLRRuntimeHost,
                                                  &kIID_ICLRRuntimeHost,
                                                  (void **)&h);
            hprintf("[SHIM] loaded runtime ver=%ls GetInterface hr=0x%08x "
                    "host=0x%08x\n", ver, (unsigned)gi, (unsigned)(UINT_PTR)h);
            if (SUCCEEDED(gi) && h) { info = ri; host = h; break; }
            ri->lpVtbl->Release(ri);
            ri = NULL;
        }
        pEnum->lpVtbl->Release(pEnum);
    }

    /* Fallback: nothing enumerated (or pre-v4 metahost) — try v4 directly. */
    if (!host) {
        hprintf("[SHIM] enum found no host, fallback GetRuntime %ls\n",
                CLR_VERSION);
        hr = meta->lpVtbl->GetRuntime(meta, CLR_VERSION,
                                      &kIID_ICLRRuntimeInfo, (void **)&info);
        if (SUCCEEDED(hr) && info) {
            hr = info->lpVtbl->GetInterface(info, &kCLSID_CLRRuntimeHost,
                                            &kIID_ICLRRuntimeHost,
                                            (void **)&host);
        }
        hprintf("[SHIM] fallback host=0x%08x\n", (unsigned)(UINT_PTR)host);
    }
    if (!host) goto out_info;

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

    /* Two fault-contained passes: cctors first (installs ConfuserEx's
     * decryptor / JIT hook), then the PrepareMethod force-JIT.  Each is
     * guarded independently so (a) a fatal fault is contained instead of
     * killing the process, and (b) the [SHIM] log localises which pass
     * faulted. */
    g_sweep_tid = GetCurrentThreadId();
    PVOID veh = AddVectoredExceptionHandler(0 /* last: after CLR's VEH */,
                                            sweep_fault_veh);

    DWORD ret1 = 0, ret2 = 0;
    int   f1 = 0, f2 = 0;

    HRESULT hr1 = guarded_execute(host, core_path,
                                  SWEEP_METHOD_CCTORS, &ret1, &f1);
    hprintf("[SHIM] SweepCctors hr=0x%08x ret=%u faulted=%d\n",
            (unsigned)hr1, (unsigned)ret1, f1);

    HRESULT hr2 = guarded_execute(host, core_path,
                                  SWEEP_METHOD_FORCEJIT, &ret2, &f2);
    hprintf("[SHIM] SweepForceJit hr=0x%08x ret=%u faulted=%d\n",
            (unsigned)hr2, (unsigned)ret2, f2);

    if (veh) RemoveVectoredExceptionHandler(veh);
    g_guard_armed = 0;
    g_sweep_tid   = 0;

out_host:
    if (host) host->lpVtbl->Release(host);
out_info:
    if (info) info->lpVtbl->Release(info);
out_meta:
    if (meta) meta->lpVtbl->Release(meta);
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
