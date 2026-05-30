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
 * lock: hosting APIs and managed execution must never run under it.
 *
 * Build (32-bit, to match a 32-bit target):
 *   i686-w64-mingw32-gcc -shared -O2 -o bin/userspace/sweep_helper.dll \
 *       src/userspace/sweep_helper/sweep_shim.c -lmscoree -lole32 -luuid
 *
 * The managed sweep_core.dll (csc /platform:x86 /target:library) must sit
 * in the same directory as this shim.
 */

#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
/* initguid.h must precede metahost.h so the CLSID_/IID_ GUIDs referenced
 * below are emitted as definitions (not just extern declarations) — MinGW
 * has no mscoree import lib carrying them. */
#include <initguid.h>
#include <metahost.h>

/* Managed assembly + entry point invoked in the default AppDomain. */
#define SWEEP_CORE_DLL   L"sweep_core.dll"
#define SWEEP_NAMESPACE  L"SweepHelper.Sweeper"
#define SWEEP_METHOD     L"Sweep"
#define CLR_VERSION      L"v4.0.30319"

static HINSTANCE g_self = NULL;

/* Attach to the running CLR and invoke the managed sweep once. */
static void run_sweep_once(void)
{
    ICLRMetaHost    *meta = NULL;
    ICLRRuntimeInfo *info = NULL;
    ICLRRuntimeHost *host = NULL;
    HRESULT hr;

    hr = CLRCreateInstance(&CLSID_CLRMetaHost, &IID_ICLRMetaHost, (LPVOID *)&meta);
    if (FAILED(hr) || !meta) return;

    hr = ICLRMetaHost_GetRuntime(meta, CLR_VERSION,
                                 &IID_ICLRRuntimeInfo, (LPVOID *)&info);
    if (FAILED(hr) || !info) goto out_meta;

    /* The target already started the CLR; GetInterface hands us the live
     * host without re-initialising it. */
    hr = ICLRRuntimeInfo_GetInterface(info, &CLSID_CLRRuntimeHost,
                                      &IID_ICLRRuntimeHost, (LPVOID *)&host);
    if (FAILED(hr) || !host) goto out_info;

    wchar_t self_dir[MAX_PATH];
    DWORD n = GetModuleFileNameW(g_self, self_dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) goto out_host;
    wchar_t *sep = wcsrchr(self_dir, L'\\');
    if (sep) *(sep + 1) = L'\0';
    else      self_dir[0] = L'\0';

    wchar_t core_path[MAX_PATH];
    lstrcpynW(core_path, self_dir, MAX_PATH);
    lstrcpynW(core_path + lstrlenW(core_path), SWEEP_CORE_DLL,
              MAX_PATH - lstrlenW(core_path));

    DWORD ret = 0;
    ICLRRuntimeHost_ExecuteInDefaultAppDomain(host, core_path,
        SWEEP_NAMESPACE, SWEEP_METHOD, L"", &ret);

out_host:
    ICLRRuntimeHost_Release(host);
out_info:
    ICLRRuntimeInfo_Release(info);
out_meta:
    ICLRMetaHost_Release(meta);
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
