/*
 * sweep_helper.cs — Force-JIT sweep for .NET unpacking
 *
 * Compiled as a .NET Framework 4.x class library (sweep_helper.dll).
 * Entry point is called via ICLRRuntimeHost::ExecuteInDefaultAppDomain,
 * which requires the exact signature:
 *
 *   static int MethodName(string arg)
 *
 * Usage from unpack_harness.c:
 *   ICLRRuntimeHost::ExecuteInDefaultAppDomain(
 *       L"sweep_helper.dll",
 *       L"SweepHelper.Sweeper",
 *       L"Sweep",
 *       L"",
 *       &retval);
 *
 * Build (on Windows, from Visual Studio Developer Command Prompt):
 *   csc.exe /target:library /out:sweep_helper.dll sweep_helper.cs
 */

using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace SweepHelper
{
    public static class Sweeper
    {
        /// <summary>
        /// PASS 1 — run every target module's static constructor
        /// (<c>&lt;Module&gt;.cctor</c>) so ConfuserEx's runtime IL-decryption /
        /// JIT hook is installed BEFORE any force-JIT.  Force-JITing a method
        /// before that init runs makes the JIT compile still-encrypted IL,
        /// faulting with a native access violation (0xC0000005).  Running the
        /// module cctor first ensures bodies are decrypted / the hook is
        /// installed.  <c>RunModuleConstructor</c> is idempotent — a no-op if
        /// the cctor already ran.
        ///
        /// Split out as its own ICLRRuntimeHost entry point (called before
        /// <see cref="SweepForceJit"/>) so the native shim can wrap each pass in
        /// its own fault-containment guard and localise where a crash occurs.
        /// </summary>
        /// <param name="_arg">Unused; required by ICLRRuntimeHost API.</param>
        /// <returns>Count of module constructors run.</returns>
        public static int SweepCctors(string _arg)
        {
            int count = 0;
            foreach (Assembly asm in CollectTargetAssemblies())
            {
                Module[] modules;
                try
                {
                    modules = asm.GetModules();
                }
                catch
                {
                    continue;
                }

                foreach (Module mod in modules)
                {
                    if (mod == null)
                        continue;
                    try
                    {
                        RuntimeHelpers.RunModuleConstructor(mod.ModuleHandle);
                        count++;
                    }
                    catch
                    {
                        // A throwing decryptor cctor is non-fatal; other
                        // modules and the force-JIT pass still run.
                    }
                }
            }
            return count;
        }

        /// <summary>
        /// PASS 2 — call <c>RuntimeHelpers.PrepareMethod</c> on every concrete,
        /// non-generic method/ctor of the target's own assemblies, forcing the
        /// JIT to compile bodies that were never called so the hypervisor's
        /// compileMethod tap captures their decrypted IL.  Run AFTER
        /// <see cref="SweepCctors"/> so method bodies are already decrypted.
        ///
        /// Errors (abstract methods, generic instantiations, P/Invoke stubs)
        /// are swallowed so one bad method never aborts the sweep.
        /// </summary>
        /// <param name="_arg">Unused; required by ICLRRuntimeHost API.</param>
        /// <returns>Count of successfully prepared methods.</returns>
        public static int SweepForceJit(string _arg)
        {
            int count = 0;
            foreach (Assembly asm in CollectTargetAssemblies())
            {
                // GetTypes() can throw ReflectionTypeLoadException when some
                // types fail to load (e.g. missing dependencies).  Recover
                // the partial type list from the exception.
                Type[] types;
                try
                {
                    types = asm.GetTypes();
                }
                catch (ReflectionTypeLoadException ex)
                {
                    types = ex.Types;
                }

                if (types == null)
                    continue;

                foreach (Type t in types)
                {
                    // Null entries can appear in the partial-load case above.
                    if (t == null)
                        continue;

                    // PrepareMethod on an open generic type definition is
                    // meaningless — concrete closed instantiations are what
                    // the JIT actually compiles.
                    if (t.IsGenericTypeDefinition)
                        continue;

                    const BindingFlags memberFlags =
                        BindingFlags.Public    | BindingFlags.NonPublic |
                        BindingFlags.Instance  | BindingFlags.Static    |
                        BindingFlags.DeclaredOnly;

                    // GetMethods() does NOT return constructors — instance
                    // (.ctor) and static (.cctor) ctors must be fetched
                    // separately via GetConstructors(), or they never get
                    // force-JITed (and stay absent from the heap capture when
                    // the program itself never invokes them).
                    var targets = new List<MethodBase>();
                    try
                    {
                        targets.AddRange(t.GetMethods(memberFlags));
                    }
                    catch
                    {
                        // Some reflection-emitted or COM-interop types refuse
                        // to enumerate their members — skip silently.
                        continue;
                    }
                    try
                    {
                        targets.AddRange(t.GetConstructors(memberFlags));
                    }
                    catch
                    {
                        // Ctor enumeration failure is non-fatal; keep methods.
                    }

                    foreach (MethodBase m in targets)
                    {
                        if (m == null)
                            continue;

                        // Abstract methods have no IL body.
                        if (m.IsAbstract)
                            continue;

                        // Open generic methods cannot be prepared — the JIT
                        // needs fully-resolved type arguments.
                        if (m.ContainsGenericParameters)
                            continue;

                        try
                        {
                            RuntimeHelpers.PrepareMethod(m.MethodHandle);
                            count++;
                        }
                        catch
                        {
                            // Swallow: P/Invoke stubs, internal calls, and
                            // other non-JITable methods will throw here.
                        }
                    }
                }
            }

            return count;
        }

        /// <summary>
        /// The target application's own assemblies currently loaded in the
        /// default AppDomain — dynamic and framework/GAC assemblies excluded.
        /// Re-enumerated per pass (cheap, idempotent) so each ICLR entry point
        /// is self-contained.
        /// </summary>
        private static List<Assembly> CollectTargetAssemblies()
        {
            var targetAsms = new List<Assembly>();
            foreach (Assembly asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                // Dynamic assemblies have no on-disk IL to prepare.
                if (asm.IsDynamic)
                    continue;
                if (IsSystemAssembly(asm))
                    continue;
                targetAsms.Add(asm);
            }
            return targetAsms;
        }

        /// <summary>
        /// True for framework / GAC assemblies we never want to force-JIT —
        /// only the target application's own assemblies are swept.
        /// </summary>
        private static bool IsSystemAssembly(Assembly asm)
        {
            string name = asm.GetName().Name ?? string.Empty;
            return
                name.StartsWith("mscorlib",              StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("System",                StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("Microsoft",             StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("PresentationCore",      StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("PresentationFramework", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("WindowsBase",           StringComparison.OrdinalIgnoreCase);
        }
    }
}
