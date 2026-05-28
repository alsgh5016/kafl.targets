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
using System.Reflection;
using System.Runtime.CompilerServices;

namespace SweepHelper
{
    public static class Sweeper
    {
        /// <summary>
        /// Enumerate all non-system assemblies already loaded in the default
        /// AppDomain and call RuntimeHelpers.PrepareMethod on every concrete,
        /// non-generic method found. This forces the JIT to compile each
        /// method body so that WtE detection sees all unpacked .NET code as
        /// executed (and therefore committed) memory.
        ///
        /// Returns the total number of methods successfully JIT-compiled.
        /// Errors (abstract methods, generic instantiations, etc.) are swallowed
        /// so that one bad method never aborts the sweep.
        /// </summary>
        /// <param name="_arg">Unused; required by ICLRRuntimeHost API.</param>
        /// <returns>Count of successfully prepared methods (ignored by harness).</returns>
        public static int Sweep(string _arg)
        {
            int count = 0;

            foreach (Assembly asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                // Skip dynamic assemblies — they have no on-disk IL to prepare.
                if (asm.IsDynamic)
                    continue;

                // Skip well-known system assemblies.  We only want the target
                // application's own assemblies (those NOT in the GAC and NOT
                // part of the framework).
                string name = asm.GetName().Name ?? string.Empty;
                if (name.StartsWith("mscorlib",       StringComparison.OrdinalIgnoreCase) ||
                    name.StartsWith("System",          StringComparison.OrdinalIgnoreCase) ||
                    name.StartsWith("Microsoft",       StringComparison.OrdinalIgnoreCase) ||
                    name.StartsWith("PresentationCore", StringComparison.OrdinalIgnoreCase) ||
                    name.StartsWith("PresentationFramework", StringComparison.OrdinalIgnoreCase) ||
                    name.StartsWith("WindowsBase",     StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

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

                    MethodBase[] methods;
                    try
                    {
                        methods = t.GetMethods(
                            BindingFlags.Public    | BindingFlags.NonPublic |
                            BindingFlags.Instance  | BindingFlags.Static    |
                            BindingFlags.DeclaredOnly);
                    }
                    catch
                    {
                        // Some reflection-emitted or COM-interop types refuse
                        // to enumerate their members — skip silently.
                        continue;
                    }

                    foreach (MethodBase m in methods)
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
    }
}
