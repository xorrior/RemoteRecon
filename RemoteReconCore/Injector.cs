using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace RemoteReconCore
{
    class Injector
    {
        //Class that will handle injecting the RemoteReconHost native dll into remote processes.
        public static bool EnableSeDebugPrivilege()
        {
            IntPtr ThreadHandle = IntPtr.Zero;
            IntPtr TokenHandle = IntPtr.Zero;

            ThreadHandle = WinApi.GetCurrentThread();
            if (ThreadHandle == IntPtr.Zero)
            {
                return false;
            }

            bool result = WinApi.OpenThreadToken(ThreadHandle, (WinApi.TOKEN_QUERY | WinApi.TOKEN_ADJUST_PRIVILEGES), false, out TokenHandle);

            if (!result)
            {
                var errorCode = Marshal.GetLastWin32Error();
                if (errorCode == WinApi.ERROR_NO_TOKEN)
                {
                    if (!WinApi.ImpersonateSelf(3))
                    {
                        return false;
                    }

                    if(!WinApi.OpenThreadToken(ThreadHandle, (WinApi.TOKEN_QUERY | WinApi.TOKEN_ADJUST_PRIVILEGES), false, out TokenHandle))
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
            }

            WinApi.LUID pLUID = new WinApi.LUID();
            if (!WinApi.LookupPrivilegeValue(null, "SeDebugPrivilege", out pLUID))
            {
                return false;
            }

            WinApi.TOKEN_PRIVILEGES tokenprivileges = new WinApi.TOKEN_PRIVILEGES();
            WinApi.TOKEN_PRIVILEGES emptytokenprivileges = new WinApi.TOKEN_PRIVILEGES();
            tokenprivileges.PrivilegeCount = 1;
            tokenprivileges.Privileges.Luid = pLUID;
            tokenprivileges.Privileges.Attributes = WinApi.SE_PRIVILEGE_ENABLED;
            uint returnlength = 0;
            WinApi.AdjustTokenPrivileges(TokenHandle, false, ref tokenprivileges, (uint)Marshal.SizeOf(typeof(WinApi.TOKEN_PRIVILEGES)), ref emptytokenprivileges, out returnlength);
            var LastError = Marshal.GetLastWin32Error();


        }
    }
}
