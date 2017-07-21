using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Security;

namespace RemoteReconCore
{
    class WinApi
    {
        //constants
        public const int TOKEN_DUPLICATE = 2;
        public const int TOKEN_QUERY = 0X00000008;
        public const int TOKEN_IMPERSONATE = 0X00000004;
        public const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const int SecurityImpersonation = 2;
        public const uint TOKEN_ALL_ACCESS = 0xf01ff;
        public const int MAXIMUM_ALLOWED = 0x02000000;
        public const int PROCESS_QUERY_INFORMATION = 0x400;
        public const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        public const int ERROR_NO_TOKEN = 0x3f0;

        //enums and structs


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string function);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("kernel32", SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(UInt32 processAccess, bool bInheritHandle, int processId);
    }
}
