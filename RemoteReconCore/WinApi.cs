using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Security;
using System.Security.AccessControl;

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
        public static IntPtr CreateNullDescriptorPtr()
        {
            RawSecurityDescriptor gsd = new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent, null, null, null, null);
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            sa.bInheritHandle = 1;
            byte[] desc = new byte[gsd.BinaryLength];
            gsd.GetBinaryForm(desc, 0);
            sa.lpSecurityDescriptor = Marshal.AllocHGlobal(desc.Length);
            Marshal.Copy(desc, 0, sa.lpSecurityDescriptor, desc.Length);

            IntPtr sec = Marshal.AllocHGlobal(Marshal.SizeOf(sa));
            Marshal.StructureToPtr(sa, sec, true);

            return sec;
        }

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

        //PInvoke Definitions
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateNamedPipe(string Pipename,
                                                      uint dwOpenMode,
                                                      uint dwPipeMode,
                                                      uint nMaxInstances,
                                                      uint nOutBufferSize,
                                                      uint nInBufferSize,
                                                      uint nDefaultTimeout,
                                                      IntPtr lpSecurityAttributes);


        [DllImport("kernel32.dll", EntryPoint = "PeekNamedPipe", SetLastError = true)]
        public static extern bool PeekNamedPipe(IntPtr handle,
                                                 byte[] buffer,
                                                 uint nBufferSize,
                                                 ref uint bytesRead,
                                                 ref uint bytesAvail,
                                                 ref uint BytesLeftThisMessage);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(IntPtr handle, byte[] buffer, uint toRead, ref uint read, IntPtr lpOverLapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ConnectNamedPipe(IntPtr pHandle, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DisconnectNamedPipe(IntPtr pHandle);

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        public IntPtr hPipe;
        public const uint INBOUND = 0x00000001;
        public const uint PIPE_ACCESS_INBOUND = 0x00000001;
        public const uint PIPE_READMODE_BYTE = 0x00000000;
        public const uint PIPE_WAIT = 0x00000000;
        public const ulong ERROR_PIPE_CONNECTED = 535;
    }
}
