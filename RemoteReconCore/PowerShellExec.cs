using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;


namespace RemoteReconCore
{
    //Powershell execution via runspaces
    class PowerShellExec
    {
        private StringBuilder cmd;
        public PowerShellExec(string command, Dictionary<string, string> loadedScripts = null)
        {
            foreach (KeyValuePair<string, string> scripts in loadedScripts)
            {
                cmd.Append(scripts.Value);
            }

            cmd.Append("\r\n" + command);
        }

        public string PsRun()
        {
            string results = "";
            //TODO
            return results;
        }
    }
}
