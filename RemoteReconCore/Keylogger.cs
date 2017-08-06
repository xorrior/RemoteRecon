using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.IO;
using System.Text;
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
            return new KeyValuePair<int, string>(0, "");
        }
    }
}
