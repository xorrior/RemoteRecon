using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace RemoteReconCore
{
    public interface IJobs
    {
        KeyValuePair<int, string> Run();
    }
}
