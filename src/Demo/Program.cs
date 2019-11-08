using System;
using System.Collections.Generic;
using System.Windows.Forms;
using Renci.SshNet;

namespace Demo
{
    static class Program
    {
        /// <summary>
        /// Der Haupteinstiegspunkt für die Anwendung.
        /// </summary>
        [STAThread]
        static void Main()
        {
            try
            {
                var authMethod = new NativeAuthenticationMethod("root");

                var currentStationConnection = new ConnectionInfo("10.49.39.33", 22, "root", authMethod);

                SshClient client = new SshClient(currentStationConnection);

                client.Connect();

                string ret = client.CreateCommand("ls -la /").Execute();

                MessageBox.Show(ret);
            }
            catch(Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }
    }
}
