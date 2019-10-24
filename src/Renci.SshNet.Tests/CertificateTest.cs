namespace Renci.SshNet.Tests
{
    using System;

    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class CertificateTest
    {
        [TestMethod]
        public void Test1()
        {
            var keyFile = new PrivateKeyFile(@"D:\Sources\sca\admin\cmv3-master-keys\user\atlascopco\asc5000\tools.1\asc_tools.1", "acIsSince1008SanderFree");
            var certFile = new PublicKeyCertFile(@"D:\Sources\sca\admin\cmv3-master-keys\user\atlascopco\asc5000\tools.1\asc_tools.1-cert.pub");
            var authMethod = new PrivateKeyCertAuthenticationMethod("root", keyFile, certFile);
            var connectionInfo = new ConnectionInfo("10.49.39.99", "root", authMethod);

            using (var client = new SshClient(connectionInfo))
            {
                client.Connect();
                var commmand = client.RunCommand("ifconfig eth2");
                Console.WriteLine(commmand.Result);
            }
        }
    }
}