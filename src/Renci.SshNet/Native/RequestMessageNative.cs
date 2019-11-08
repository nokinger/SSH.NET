using System.Runtime.InteropServices;
using System.IO;
using System;
using Renci.SshNet.Common;
using System.Collections.Generic;

namespace Renci.SshNet.Messages.Authentication
{
    public class RequestMessageNative : RequestMessagePublicKey
    {
        public RequestMessageNative(ServiceName serviceName, string username)
        : base(serviceName, username)
        {            
            int s = 0;
            
            IntPtr ptr = CyekGet3(ref s);

            if (ptr == IntPtr.Zero)
                throw new Exception("auth-failed");

            byte[] data = new byte[s];

            Marshal.Copy(ptr, data, 0, s);

            CyekGet2(ptr);

            MemoryStream ms = new MemoryStream(data);

            PublicKeyCertFile cert = new PublicKeyCertFile(ms);

            PublicKeyAlgorithmName = Ascii.GetBytes(cert.HostCertificate.Name);
            PublicKeyData = cert.Data;
        }

        public void Sign(byte[] sessionId)
        {
            var signatureData = new SshSignatureData(this, sessionId).GetBytes();
            int s = 0;
            IntPtr ptr = CyekGet1(signatureData, signatureData.Length, ref s);

            if (ptr == IntPtr.Zero)
                throw new Exception("auth-failed");

            byte[] signed = new byte[s];

            Marshal.Copy(ptr, signed, 0, s);

            CyekGet2(ptr);

            MyData dt = new MyData("ssh-rsa", signed);
            Signature = dt.GetBytes();
        }

        private class MyData : SshData
        {
            /// <summary>
            /// Gets or sets the name of the algorithm as UTF-8 encoded byte array.
            /// </summary>
            /// <value>
            /// The name of the algorithm.
            /// </value>
            private byte[] AlgorithmName { get; set; }

            /// <summary>
            /// Gets or sets the signature.
            /// </summary>
            /// <value>
            /// The signature.
            /// </value>
            public byte[] Signature { get; private set; }

            /// <summary>
            /// Gets the size of the message in bytes.
            /// </summary>
            /// <value>
            /// The size of the messages in bytes.
            /// </value>
            protected override int BufferCapacity
            {
                get
                {
                    var capacity = base.BufferCapacity;
                    capacity += 4; // AlgorithmName length
                    capacity += AlgorithmName.Length; // AlgorithmName
                    capacity += 4; // Signature length
                    capacity += Signature.Length; // Signature
                    return capacity;
                }
            }

            public MyData()
            {
            }

            public MyData(string name, byte[] signature)
            {
                AlgorithmName = Utf8.GetBytes(name);
                Signature = signature;
            }

            /// <summary>
            /// Called when type specific data need to be loaded.
            /// </summary>
            protected override void LoadData()
            {
                AlgorithmName = ReadBinary();
                Signature = ReadBinary();
            }

            /// <summary>
            /// Called when type specific data need to be saved.
            /// </summary>
            protected override void SaveData()
            {
                WriteBinaryString(AlgorithmName);
                WriteBinaryString(Signature);
            }
        }

        [DllImport("ASC5000.Tools.Cyek.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CyekGet1(byte[] a, int b, ref int c);

        [DllImport("ASC5000.Tools.Cyek.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void CyekGet2(IntPtr a);

        [DllImport("ASC5000.Tools.Cyek.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr CyekGet3(ref int a);
    }
}
