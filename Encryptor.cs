using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace TacacsSharp
{
    public static class Encryptor
    {
        public static IEnumerable<byte> Encrypt(int sessionId, string key, byte version, byte seqNo, byte[] data)
            => DoWork(sessionId, key, version, seqNo, data);

        public static IEnumerable<byte> Decrypt(int sessionId, string key, byte version, byte seqNo, byte[] data)
            => DoWork(sessionId, key, version, seqNo, data);

        private static IEnumerable<byte> DoWork(int sessionId, string key, byte version, byte seqNo, byte[] data)
        {
            var pseudoPad = GeneratePseudoPad(sessionId, key, version, seqNo, data.Length);
            for(int i=0; i<data.Length; i++)
                yield return (byte)(data.ElementAt(i) ^ pseudoPad.ElementAt(i));
        }

        private static byte[] GeneratePseudoPad(int sessionId, string key, byte version, byte seqNo, int dataToEncryptSize)
        {
            var md5Hash = CalculateHash(sessionId, key, version, seqNo);
            using(var pseudoPad = new MemoryStream())
            {
                pseudoPad.Write(md5Hash, 0, md5Hash.Length);
                while(pseudoPad.Length < dataToEncryptSize)
                {
                    md5Hash = CalculateHash(sessionId, key, version, seqNo, md5Hash).ToArray();
                    pseudoPad.Write(md5Hash, 0 , md5Hash.Length);
                }
                return pseudoPad.ToArray();
            }   
        }

        private static byte[] CalculateHash(int sessionId, string key, byte version, byte seqNo, byte[] previousHash = null)
        {
            var dataToHash = new List<byte>();
            dataToHash.AddRange(BitConverter.GetBytes(sessionId));
            dataToHash.AddRange(Encoding.ASCII.GetBytes(key));
            dataToHash.Add(version);
            dataToHash.Add(seqNo);

            if(previousHash != null) dataToHash.AddRange(previousHash);
            using(var md5 = MD5.Create()) return md5.ComputeHash(dataToHash.ToArray());
        }
    }
}