using System;
using System.IO;
using System.Net;
using System.Text;

namespace TacacsSharp.Authentication
{
    public class AuthenticationContinuePacketBody
    {
        public short UserMsgLen => (short)UserMsg.Length;
        public short DataLen => (short)((string.IsNullOrEmpty(Data) || string.IsNullOrWhiteSpace(Data)) ? 0 : Data.Length);
        public CommunicationFlag Flags { get; }
        public string UserMsg { get; }
        public string Data { get; }

        public AuthenticationContinuePacketBody(CommunicationFlag flags, string userMsg)
        {
            UserMsg = userMsg;
            Flags = flags;
        }

        public AuthenticationContinuePacketBody(CommunicationFlag flags, string userMsg, string data) : this(flags, userMsg)
        {
            Data = data;
        }

        public byte[] ToArray()
        {
            using(var buffer = new MemoryStream())
            {
                using(var bw = new BinaryWriter(buffer))
                {
                    bw.Write(BitConverter.IsLittleEndian ? IPAddress.HostToNetworkOrder(UserMsgLen) : UserMsgLen);
                    bw.Write(DataLen);
                    bw.Write((byte)Flags);
                    bw.Write(Encoding.ASCII.GetBytes(UserMsg));
                    if(DataLen > 0) bw.Write(Encoding.ASCII.GetBytes(Data));
                }
                return buffer.ToArray();
            }   
        }       
    }
}