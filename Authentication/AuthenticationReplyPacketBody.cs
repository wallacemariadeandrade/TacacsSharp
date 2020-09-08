using System;
using System.IO;
using System.Net;
using System.Text;

namespace TacacsSharp.Authentication
{
    public class AuthenticationReplyPacketBody
    {
        public AuthenticationStatus AuthStatus { get; }
        public EncryptionFlag Flags { get; }
        public short ServerMsgLen => (short)((string.IsNullOrEmpty(ServerMsg) || string.IsNullOrWhiteSpace(ServerMsg)) ? 0 : ServerMsg.Length);
        public short DataLen => (short)((string.IsNullOrEmpty(Data) || string.IsNullOrWhiteSpace(Data)) ? 0 : Data.Length);
        public string ServerMsg { get; }
        public string Data { get; }

        public AuthenticationReplyPacketBody(AuthenticationStatus authStatus, EncryptionFlag flags)
        {
            AuthStatus = authStatus;
            Flags = flags;
        }

        public AuthenticationReplyPacketBody(AuthenticationStatus authStatus, EncryptionFlag flags, string serverMsg) : this(authStatus, flags)
        {
            ServerMsg = serverMsg;
        }

        public AuthenticationReplyPacketBody(AuthenticationStatus authStatus, EncryptionFlag flags, string serverMsg, string data) 
            :this(authStatus, flags, serverMsg)
        {
            Data = data;
        }

        public byte[] ToArray()
        {
            using(var buffer = new MemoryStream())
            {
                using(var bw = new BinaryWriter(buffer))
                {
                    bw.Write((byte)AuthStatus);
                    bw.Write((byte)Flags);
                    bw.Write(BitConverter.IsLittleEndian ? IPAddress.HostToNetworkOrder(ServerMsgLen) : ServerMsgLen);
                    bw.Write(DataLen);
                    if(ServerMsgLen > 0) bw.Write(Encoding.ASCII.GetBytes(ServerMsg));
                    if(DataLen > 0) bw.Write(Encoding.ASCII.GetBytes(Data)); 
                }
                return buffer.ToArray();
            }
        }

        public static AuthenticationReplyPacketBody Parse(byte[] data)
        {
            using(var br = new BinaryReader(new MemoryStream(data)))
            {
                var status = br.ReadByte();
                var flags = br.ReadByte();
                var serverMsgLen = (short)IPAddress.NetworkToHostOrder(br.ReadInt16());
                var dataLen = br.ReadInt16();

                return new AuthenticationReplyPacketBody(
                    (AuthenticationStatus)Enum.Parse(typeof(AuthenticationStatus), status.ToString()),
                    (EncryptionFlag)Enum.Parse(typeof(EncryptionFlag), flags.ToString()),
                    serverMsgLen > 0 ? Encoding.ASCII.GetString(br.ReadBytes(serverMsgLen)) : null,
                    dataLen > 0 ? Encoding.ASCII.GetString(br.ReadBytes(dataLen)) : null
                );
            }
        }

        public override string ToString()
            => string.Format(
                "status={0}, flags={1}, server_msg_len={2}, data_len={3}, server_msg={4}, data={5}",
                AuthStatus,
                Flags,
                ServerMsgLen,
                DataLen,
                ServerMsgLen > 0 ? ServerMsg : "null",
                DataLen > 0 ? Data : "null"
            );
    }
}