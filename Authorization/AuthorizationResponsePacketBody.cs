using System;
using System.IO;
using System.Net;
using System.Text;

namespace TacacsSharp.Authorization
{
    public class AuthorizationResponsePacketBody
    {
        public AuthorizationStatus Status { get; }
        public short ServerMsgLen => (short)((string.IsNullOrEmpty(ServerMsg) || string.IsNullOrWhiteSpace(ServerMsg)) ? 0 : ServerMsg.Length);
        public short DataLen => (short)((string.IsNullOrEmpty(Data) || string.IsNullOrWhiteSpace(Data)) ? 0 : Data.Length);
        public string ServerMsg { get; }
        public string Data { get; }
        public string[] Args { get; }
        public byte ArgCnt => (byte)Args.Length;

        public AuthorizationResponsePacketBody(AuthorizationStatus status, string[] args)
        {
            Status = status;
            Args = args;
        }

        public AuthorizationResponsePacketBody(AuthorizationStatus status, string[] args, string serverMsg) : this(status, args)
        {
            ServerMsg = serverMsg;
        }

        public AuthorizationResponsePacketBody(AuthorizationStatus status, string[] args, string serverMsg, string data)
            : this(status, args, serverMsg)
        {
            Data = data;
        }

        public byte[] ToArray()
        {
            using (var buffer = new MemoryStream())
            {
                using (var bw = new BinaryWriter(buffer))
                {
                    bw.Write((byte)Status);
                    bw.Write(ArgCnt);
                    bw.Write(BitConverter.IsLittleEndian ? IPAddress.HostToNetworkOrder(ServerMsgLen) : ServerMsgLen);
                    bw.Write(DataLen);
                    for (var i = 0; i < ArgCnt; i++)
                    {
                        bw.Write((byte)Args[i].Length);
                    }
                    if (ServerMsgLen > 0) bw.Write(Encoding.ASCII.GetBytes(ServerMsg));
                    if (DataLen > 0) bw.Write(Encoding.ASCII.GetBytes(Data));
                    for (var i = 0; i < ArgCnt; i++)
                    {
                        bw.Write(Encoding.ASCII.GetBytes(Args[i]));
                    }
                }
                return buffer.ToArray();
            }
        }

        public static AuthorizationResponsePacketBody Parse(byte[] bodyData)
        {
            using (var br = new BinaryReader(new MemoryStream(bodyData)))
            {
                var status = br.ReadByte();
                var argCnt = br.ReadByte();
                var serverMsgLen = (short)IPAddress.NetworkToHostOrder(br.ReadInt16());
                var dataLen = br.ReadInt16();
                var argLens = new byte[argCnt];
                for (var i = 0; i < argCnt; i++)
                {
                    argLens[i] = br.ReadByte();
                }
                var serverMsg = serverMsgLen > 0 ? Encoding.ASCII.GetString(br.ReadBytes(serverMsgLen)) : null;
                var data = dataLen > 0 ? Encoding.ASCII.GetString(br.ReadBytes(dataLen)) : null;
                var args = new string[argCnt];
                for (var i = 0; i < argCnt; i++)
                {
                    args[i] = Encoding.ASCII.GetString(br.ReadBytes(argLens[i]));
                }
                return new AuthorizationResponsePacketBody((AuthorizationStatus)Enum.Parse(typeof(AuthorizationStatus), status.ToString()), args, serverMsg, data);
            }
        }

        public override string ToString()
        {
            var builder = new StringBuilder(
                $"status={Status}, arg_count={ArgCnt}, server_msg_len={ServerMsgLen}, data_len={DataLen},"
            );
            for (int i = 1; i <= Args.Length; i++) builder.Append($" arg_{i}_len={Args[i - 1].Length},");
            var srvMessage = ServerMsgLen > 0 ? ServerMsg : "null";
            var data = DataLen > 0 ? Data : "null";
            builder.Append($" server_msg={srvMessage}, data={data},");
            for (int i = 1; i <= Args.Length; i++) builder.Append($" arg_{i}={Args[i - 1]},");
            return builder.Remove(builder.Length - 1, 1).ToString(); // removes last ',' appended above and returns
        }
    }
}