using System;
using System.IO;
using System.Net;
using System.Text;

namespace TacacsSharp.Accounting
{
    public class AccountingResponsePacketBody
    {
        public short ServerMsgLen => (short)((string.IsNullOrEmpty(ServerMsg) || string.IsNullOrWhiteSpace(ServerMsg)) ? 0 : ServerMsg.Length);
        public short DataLen => (short)((string.IsNullOrEmpty(Data) || string.IsNullOrWhiteSpace(Data)) ? 0 : Data.Length);
        public AccountingStatus Status { get; }
        public string ServerMsg { get; }
        public string Data { get; }

        public AccountingResponsePacketBody(AccountingStatus status)
        {
            Status = status;
        }

        public AccountingResponsePacketBody(AccountingStatus status, string serverMsg) : this(status)
        {
            ServerMsg = serverMsg;
        }

        public AccountingResponsePacketBody(AccountingStatus status, string serverMsg, string data) : this(status, serverMsg)
        {
            Data = data;
        }

        public byte[] ToArray()
        {
            using (var buffer = new MemoryStream())
            {
                using (var bw = new BinaryWriter(buffer))
                {
                    bw.Write(BitConverter.IsLittleEndian ? IPAddress.HostToNetworkOrder(ServerMsgLen) : ServerMsgLen);
                    bw.Write(DataLen);
                    bw.Write((byte)Status);
                    if (ServerMsgLen > 0) bw.Write(Encoding.ASCII.GetBytes(ServerMsg));
                    if (DataLen > 0) bw.Write(Encoding.ASCII.GetBytes(Data));
                }
                return buffer.ToArray();
            }
        }

        public static AccountingResponsePacketBody Parse(byte[] bodyData)
        {
            using (var br = new BinaryReader(new MemoryStream(bodyData)))
            {
                var serverMsgLen = (short)IPAddress.NetworkToHostOrder(br.ReadInt16());
                var dataLen = br.ReadInt16();
                var status = br.ReadByte();
                var serverMsg = serverMsgLen > 0 ? Encoding.ASCII.GetString(br.ReadBytes(serverMsgLen)) : null;
                var data = dataLen > 0 ? Encoding.ASCII.GetString(br.ReadBytes(dataLen)) : null;
                return new AccountingResponsePacketBody((AccountingStatus)Enum.Parse(typeof(AuthorizationStatus), status.ToString()), serverMsg, data);
            }
        }

        public override string ToString()
        {
            var builder = new StringBuilder(
                $"server_msg_len={ServerMsgLen}, data_len={DataLen}, status={Status},"
            );
            var srvMessage = ServerMsgLen > 0 ? ServerMsg : "null";
            var data = DataLen > 0 ? Data : "null";
            builder.Append($" server_msg={srvMessage}, data={data},");
            return builder.Remove(builder.Length - 1, 1).ToString(); // removes last ',' appended above and returns
        }
    }
}
