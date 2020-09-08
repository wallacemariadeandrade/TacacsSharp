using System.IO;
using System.Net;
using System.Text;

namespace TacacsSharp.Authentication
{
    public class AuthenticationStartPacketBody
    {
        public PacketType Action { get; }
        public PrivilegeLevel PrivLvl { get; }
        public AuthenticationType AuthenType { get; }
        public AuthenticationService Service { get; }
        public byte UserLen => (byte)((string.IsNullOrEmpty(User) || string.IsNullOrWhiteSpace(User)) ? 0 : User.Length);
        public byte PortLen => (byte)((string.IsNullOrEmpty(Port) || string.IsNullOrWhiteSpace(Port)) ? 0 : Port.ToString().Length);
        public byte RemAddrLen => (byte)(RemAddr == null ? 0 : RemAddr.ToString().Length);
        public byte DataLen => (byte)((string.IsNullOrEmpty(Data) || string.IsNullOrWhiteSpace(Data)) ? 0 : Data.Length);
        public string User { get; set; }
        public string Port { get; }
        public IPAddress RemAddr { get; }
        public string Data { get; set; }

        public AuthenticationStartPacketBody(PrivilegeLevel privLvl, AuthenticationType type, AuthenticationService service, IPAddress remAdrr = null, string port = null, PacketType action = PacketType.TAC_PLUS_AUTHEN)
        {
            Action = action;
            PrivLvl = privLvl;
            AuthenType = type;
            Service = service;
            RemAddr = remAdrr;
            Port = port;
        }

        public byte[] ToArray()
        {
            using (var buffer = new MemoryStream())
            {
                using (var bw = new BinaryWriter(buffer))
                {
                    bw.Write((byte)Action); // action
                    bw.Write((byte)PrivLvl); // priv_lvl
                    bw.Write((byte)AuthenType); // authen_type
                    bw.Write((byte)Service); // authen_service
                    bw.Write(UserLen); // user_len
                    bw.Write(PortLen); // port_len 
                    bw.Write(RemAddrLen); // remote address len
                    bw.Write(DataLen); // data_len
                    if(UserLen > 0) bw.Write(Encoding.ASCII.GetBytes(User));
                    if(PortLen > 0) bw.Write(Encoding.ASCII.GetBytes(Port)); // port
                    if(RemAddrLen > 0) bw.Write(Encoding.ASCII.GetBytes(RemAddr.ToString())); // remote address
                    if(DataLen > 0) bw.Write(Encoding.ASCII.GetBytes(Data));
                }
                return buffer.ToArray();
            }
        }
    }
}