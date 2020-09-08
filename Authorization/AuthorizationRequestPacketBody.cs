using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace TacacsSharp.Authorization
{
    public class AuthorizationRequestPacketBody
    {
        public AuthenticationMethod AuthenMethod { get; }
        public PrivilegeLevel PrivLvl { get; }
        public AuthenticationType AuthenType { get; }
        public AuthenticationService Service { get; }
        public byte UserLen => (byte)((string.IsNullOrEmpty(User) || string.IsNullOrWhiteSpace(User)) ? 0 : User.Length);
        public byte PortLen => (byte)((string.IsNullOrEmpty(Port) || string.IsNullOrWhiteSpace(Port)) ? 0 : Port.Length);
        public byte RemAddrLen => (byte)(RemAddr == null ? 0 : RemAddr.ToString().Length);
        public byte ArgCnt => (byte)Args.Length;
        public string User { get; }
        public string Port { get; }
        public IPAddress RemAddr { get; }
        public string[] Args { get; }

        public AuthorizationRequestPacketBody(
            AuthenticationMethod authenMethod, 
            PrivilegeLevel privLvl, 
            AuthenticationType authenType, 
            AuthenticationService service, 
            string[] args,
            string user = null,
            string port = null,
            IPAddress remAddr = null
            )
        {
            AuthenMethod = authenMethod;
            PrivLvl = privLvl;
            AuthenType = authenType;
            Service = service;
            User = user;
            Port = port;
            RemAddr = remAddr;
            Args = args;
        }

        public byte[] ToArray()
        {
            using (var buffer = new MemoryStream())
            {
                using(var bw = new BinaryWriter(buffer))
                {
                    bw.Write((byte)AuthenMethod);
                    bw.Write((byte)PrivLvl);
                    bw.Write((byte)AuthenType);
                    bw.Write((byte)Service);
                    bw.Write(UserLen);
                    bw.Write(PortLen);
                    bw.Write(RemAddrLen);
                    bw.Write(ArgCnt);
                    foreach(var arg in Args) bw.Write((byte)arg.Length);
                    if(UserLen > 0) bw.Write(Encoding.ASCII.GetBytes(User));
                    if(PortLen > 0) bw.Write(Encoding.ASCII.GetBytes(Port));
                    if(RemAddrLen > 0) bw.Write(Encoding.ASCII.GetBytes(RemAddr.ToString()));
                    foreach(var arg in Args) bw.Write(Encoding.ASCII.GetBytes(arg));
                }
                return buffer.ToArray();
            }
        }

        public override string ToString()
        {
            var builder = new StringBuilder(
                $"authen_method={AuthenMethod}, priv_lvl={PrivLvl}, authen_type={AuthenType}, authen_service={Service}, user_len={UserLen}, port_len={PortLen}, rem_addr_len={RemAddrLen}, arg_cnt={ArgCnt},"
            );
            for(int i=1; i<=Args.Length; i++) builder.Append($" arg_{i}_len={Args[i-1]},");
            if(UserLen > 0) builder.Append($" user={User},");
            if(PortLen > 0) builder.Append($" port={Port},");
            if(RemAddrLen > 0) builder.Append($" rm_addr={RemAddr},");
            for(int i=1; i<=Args.Length; i++) builder.Append($" arg_{i}={Args[i-1]},");
            return builder.Remove(builder.Length - 1, 1).ToString(); // removes last ',' appended above and returns
        }
    }
}