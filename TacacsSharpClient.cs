using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using TacacsSharp.Accounting;
using TacacsSharp.Authentication;
using TacacsSharp.Authorization;

namespace TacacsSharp
{
    public class TacacsSharpClient
    {
        private string serverIp;
        private int serverPort;
        private string sharedKey;
        private bool isEncryptionActive;

        public TacacsSharpClient(string serverIp, int serverPort = 49, string sharedKey = null)
        {
            this.serverIp = serverIp;
            this.serverPort = serverPort;
            this.sharedKey = sharedKey;
            isEncryptionActive = (!string.IsNullOrEmpty(sharedKey) && !string.IsNullOrWhiteSpace(sharedKey));
        }

        private byte[] SendAndReceiveData(TcpClient client, byte[] data)
        {
            var s = client.GetStream();
            if(s.CanWrite) s.Write(data, 0 , data.Length);
            var buffer = new byte[client.ReceiveBufferSize];
            s.Read(buffer, 0, (int)client.ReceiveBufferSize);
            return buffer;
        }

        private async Task<byte[]> SendAndReceiveDataAsync(TcpClient client, byte[] data)
        {
            var s = client.GetStream();
            if(s.CanWrite) s.Write(data, 0 , data.Length);
            var buffer = new byte[client.ReceiveBufferSize];
            await s.ReadAsync(buffer, 0, (int)client.ReceiveBufferSize);
            return buffer;
        }

        private IEnumerable<byte> MergeHeaderWithBody(PacketHeader header, byte[] bodyBytes)
            => isEncryptionActive? header.ToArray().Concat(Encryptor.Encrypt(header.SessionId, sharedKey, 192, header.SeqNumber, bodyBytes)) 
                : header.ToArray().Concat(bodyBytes);
        
        private Tuple<PacketHeader, byte[]> UnmergeHeaderAndBody(byte[] bytesFromServer)
        {
            using(var br = new BinaryReader(new MemoryStream(bytesFromServer)))
            {
                var recvHeader = PacketHeader.Parse(br.ReadBytes(12)); 
                var recvBodyBytes = br.ReadBytes(recvHeader.BodyLength);
                if(isEncryptionActive) recvBodyBytes = Encryptor.Decrypt(recvHeader.SessionId, sharedKey, 192, recvHeader.SeqNumber, recvBodyBytes).ToArray();
                return new Tuple<PacketHeader, byte[]>(recvHeader, recvBodyBytes);
            }
        }

        public async Task<AuthenticationStatus> AuthenticateAsciiAsync(string user, string pass, string remoteAddr, string port, 
            PrivilegeLevel privLev = PrivilegeLevel.TAC_PLUS_PRIV_LVL_MAX, AuthenticationService authService = AuthenticationService.TAC_PLUS_AUTHEN_SVC_LOGIN)
        {
            var authStartBytes = new AuthenticationStartPacketBody(privLev, AuthenticationType.TAC_PLUS_AUTHEN_TYPE_ASCII, authService, IPAddress.Parse(remoteAddr), port).ToArray();

            var header = new PacketHeader(
                PacketType.TAC_PLUS_AUTHEN, 1, 
                isEncryptionActive ? EncryptionFlag.TAC_PLUS_ENCRYPTED_FLAG : EncryptionFlag.TAC_PLUS_UNENCRYPTED_FLAG, 
                authStartBytes.Length
            );

            using(TcpClient client = new TcpClient(serverIp, serverPort))
            {
                var recvData = UnmergeHeaderAndBody(await SendAndReceiveDataAsync(client, MergeHeaderWithBody(header, authStartBytes).ToArray()));
                var recvHeader = recvData.Item1;
                if(AuthenticationReplyPacketBody.Parse(recvData.Item2).AuthStatus == AuthenticationStatus.GETUSER)
                {
                    var continuePacket = new AuthenticationContinuePacketBody(CommunicationFlag.CONTINUES, user);
                    recvHeader.SeqNumber++;
                    recvHeader.BodyLength = continuePacket.ToArray().Count();

                    recvData = UnmergeHeaderAndBody(await SendAndReceiveDataAsync(client, MergeHeaderWithBody(recvHeader, continuePacket.ToArray()).ToArray()));
                    recvHeader = recvData.Item1;

                    if(AuthenticationReplyPacketBody.Parse(recvData.Item2).AuthStatus == AuthenticationStatus.GETPASS)
                    {
                        continuePacket = new AuthenticationContinuePacketBody(CommunicationFlag.CONTINUES, pass);
                        recvHeader.SeqNumber++;
                        recvHeader.BodyLength = continuePacket.ToArray().Count();

                        recvData = UnmergeHeaderAndBody(await SendAndReceiveDataAsync(client, MergeHeaderWithBody(recvHeader, continuePacket.ToArray()).ToArray()));
                    }
                }
                return AuthenticationReplyPacketBody.Parse(recvData.Item2).AuthStatus;
            }
        }

        public AuthenticationStatus AuthenticateAscii(string user, string pass, string remoteAddr, string port, 
            PrivilegeLevel privLev = PrivilegeLevel.TAC_PLUS_PRIV_LVL_MAX, AuthenticationService authService = AuthenticationService.TAC_PLUS_AUTHEN_SVC_LOGIN)
        {
            var authStartBytes = new AuthenticationStartPacketBody(privLev, AuthenticationType.TAC_PLUS_AUTHEN_TYPE_ASCII, authService, IPAddress.Parse(remoteAddr), port).ToArray();

            var header = new PacketHeader(
                PacketType.TAC_PLUS_AUTHEN, 1, 
                isEncryptionActive ? EncryptionFlag.TAC_PLUS_ENCRYPTED_FLAG : EncryptionFlag.TAC_PLUS_UNENCRYPTED_FLAG, 
                authStartBytes.Length
            );

            using(TcpClient client = new TcpClient(serverIp, serverPort))
            {
                var recvData = UnmergeHeaderAndBody(SendAndReceiveData(client, MergeHeaderWithBody(header, authStartBytes).ToArray()));
                var recvHeader = recvData.Item1;
                if(AuthenticationReplyPacketBody.Parse(recvData.Item2).AuthStatus == AuthenticationStatus.GETUSER)
                {
                    var continuePacket = new AuthenticationContinuePacketBody(CommunicationFlag.CONTINUES, user);
                    recvHeader.SeqNumber++;
                    recvHeader.BodyLength = continuePacket.ToArray().Count();

                    recvData = UnmergeHeaderAndBody(SendAndReceiveData(client, MergeHeaderWithBody(recvHeader, continuePacket.ToArray()).ToArray()));
                    recvHeader = recvData.Item1;

                    if(AuthenticationReplyPacketBody.Parse(recvData.Item2).AuthStatus == AuthenticationStatus.GETPASS)
                    {
                        continuePacket = new AuthenticationContinuePacketBody(CommunicationFlag.CONTINUES, pass);
                        recvHeader.SeqNumber++;
                        recvHeader.BodyLength = continuePacket.ToArray().Count();

                        recvData = UnmergeHeaderAndBody(SendAndReceiveData(client, MergeHeaderWithBody(recvHeader, continuePacket.ToArray()).ToArray()));
                    }
                }
                return AuthenticationReplyPacketBody.Parse(recvData.Item2).AuthStatus;
            }
        }

        public AuthorizationResponsePacketBody Authorize(string user, string[] args = null, AuthenticationType authenticationType = AuthenticationType.TAC_PLUS_AUTHEN_TYPE_ASCII, PrivilegeLevel privLev = PrivilegeLevel.TAC_PLUS_PRIV_LVL_MAX,
            AuthenticationService authService = AuthenticationService.TAC_PLUS_AUTHEN_SVC_NONE)
        {
            args = args ?? new[] {"service=shell", "cmd="};

            var authRequestBytes = new AuthorizationRequestPacketBody(AuthenticationMethod.TAC_PLUS_AUTHEN_METH_NONE, privLev, authenticationType, authService, args, user).ToArray();

            var header = new PacketHeader(
                PacketType.TAC_PLUS_AUTHOR, 1,
                isEncryptionActive ? EncryptionFlag.TAC_PLUS_ENCRYPTED_FLAG : EncryptionFlag.TAC_PLUS_UNENCRYPTED_FLAG,
                authRequestBytes.Length
            );

            using (TcpClient client = new TcpClient(serverIp, serverPort))
            {
                var recvData = UnmergeHeaderAndBody(SendAndReceiveData(client, MergeHeaderWithBody(header, authRequestBytes).ToArray()));
                var recvHeader = recvData.Item1;
                var response = AuthorizationResponsePacketBody.Parse(recvData.Item2);
                return response;
            }
        }

        public AccountingResponsePacketBody Accounting(string user, string[] args = null, AuthenticationType authenticationType = AuthenticationType.TAC_PLUS_AUTHEN_TYPE_ASCII, AccountingFlag flags = AccountingFlag.TAC_PLUS_ACCT_FLAG_START,
            PrivilegeLevel privLev = PrivilegeLevel.TAC_PLUS_PRIV_LVL_MAX, AuthenticationService authService = AuthenticationService.TAC_PLUS_AUTHEN_SVC_NONE)
        {
            var acctRequestBytes = new AccountingRequestPacketBody(flags, AuthenticationMethod.TAC_PLUS_AUTHEN_METH_NONE, privLev, authenticationType, authService, args, user).ToArray();

            var header = new PacketHeader(
                PacketType.TAC_PLUS_ACCT, 1,
                isEncryptionActive ? EncryptionFlag.TAC_PLUS_ENCRYPTED_FLAG : EncryptionFlag.TAC_PLUS_UNENCRYPTED_FLAG,
                acctRequestBytes.Length
            );

            using (TcpClient client = new TcpClient(serverIp, serverPort))
            {
                var recvData = UnmergeHeaderAndBody(SendAndReceiveData(client, MergeHeaderWithBody(header, acctRequestBytes).ToArray()));
                var recvHeader = recvData.Item1;
                var response = AccountingResponsePacketBody.Parse(recvData.Item2);
                return response;
            }
        }
    }
}