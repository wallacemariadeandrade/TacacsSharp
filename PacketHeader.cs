using System;
using System.IO;
using System.Net;

namespace TacacsSharp
{
    public class PacketHeader 
    {
        public Version Version { get; }
        public PacketType Type { get; set; }
        public byte SeqNumber { get; set; }
        public EncryptionFlag Flags { get; }
        public int SessionId { get; set; }
        public int BodyLength { get; set; }      

        public PacketHeader(PacketType type, byte seqNumber, EncryptionFlag flags, int bodyLength, byte majorVersion = 0xc, byte minorVersion = 0x0)
            :this(type, seqNumber, flags, bodyLength, new Random().Next(), majorVersion, minorVersion) { }

        public PacketHeader(PacketType type, byte seqNumber, EncryptionFlag flags, int bodyLength, int sessionId, byte majorVersion = 0xc, byte minorVersion = 0x0) 
            :this(type, seqNumber, flags, bodyLength, new Random().Next(), new Version(majorVersion, minorVersion)) { }

        public PacketHeader(PacketType type, byte seqNumber, EncryptionFlag flags, int bodyLength, int sessionId, Version version) 
        {
            Type = type;
            SeqNumber = seqNumber;
            Flags = flags;
            BodyLength = bodyLength;
            Version = version;
            SessionId = sessionId;
        }

        public byte[] ToArray()
        {
            using(var header = new MemoryStream(new byte[12]))
            {
                using(var bw = new BinaryWriter(header))
                {
                    bw.Write(Version.Value); // version
                    bw.Write((byte)Type); // type
                    bw.Write((byte)SeqNumber); // seq number
                    bw.Write((byte)Flags); // flags
                    bw.Write(SessionId); // session_id
                    bw.Write(BitConverter.IsLittleEndian ? IPAddress.HostToNetworkOrder(BodyLength) : BodyLength); // length
                }
                return header.ToArray();
            }
        }

        public static PacketHeader Parse(byte[] data)
        {
            using(var br = new BinaryReader(new MemoryStream(data)))
            {
                var version = br.ReadByte();
                var type = br.ReadByte();
                var seqNo = br.ReadByte();
                var flags = br.ReadByte();
                var sessionIdReply = br.ReadInt32();
                var replyLength = IPAddress.NetworkToHostOrder(br.ReadInt32());

                return new PacketHeader(
                    (PacketType)Enum.Parse(typeof(PacketType), type.ToString()),
                    seqNo,
                    (EncryptionFlag)Enum.Parse(typeof(EncryptionFlag), flags.ToString()),
                    replyLength,
                    sessionIdReply,
                    Version.Parse(version)
                );
            }
        }

        public override string ToString() 
            => string.Format("major_version=0x{0:x}, minor_version=0x{1:x}, type={2}, seq_no={3}, flags={4}, session_id={5}, length={6}",
                Version.Major,
                Version.Minor,
                Type,
                SeqNumber,
                Flags,
                SessionId,
                BodyLength
            );
    }
}