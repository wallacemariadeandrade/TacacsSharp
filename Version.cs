namespace TacacsSharp
{
    public struct Version
    {
        public byte Minor { get; }
        public byte Major { get; }
        public byte Value => (byte)((Major << 4) ^ Minor);

        public Version(byte major = 0xc, byte minor = 0x0)
        {
            Minor = minor;
            Major = major;
        }

        public static Version Parse(byte version)
        {
            var major = (byte)(version >> 4);
            return new Version(major, (byte)((major << 4) ^ version));
        }
    }
}