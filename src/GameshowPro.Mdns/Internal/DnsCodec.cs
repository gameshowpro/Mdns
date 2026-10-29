namespace GameshowPro.Mdns.Internal;

internal static class DnsCodec
{
    private const int MaxPacket = 65535;
    private static readonly UTF8Encoding s_utf8 = new(false, true);

    public static bool TryRead(ReadOnlySpan<byte> packet, out DnsMessage? message)
    {
        message = null;
        if (packet.Length is < 12 or > MaxPacket)
        {
            return false;
        }

        try
        {
            int offset = 0;
            ushort id = Read16(packet, ref offset);
            ushort flags = Read16(packet, ref offset);
            ushort qd = Read16(packet, ref offset);
            ushort an = Read16(packet, ref offset);
            ushort ns = Read16(packet, ref offset);
            ushort ar = Read16(packet, ref offset);
            // Every question consumes at least five bytes; every RR at least eleven.
            if ((long)qd * 5 + (long)(an + ns + ar) * 11 > packet.Length - 12)
            {
                return false;
            }

            ImmutableArray<DnsQuestion>.Builder questions = ImmutableArray.CreateBuilder<DnsQuestion>(qd);
            ImmutableArray<DnsRecord>.Builder answers = ImmutableArray.CreateBuilder<DnsRecord>(an);
            ImmutableArray<DnsRecord>.Builder authorities = ImmutableArray.CreateBuilder<DnsRecord>(ns);
            ImmutableArray<DnsRecord>.Builder additionals = ImmutableArray.CreateBuilder<DnsRecord>(ar);
            for (int i = 0; i < qd; i++)
            {
                string name = ReadName(packet, ref offset);
                questions.Add(new(name, Read16(packet, ref offset), Read16(packet, ref offset)));
            }
            for (int i = 0; i < an; i++)
            {
                answers.Add(ReadRecord(packet, ref offset));
            }

            for (int i = 0; i < ns; i++)
            {
                authorities.Add(ReadRecord(packet, ref offset));
            }

            for (int i = 0; i < ar; i++)
            {
                additionals.Add(ReadRecord(packet, ref offset));
            }

            if (offset != packet.Length)
            {
                return false;
            }

            message = new DnsMessage
            {
                Id = id, Flags = flags, Questions = questions.MoveToImmutable(),
                Answers = answers.MoveToImmutable(), Authorities = authorities.MoveToImmutable(),
                Additionals = additionals.MoveToImmutable()
            };
            return true;
        }
        catch (ArgumentException) { return false; }
        catch (InvalidOperationException) { return false; }
        catch (OverflowException) { return false; }
    }

    public static byte[] Write(DnsMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        List<byte> bytes = new(512);
        Put16(bytes, message.Id);
        Put16(bytes, message.Flags);
        Put16(bytes, Count(message.Questions));
        Put16(bytes, Count(message.Answers));
        Put16(bytes, Count(message.Authorities));
        Put16(bytes, Count(message.Additionals));
        foreach (DnsQuestion question in message.Questions)
        {
            PutName(bytes, question.Name);
            Put16(bytes, question.Type);
            Put16(bytes, question.Class);
            CheckSize(bytes);
        }
        foreach (DnsRecord record in message.Answers)
        {
            PutRecord(bytes, record);
        }

        foreach (DnsRecord record in message.Authorities)
        {
            PutRecord(bytes, record);
        }

        foreach (DnsRecord record in message.Additionals)
        {
            PutRecord(bytes, record);
        }

        if (bytes.Count > MaxPacket)
        {
            throw new ArgumentException("DNS packet exceeds 65535 bytes.", nameof(message));
        }

        return [.. bytes];
    }

    private static ushort Count<T>(ImmutableArray<T> values)
    {
        if (values.Length > ushort.MaxValue)
        {
            throw new ArgumentException("Too many DNS section entries.");
        }

        return (ushort)values.Length;
    }

    private static DnsRecord ReadRecord(ReadOnlySpan<byte> packet, ref int offset)
    {
        string name = ReadName(packet, ref offset);
        ushort type = Read16(packet, ref offset);
        ushort @class = Read16(packet, ref offset);
        uint ttl = Read32(packet, ref offset);
        ushort length = Read16(packet, ref offset);
        int end = checked(offset + length);
        if (end > packet.Length)
        {
            throw new ArgumentException("Truncated DNS record.");
        }

        DnsData data;
        switch (type)
        {
            case DnsTypes.A:
            case DnsTypes.Aaaa:
                if (length != (type == DnsTypes.A ? 4 : 16))
                {
                    throw new ArgumentException("Invalid address length.");
                }

                data = new AddressData(new IPAddress(packet.Slice(offset, length)));
                offset = end;
                break;
            case DnsTypes.Ptr:
                data = new NameData(ReadName(packet, ref offset));
                RequireEnd(offset, end);
                break;
            case DnsTypes.Srv:
                if (end - offset < 7)
                {
                    throw new ArgumentException("Invalid SRV length.");
                }

                ushort priority = Read16(packet, ref offset);
                ushort weight = Read16(packet, ref offset);
                ushort port = Read16(packet, ref offset);
                data = new SrvData(priority, weight, port, ReadName(packet, ref offset));
                RequireEnd(offset, end);
                break;
            case DnsTypes.Txt:
                ImmutableArray<byte[]>.Builder strings = ImmutableArray.CreateBuilder<byte[]>();
                while (offset < end)
                {
                    byte n = packet[offset++];
                    if (n > end - offset)
                    {
                        throw new ArgumentException("Invalid TXT length.");
                    }

                    strings.Add(packet.Slice(offset, n).ToArray());
                    offset += n;
                }
                data = new TxtData(strings.ToImmutable());
                break;
            case DnsTypes.Nsec:
                string nextName = ReadName(packet, ref offset);
                ImmutableArray<ushort>.Builder types = ImmutableArray.CreateBuilder<ushort>();
                int previousWindow = -1;
                while (offset < end)
                {
                    if (end - offset < 3)
                    {
                        throw new ArgumentException("Invalid NSEC bitmap.");
                    }

                    byte window = packet[offset++];
                    byte bitmapLength = packet[offset++];
                    if (window <= previousWindow || bitmapLength is < 1 or > 32 || bitmapLength > end - offset)
                    {
                        throw new ArgumentException("Invalid NSEC bitmap.");
                    }

                    previousWindow = window;
                    bool any = false;
                    byte last = (byte)0;
                    for (int octet = 0; octet < bitmapLength; octet++)
                    {
                        byte bits = packet[offset++];
                        last = bits;
                        any |= bits != 0;
                        for (int bit = 0; bit < 8; bit++)
                        {
                            if ((bits & (0x80 >> bit)) != 0)
                            {
                                types.Add((ushort)((window << 8) | (octet << 3) | bit));
                            }
                        }
                    }
                    if (!any || last == 0)
                    {
                        throw new ArgumentException("Invalid NSEC bitmap.");
                    }
                }
                if (previousWindow < 0)
                {
                    throw new ArgumentException("Empty NSEC bitmap.");
                }

                data = new NsecData(nextName, types.ToImmutable());
                break;
            default:
                data = new UnknownData(packet.Slice(offset, length).ToArray());
                offset = end;
                break;
        }
        if (offset != end)
        {
            throw new ArgumentException("Invalid DNS record length.");
        }

        return new(name, type, @class, ttl, data);
    }

    private static string ReadName(ReadOnlySpan<byte> packet, ref int offset)
    {
        List<string> labels = [];
        int pos = offset;
        bool jumped = false;
        int wireLength = 1;
        int jumps = 0;
        while (true)
        {
            if (pos >= packet.Length)
            {
                throw new ArgumentException("Truncated DNS name.");
            }

            byte size = packet[pos++];
            if ((size & 0xc0) == 0xc0)
            {
                if (pos >= packet.Length)
                {
                    throw new ArgumentException("Truncated DNS pointer.");
                }

                int pointer = ((size & 0x3f) << 8) | packet[pos++];
                if (pointer < 12 || pointer >= pos - 2 || ++jumps > 128)
                {
                    throw new ArgumentException("Invalid DNS pointer.");
                }

                if (!jumped) { offset = pos; jumped = true; }
                pos = pointer;
                continue;
            }
            if ((size & 0xc0) != 0)
            {
                throw new ArgumentException("Invalid DNS label type.");
            }

            if (size == 0)
            {
                if (!jumped)
                {
                    offset = pos;
                }

                return DnsNames.FromLabels([.. labels]);
            }
            if (size > 63 || size > packet.Length - pos)
            {
                throw new ArgumentException("Truncated DNS label.");
            }

            wireLength += size + 1;
            if (wireLength > 255)
            {
                throw new ArgumentException("DNS name is too long.");
            }

            labels.Add(s_utf8.GetString(packet.Slice(pos, size)));
            pos += size;
        }
    }

    private static void PutRecord(List<byte> bytes, DnsRecord record)
    {
        PutName(bytes, record.Name);
        Put16(bytes, record.Type);
        Put16(bytes, record.Class);
        Put32(bytes, record.Ttl);
        int lengthPosition = bytes.Count;
        Put16(bytes, 0);
        int start = bytes.Count;
        switch (record.Type, record.Data)
        {
            case (DnsTypes.A, AddressData ipv4) when ipv4.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork:
                AppendBytes(bytes, ipv4.Address.GetAddressBytes()); break;
            case (DnsTypes.Aaaa, AddressData ipv6) when ipv6.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6:
                AppendBytes(bytes, ipv6.Address.GetAddressBytes()); break;
            case (DnsTypes.Ptr, NameData ptr): PutName(bytes, ptr.Name); break;
            case (DnsTypes.Srv, SrvData srv):
                Put16(bytes, srv.Priority); Put16(bytes, srv.Weight); Put16(bytes, srv.Port); PutName(bytes, srv.Target); break;
            case (DnsTypes.Txt, TxtData txt):
                foreach (byte[]? item in txt.Strings)
                {
                    if (item is null || item.Length > 255)
                    {
                        throw new ArgumentException("Invalid TXT item.");
                    }

                    bytes.Add((byte)item.Length);
                    AppendBytes(bytes, item);
                }
                break;
            case (DnsTypes.Nsec, NsecData nsec):
                PutName(bytes, nsec.NextName);
                if (nsec.Types.IsEmpty)
                {
                    throw new ArgumentException("NSEC needs at least one type.", nameof(record));
                }

                foreach (IGrouping<int, ushort> group in nsec.Types.Distinct().Order().GroupBy(t => t >> 8))
                {
                    ushort[] types = [.. group];
                    int count = (types[^1] & 0xff) / 8 + 1;
                    bytes.Add((byte)group.Key); bytes.Add((byte)count);
                    byte[] bitmap = new byte[count];
                    foreach (ushort type in types)
                    {
                        int index = type & 0xff;
                        bitmap[index / 8] |= (byte)(0x80 >> (index % 8));
                    }
                    bytes.AddRange(bitmap);
                    CheckSize(bytes);
                }
                break;
            case (_, UnknownData unknown): AppendBytes(bytes, unknown.Bytes); break;
            default: throw new ArgumentException("Record type and data do not match.", nameof(record));
        }
        int length = bytes.Count - start;
        if (length > ushort.MaxValue)
        {
            throw new ArgumentException("DNS RDATA is too long.", nameof(record));
        }

        bytes[lengthPosition] = (byte)(length >> 8);
        bytes[lengthPosition + 1] = (byte)length;
        CheckSize(bytes);
    }

    private static void PutName(List<byte> bytes, string name)
    {
        int length = 1;
        foreach (string label in DnsNames.Labels(name))
        {
            byte[] raw = s_utf8.GetBytes(label);
            if (raw.Length is < 1 or > 63)
            {
                throw new ArgumentException("Invalid DNS label length.", nameof(name));
            }

            length += raw.Length + 1;
            if (length > 255)
            {
                throw new ArgumentException("DNS name is too long.", nameof(name));
            }

            bytes.Add((byte)raw.Length); bytes.AddRange(raw);
        }
        bytes.Add(0);
        CheckSize(bytes);
    }

    private static ushort Read16(ReadOnlySpan<byte> bytes, ref int offset)
    {
        if (bytes.Length - offset < 2)
        {
            throw new ArgumentException("Truncated DNS field.");
        }

        ushort value = BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(offset, 2)); offset += 2; return value;
    }

    private static uint Read32(ReadOnlySpan<byte> bytes, ref int offset)
    {
        if (bytes.Length - offset < 4)
        {
            throw new ArgumentException("Truncated DNS field.");
        }

        uint value = BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(offset, 4)); offset += 4; return value;
    }

    private static void Put16(List<byte> bytes, ushort value) { bytes.Add((byte)(value >> 8)); bytes.Add((byte)value); }
    private static void AppendBytes(List<byte> bytes, byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length > MaxPacket - bytes.Count)
        {
            throw new ArgumentException("DNS packet exceeds 65535 bytes.");
        }

        bytes.AddRange(value);
    }
    private static void CheckSize(List<byte> bytes)
    {
        if (bytes.Count > MaxPacket)
        {
            throw new ArgumentException("DNS packet exceeds 65535 bytes.");
        }
    }
    private static void Put32(List<byte> bytes, uint value)
    {
        bytes.Add((byte)(value >> 24)); bytes.Add((byte)(value >> 16)); bytes.Add((byte)(value >> 8)); bytes.Add((byte)value);
    }
    private static void RequireEnd(int actual, int expected)
    {
        if (actual != expected)
        {
            throw new ArgumentException("Invalid DNS record length.");
        }
    }
}
