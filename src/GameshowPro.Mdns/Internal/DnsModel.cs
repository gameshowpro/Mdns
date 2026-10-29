namespace GameshowPro.Mdns.Internal;

internal static class DnsTypes
{
    public const ushort A = 1, Ptr = 12, Txt = 16, Aaaa = 28, Srv = 33, Nsec = 47, Any = 255;
}

internal static class DnsNames
{
    public static string Canonical(string name) => FromLabels([.. Labels(name)]);

    public static string FromLabels(params string[] labels)
    {
        ArgumentNullException.ThrowIfNull(labels);
        if (labels.Length == 0)
        {
            return ".";
        }

        return string.Join('.', labels.Select(EscapeLabel)) + ".";

        string EscapeLabel(string label)
        {
            ArgumentNullException.ThrowIfNull(label);
            if (label.Length == 0)
            {
                throw new ArgumentException("DNS labels cannot be empty.", nameof(labels));
            }

            return label.Replace("\\", "\\\\", StringComparison.Ordinal)
                .Replace(".", "\\.", StringComparison.Ordinal);
        }
    }

    public static IReadOnlyList<string> Labels(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (name == ".")
        {
            return [];
        }

        if (name.Length == 0)
        {
            throw new ArgumentException("DNS name cannot be empty.", nameof(name));
        }

        List<string> labels = [];
        System.Text.StringBuilder label = new();
        for (int i = 0; i < name.Length; i++)
        {
            char ch = name[i];
            if (ch == '\\')
            {
                if (++i == name.Length)
                {
                    throw new ArgumentException("Incomplete DNS escape.", nameof(name));
                }

                _ = label.Append(name[i]);
            }
            else if (ch == '.')
            {
                if (label.Length == 0)
                {
                    throw new ArgumentException("DNS labels cannot be empty.", nameof(name));
                }

                labels.Add(label.ToString());
                _ = label.Clear();
                if (i != name.Length - 1 && name[i + 1] == '.')
                {
                    throw new ArgumentException("DNS labels cannot be empty.", nameof(name));
                }
            }
            else
            {
                _ = label.Append(ch);
            }
        }
        if (label.Length > 0)
        {
            labels.Add(label.ToString());
        }

        return labels;
    }

    public static bool Equals(string? left, string? right)
    {
        if (left is null || right is null)
        {
            return left is null && right is null;
        }

        IReadOnlyList<string> a = Labels(left);
        IReadOnlyList<string> b = Labels(right);
        if (a.Count != b.Count)
        {
            return false;
        }

        for (int i = 0; i < a.Count; i++)
        {
            if (a[i].Length != b[i].Length)
            {
                return false;
            }

            for (int j = 0; j < a[i].Length; j++)
            {
                char ac = a[i][j];
                char bc = b[i][j];
                if (ac is >= 'A' and <= 'Z')
                {
                    ac = (char)(ac + 32);
                }

                if (bc is >= 'A' and <= 'Z')
                {
                    bc = (char)(bc + 32);
                }

                if (ac != bc)
                {
                    return false;
                }
            }
        }
        return true;
    }
}

internal sealed record DnsQuestion(string Name, ushort Type, ushort Class = 1);

internal abstract record DnsData;
internal sealed record AddressData(IPAddress Address) : DnsData;
internal sealed record NameData(string Name) : DnsData;
internal sealed record SrvData(ushort Priority, ushort Weight, ushort Port, string Target) : DnsData;
internal sealed record TxtData(ImmutableArray<byte[]> Strings) : DnsData;
internal sealed record NsecData(string NextName, ImmutableArray<ushort> Types) : DnsData;
internal sealed record UnknownData(byte[] Bytes) : DnsData;

internal sealed record DnsRecord(string Name, ushort Type, ushort Class, uint Ttl, DnsData Data)
{
    public ushort BaseClass => (ushort)(Class & 0x7fff);
    public bool CacheFlush => (Class & 0x8000) != 0;
}

internal static class DnsRecords
{
    public static bool Equivalent(DnsRecord a, DnsRecord b)
    {
        if (!DnsNames.Equals(a.Name, b.Name) || a.Type != b.Type || a.BaseClass != b.BaseClass)
        {
            return false;
        }

        return (a.Data, b.Data) switch
        {
            (AddressData x, AddressData y) => x.Address.AddressFamily == y.Address.AddressFamily &&
                x.Address.GetAddressBytes().AsSpan().SequenceEqual(y.Address.GetAddressBytes()),
            (NameData x, NameData y) => DnsNames.Equals(x.Name, y.Name),
            (SrvData x, SrvData y) => x.Priority == y.Priority && x.Weight == y.Weight &&
                x.Port == y.Port && DnsNames.Equals(x.Target, y.Target),
            (TxtData x, TxtData y) => x.Strings.Length == y.Strings.Length &&
                x.Strings.Zip(y.Strings).All(pair => pair.First.AsSpan().SequenceEqual(pair.Second)),
            (NsecData x, NsecData y) => DnsNames.Equals(x.NextName, y.NextName) &&
                x.Types.Order().SequenceEqual(y.Types.Order()),
            (UnknownData x, UnknownData y) => x.Bytes.AsSpan().SequenceEqual(y.Bytes),
            _ => false
        };
    }
}

internal sealed record DnsMessage
{
    public ushort Id { get; init; }
    public ushort Flags { get; init; }
    public ImmutableArray<DnsQuestion> Questions { get; init; } = [];
    public ImmutableArray<DnsRecord> Answers { get; init; } = [];
    public ImmutableArray<DnsRecord> Authorities { get; init; } = [];
    public ImmutableArray<DnsRecord> Additionals { get; init; } = [];
    public bool IsResponse => (Flags & 0x8000) != 0;
}
