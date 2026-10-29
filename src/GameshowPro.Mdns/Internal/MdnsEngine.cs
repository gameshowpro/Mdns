namespace GameshowPro.Mdns.Internal;

internal sealed record MdnsScope(string? NetworkInterfaceId = null, IPAddress? LocalAddress = null);
internal sealed record MdnsPublication(string InstanceName, string ServiceType, string Protocol,
    ushort Port, IReadOnlyDictionary<string, string> TxtProperties);
internal sealed record MdnsPacket(DnsMessage Message, int InterfaceIndex, IPAddress Destination, IPAddress Source);

/// <summary>Record construction and query matching shared by every registration in this process.</summary>
internal static class MdnsEngine
{
    internal const uint SharedTtl = 4500;
    internal const uint UniqueTtl = 120;
    internal const string EnumerationName = "_services._dns-sd._udp.local.";

    internal static ImmutableArray<DnsRecord> CreateRecords(MdnsPublication publication, IReadOnlyCollection<IPAddress> addresses)
    {
        string service = DnsNames.Canonical($"{publication.ServiceType}._{publication.Protocol}.local");
        string instance = DnsNames.FromLabels(publication.InstanceName, publication.ServiceType,
            "_" + publication.Protocol, "local");
        // Retain the historical host identity expected by existing GameshowPro consumers.
        string host = DnsNames.FromLabels(publication.InstanceName,
            publication.ServiceType.TrimStart('_').Replace('_', '-'), "local");
        ImmutableArray<byte[]> txt = [.. publication.TxtProperties.Select(pair => Encoding.UTF8.GetBytes(
            string.Concat(pair.Key, "=", pair.Value)))];
        if (txt.IsEmpty)
        {
            txt = [[]];
        }

        ImmutableArray<DnsRecord>.Builder records = ImmutableArray.CreateBuilder<DnsRecord>();
        records.Add(new(EnumerationName, DnsTypes.Ptr, 1, SharedTtl, new NameData(service)));
        records.Add(new(service, DnsTypes.Ptr, 1, SharedTtl, new NameData(instance)));
        records.Add(new(instance, DnsTypes.Srv, 0x8001, UniqueTtl,
            new SrvData(0, 0, publication.Port, host)));
        records.Add(new(instance, DnsTypes.Txt, 0x8001, UniqueTtl, new TxtData(txt)));
        foreach (IPAddress address in addresses.Distinct())
        {
            records.Add(new(host, address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                ? DnsTypes.A : DnsTypes.Aaaa, 0x8001, UniqueTtl, new AddressData(address)));
        }

        return records.ToImmutable();
    }

    internal static ImmutableArray<DnsRecord> Query(DnsMessage query, IEnumerable<DnsRecord> catalogue,
        bool suppressKnownAnswers = true)
    {
        DnsRecord[] records = [.. catalogue.DistinctBy(r => (DnsNames.Canonical(r.Name).ToUpperInvariant(), r.Type,
            DataKey(r.Data)))];
        ImmutableArray<DnsRecord>.Builder answers = ImmutableArray.CreateBuilder<DnsRecord>();
        ImmutableArray<DnsRecord>.Builder additionals = ImmutableArray.CreateBuilder<DnsRecord>();
        foreach (DnsQuestion question in query.Questions)
        {
            if ((question.Class & 0x7fff) is not (1 or 255))
            {
                continue;
            }

            foreach (DnsRecord record in records)
            {
                if (!DnsNames.Equals(record.Name, question.Name) ||
                    question.Type != DnsTypes.Any && record.Type != question.Type)
                {
                    continue;
                }

                Add(record, answers);
                if (record.Data is NameData name && record.Type == DnsTypes.Ptr)
                {
                    foreach (DnsRecord related in records.Where(r => DnsNames.Equals(r.Name, name.Name)))
                    {
                        Add(related, additionals);
                        if (related.Data is SrvData srv)
                        {
                            foreach (DnsRecord address in records.Where(r => DnsNames.Equals(r.Name, srv.Target)))
                            {
                                Add(address, additionals);
                            }
                        }
                    }
                }
                else if (record.Data is SrvData srv)
                {
                    foreach (DnsRecord address in records.Where(r => DnsNames.Equals(r.Name, srv.Target)))
                    {
                        Add(address, additionals);
                    }
                }
            }
        }
        if (suppressKnownAnswers)
        {
            answers.RemoveAll(r => query.Answers.Any(k => k.Ttl >= r.Ttl / 2 && DnsRecords.Equivalent(k, r)));
            additionals.RemoveAll(r => query.Answers.Any(k => k.Ttl >= r.Ttl / 2 && DnsRecords.Equivalent(k, r)));
        }
        return [.. answers, .. additionals.Where(r => !answers.Any(a => DnsRecords.Equivalent(a, r)))];
    }

    internal static ImmutableArray<DnsRecord> Goodbye(IEnumerable<DnsRecord> oldRecords,
        IEnumerable<DnsRecord> retainedRecords)
    {
        DnsRecord[] retained = [.. retainedRecords];
        return [.. oldRecords.Where(r => !retained.Any(k => DnsRecords.Equivalent(r, k)))
            .Select(r => r with { Ttl = 0 })];
    }

    internal static bool HasConflict(DnsMessage response, IEnumerable<DnsRecord> owned)
    {
        DnsRecord[] ours = [.. owned.Where(r => r.CacheFlush)];
        return response.Answers.Concat(response.Authorities).Concat(response.Additionals)
            .Any(theirs => theirs.Ttl != 0 && theirs.BaseClass == 1 &&
                ours.Any(mine => mine.Type == theirs.Type && DnsNames.Equals(mine.Name, theirs.Name)) &&
                !ours.Any(mine => DnsRecords.Equivalent(mine, theirs)));
    }

    private static void Add(DnsRecord record, ImmutableArray<DnsRecord>.Builder builder)
    {
        if (!builder.Any(r => DnsRecords.Equivalent(r, record)))
        {
            builder.Add(record);
        }
    }

    private static string DataKey(DnsData data) => data switch
    {
        AddressData address => address.Address.ToString(),
        NameData name => DnsNames.Canonical(name.Name).ToUpperInvariant(),
        SrvData srv => $"{srv.Priority}|{srv.Weight}|{srv.Port}|{DnsNames.Canonical(srv.Target).ToUpperInvariant()}",
        TxtData txt => string.Join("|", txt.Strings.Select(Convert.ToHexString)),
        _ => data.ToString() ?? string.Empty
    };
}
