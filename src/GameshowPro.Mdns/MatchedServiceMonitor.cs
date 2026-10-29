namespace GameshowPro.Mdns;

public class MatchedServicesMonitor : ObservableClass, IMdnsMatchedServicesMonitor
{
    private sealed record CachedRecord(int InterfaceIndex, DnsRecord Record,
        DateTimeOffset Received, DateTimeOffset Expires);
    // TTL refresh and goodbye processing update entries in place under _sync.
    private readonly List<CachedRecord> _records = [];
    private readonly object _sync = new();
    private readonly TimeProvider _clock;
    private readonly string? _ignoredMachineName;
    private ImmutableArray<IMdnsMatchedService> _services = [];

    internal MatchedServicesMonitor(IMdnsServiceSearchProfile profile, string thisMachineName,
        TimeProvider? clock = null)
    {
        SearchProfile = profile;
        _clock = clock ?? TimeProvider.System;
        if (!profile.AllowLocalhost)
        {
            _ignoredMachineName = thisMachineName;
        }
#if WPF
        MatchedServiceSelectedCommand = new(Select);

        void Select(object[]? contextAndService)
        {
            if (contextAndService?.Length > 1 && contextAndService[1] is IMdnsMatchedService service)
            {
                ServiceWasSelected?.Invoke(contextAndService[0], service);
            }
        }
#endif
    }

    // Non-WPF builds retain the interface event; only the WPF command raises it.
#pragma warning disable CS0067
    public event Action<object, IMdnsMatchedService>? ServiceWasSelected;
#pragma warning restore CS0067
    public IMdnsServiceSearchProfile SearchProfile { get; }
    public ImmutableArray<IMdnsMatchedService> Services
    {
        get => _services;
        set => _ = SetProperty(ref _services, value);
    }
#if WPF
    public RelayCommand<object[]> MatchedServiceSelectedCommand { get; }
#endif

    internal static string GetKey(string serviceType, string protocol) =>
        serviceType + "._" + protocol.ToLowerInvariant();

    internal void Receive(MdnsPacket packet)
    {
        lock (_sync)
        {
            DateTimeOffset now = _clock.GetUtcNow();
            _ = _records.RemoveAll(entry => entry.Expires <= now);
            DnsRecord[] incoming = [.. packet.Message.Answers, .. packet.Message.Authorities,
                .. packet.Message.Additionals];
            incoming = [.. incoming.Where(r => r.BaseClass == 1 &&
                r.Type is DnsTypes.Ptr or DnsTypes.Srv or DnsTypes.Txt or DnsTypes.A or DnsTypes.Aaaa)];
            // A cache-flush packet can contain several addresses for the same host.
            foreach (IGrouping<(string Name, ushort Type, ushort BaseClass), DnsRecord> group in incoming.Where(r => r.CacheFlush && r.Ttl > 0)
                         .GroupBy(r => (Name: DnsNames.Canonical(r.Name).ToUpperInvariant(), r.Type, r.BaseClass)))
            {
                for (int i = 0; i < _records.Count; i++)
                {
                    CachedRecord old = _records[i];
                    if (old.InterfaceIndex == packet.InterfaceIndex &&
                        old.Record.Type == group.Key.Type && old.Record.BaseClass == group.Key.BaseClass &&
                        DnsNames.Equals(old.Record.Name, group.Key.Name) &&
                        !group.Any(record => DnsRecords.Equivalent(old.Record, record)) &&
                        now - old.Received >= TimeSpan.FromSeconds(1))
                    {
                        _records[i] = old with { Expires = now.AddSeconds(1) };
                    }
                }
            }

            foreach (DnsRecord record in incoming)
            {
                if (record.Ttl == 0)
                {
                    for (int i = 0; i < _records.Count; i++)
                    {
                        CachedRecord old = _records[i];
                        if (old.InterfaceIndex == packet.InterfaceIndex &&
                            DnsRecords.Equivalent(old.Record, record))
                        {
                            _records[i] = old with { Expires =
                                Min(old.Expires, now.AddSeconds(1)) };
                        }
                    }
                    continue;
                }
                _ = _records.RemoveAll(e => e.InterfaceIndex == packet.InterfaceIndex &&
                    DnsRecords.Equivalent(e.Record, record));
                _records.Add(new(packet.InterfaceIndex, record, now,
                    now.AddSeconds(Math.Min(record.Ttl, 86400u))));
            }
            if (_records.Count > 4096)
            {
                _records.RemoveRange(0, _records.Count - 4096);
            }

            Rebuild();
        }
    }

    private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b) => a <= b ? a : b;

    internal void TrimExpiredServices()
    {
        lock (_sync)
        {
            if (_records.RemoveAll(e => e.Expires <= _clock.GetUtcNow()) > 0)
            {
                Rebuild();
            }
        }
    }

    private void Rebuild()
    {
        string serviceName = DnsNames.Canonical(GetKey(SearchProfile.ServiceType,
            SearchProfile.Protocol) + ".local");
        Dictionary<string, (string HostName, int Port, HashSet<IPAddress> Addresses)> matches = new(
            StringComparer.OrdinalIgnoreCase);
        foreach (IGrouping<int, CachedRecord> interfaceRecords in _records.GroupBy(e => e.InterfaceIndex))
        {
            DnsRecord[] records = [.. interfaceRecords.Select(e => e.Record)];
            foreach (DnsRecord ptr in records.Where(r => r.Type == DnsTypes.Ptr &&
                         DnsNames.Equals(r.Name, serviceName) && r.Data is NameData))
            {
                string instance = ((NameData)ptr.Data).Name;
                DnsRecord? srvRecord = records.LastOrDefault(r => r.Type == DnsTypes.Srv &&
                    DnsNames.Equals(r.Name, instance) && r.Data is SrvData);
                if (srvRecord?.Data is not SrvData srv)
                {
                    continue;
                }

                DnsRecord? txtRecord = records.LastOrDefault(r => r.Type == DnsTypes.Txt &&
                    DnsNames.Equals(r.Name, instance) && r.Data is TxtData);
                string? machineName = txtRecord?.Data is TxtData txt ? MachineName(txt) : null;
                IReadOnlyList<string> hostLabels = DnsNames.Labels(srv.Target);
                if (_ignoredMachineName is not null &&
                    string.Equals(machineName ?? (hostLabels.Count > 0 ? hostLabels[0] : null), _ignoredMachineName,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                ImmutableArray<IPAddress> addresses = [.. records.Where(r =>
                        (r.Type == DnsTypes.A || r.Type == DnsTypes.Aaaa) &&
                        DnsNames.Equals(r.Name, srv.Target) && r.Data is AddressData)
                    .Select(r => ScopeAddress(((AddressData)r.Data).Address,
                        interfaceRecords.Key)).Distinct()];
                if (addresses.Length == 0)
                {
                    continue;
                }

                string key = DnsNames.Canonical(instance) + "|" + srv.Port;
                if (!matches.TryGetValue(key, out (string HostName, int Port, HashSet<IPAddress> Addresses) match))
                {
                    match = (DisplayHost(srv.Target, machineName), srv.Port, []);
                    matches.Add(key, match);
                }
                foreach (IPAddress address in addresses)
                {
                    _ = match.Addresses.Add(address);
                }
            }
        }
        Services = [.. matches.Values.OrderBy(m => m.HostName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(m => m.Port).Select(m => (IMdnsMatchedService)new MdnsMatchedService(this,
                m.HostName, m.Port, [.. m.Addresses]))];
    }

    private static IPAddress ScopeAddress(IPAddress address, int interfaceIndex) =>
        address.IsIPv6LinkLocal && address.ScopeId == 0 && interfaceIndex > 0
            ? new IPAddress(address.GetAddressBytes(), interfaceIndex) : address;

    private static string? MachineName(TxtData txt)
    {
        foreach (byte[] raw in txt.Strings)
        {
            string value = Encoding.UTF8.GetString(raw);
            const string Prefix = "machineName=";
            if (value.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
            {
                return value[Prefix.Length..];
            }
        }
        return null;
    }

    private static string DisplayHost(string target, string? machineName)
    {
        IReadOnlyList<string> labels = DnsNames.Labels(target);
        if (labels.Count == 0)
        {
            return target;
        }

        if (machineName is not null &&
            labels[0].Equals(machineName, StringComparison.OrdinalIgnoreCase))
        {
            return machineName + ".local";
        }

        if (machineName is null && labels.Count > 1 &&
            labels[^1].Equals("local", StringComparison.OrdinalIgnoreCase))
        {
            return labels[0] + ".local";
        }

        if (labels.Count == 2 && labels[1].Equals("local", StringComparison.OrdinalIgnoreCase))
        {
            return labels[0] + ".local";
        }

        return target.TrimEnd('.');
    }
}
