#if WPF
using GameshowPro.Common.ViewModel;
#endif
namespace GameshowPro.Mdns;

public class MatchedServicesMonitor : ObservableClass, IMdnsMatchedServicesMonitor
{
    private record FoundHost(string HostName, int Port, ConcurrentDictionary<IPAddress, Stopwatch> Addresses);
    private record MessageRecords(SRVRecord? Srv, ImmutableArray<ARecord> A);
    public event Action<object, IMdnsMatchedService>? ServiceWasSelected;
    private static readonly string s_machineNamePrefix = TxtRecordMachineName + "=";
    private readonly ConcurrentDictionary<string, FoundHost> _foundHosts = [];
    private readonly ConcurrentDictionary<IPAddress, string> _foundAddresses = [];
    private readonly string? _ignoredMachineName;
    internal MatchedServicesMonitor(IMdnsServiceSearchProfile searchProfile, string thisMachineName)
    {
#if WPF
        MatchedServiceSelectedCommand = new(contextAndService => {
            if (contextAndService?.Length > 1 && contextAndService[1] is IMdnsMatchedService service)
            {
                ServiceWasSelected?.Invoke(contextAndService[0], service);
            }
        });
#endif
        SearchProfile = searchProfile;
        if (!searchProfile.AllowLocalhost)
        {
            _ignoredMachineName = thisMachineName;
        }
    }
    public IMdnsServiceSearchProfile SearchProfile { get; }
    internal static string GetKey(string serviceType, string protocol) => serviceType + "._" + protocol.ToLowerInvariant();
    internal static string GetKey(ServiceSearchProfile searchProfile) => GetKey(searchProfile.ServiceType, searchProfile.Protocol);

    private ImmutableArray<IMdnsMatchedService> _services = [];
    public ImmutableArray<IMdnsMatchedService> Services
    {
        get => _services;
        set => _ = SetProperty(ref _services, value);
    }

#if WPF
    public RelayCommand<object[]> MatchedServiceSelectedCommand { get; }
#endif

    internal void Discovered(ServiceInstanceDiscoveryEventArgs args)
    {
        MessageRecords records = MessageToRecords(args.Message);

        if (records.Srv != null  && (_ignoredMachineName == null || !records.Srv.Target.Labels[0].Equals(_ignoredMachineName, StringComparison.InvariantCultureIgnoreCase)) && records.A.Length > 0)
        {
            FoundHost foundHost = _foundHosts.GetOrAdd(records.Srv.CanonicalName, (a) => new FoundHost(LabelsToMdnsHostName(records.Srv.Target.Labels), records.Srv.Port, new ConcurrentDictionary<IPAddress, Stopwatch>()));
            foreach (ARecord a in records.A)
            {
                foundHost.Addresses.AddOrUpdate(a.Address, Stopwatch.StartNew(), (address, sw) => { sw.Restart(); return sw; });
                _foundAddresses.AddOrUpdate(a.Address, records.Srv.CanonicalName, (address, old) => records.Srv.CanonicalName);

            }
            UpdateConflictingServices();
        }
    }

    private static string LabelsToMdnsHostName(IReadOnlyList<string> labels)
    {
        switch (labels.Count)
        {
            case 0:
                return "";
            case 1:
                return labels[0];
            default:
                if (labels[labels.Count - 1] == "local")
                {
                    return labels[0] + ".local";
                }
                return labels[0];
        }
    }

    private static MessageRecords MessageToRecords(Makaretu.Dns.Message message)
    {
        SRVRecord? srv = (SRVRecord?)message.Answers.FirstOrDefault(r => r is SRVRecord) ?? 
                         (SRVRecord?)message.AdditionalRecords.FirstOrDefault(r => r is SRVRecord);
        
        ImmutableArray<ARecord> aRecords = [
            .. message.Answers.Where(r => r is ARecord).Select(r => (ARecord)r),
            .. message.AdditionalRecords.Where(r => r is ARecord).Select(r => (ARecord)r)
        ];
        
        return new MessageRecords(srv, aRecords);
    }

    internal void Shutdown(ServiceInstanceShutdownEventArgs args)
    {
        MessageRecords records = MessageToRecords(args.Message);
        foreach (ARecord a in records.A)
        {
            if (_foundAddresses.TryRemove(a.Address, out string? serviceInstanceName))
            {
                if (_foundHosts.TryRemove(serviceInstanceName, out _)) // Remove all records with this host name, because we might not get message for every individual address
                {
                    UpdateConflictingServices();
                }
            }
        }
            
    }

    internal void AnswerReceived(MessageEventArgs args)
    {
        MessageRecords records = MessageToRecords(args.Message);
        foreach (ARecord a in records.A)
        {
            if (_foundAddresses.TryGetValue(a.Address, out string? serviceInstanceName))
            {
                if (_foundHosts.TryGetValue(serviceInstanceName, out FoundHost? foundHost))
                {
                    foundHost.Addresses.AddOrUpdate(a.Address, Stopwatch.StartNew(), (address, sw) => { sw.Restart(); return sw; });
                }
            }
        }
    }

    internal void TrimExpiredServices()
    {
        bool change = false;
        try
        {
            foreach (KeyValuePair<string, FoundHost> foundHostPair in _foundHosts)
            {
                ImmutableArray<IPAddress> expiredAddresses = [.. foundHostPair.Value.Addresses.Where(a => a.Value.Elapsed > TimeSpan.FromSeconds(15)).Select(a => a.Key)];
                expiredAddresses.ForEach(expired =>
                {
                    foundHostPair.Value.Addresses.TryRemove(expired, out _);
                    _foundAddresses.TryRemove(expired, out _);
                });
                change = expiredAddresses.Length > 0;
            }
            ImmutableArray<string> expiredHosts = [.. _foundHosts.Where(ha => ha.Value.Addresses.IsEmpty).Select(ha => ha.Key)];
            expiredHosts.ForEach(expired =>
            {
                _foundHosts.TryRemove(expired, out _);
            });
            change = change || expiredHosts.Length > 0;
        }
        catch { }
        if (change)
        {
            UpdateConflictingServices();
        }
    }

    void UpdateConflictingServices()
    {
        Services = [.. _foundHosts
                .OrderBy(ha => ha.Key)
                .Select(ha => new MdnsMatchedService(this, ha.Value.HostName, ha.Value.Port, [.. ha.Value.Addresses.Select((a, s) => a.Key)]))
        ];
    }

    static string? GetMachineNameFromRecords(List<ResourceRecord> records)
        => records.SelectMany(a => a is TXTRecord txt ? txt.Strings : []).Where(s => s.StartsWith(s_machineNamePrefix)).FirstOrDefault()?[s_machineNamePrefix.Length..];
}
