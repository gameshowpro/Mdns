using GameshowPro.Common.ViewModel;

namespace GameshowPro.Mdns;

public class MatchedServicesMonitor : ObservableClass, IMdnsMatchedServicesMonitor
{
    public event Action<object, IMdnsMatchedService>? ServiceWasSelected;
    private static readonly string s_machineNamePrefix = TxtRecordMachineName + "=";
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<IPEndPoint, Stopwatch>> _foundHosts = [];
    private readonly ConcurrentDictionary<IPEndPoint, string> _foundAddresses = [];
    private readonly string? _ignoredMachineName;
    internal MatchedServicesMonitor(IMdnsServiceSearchProfile searchProfile, string thisMachineName)
    {
        MatchedServiceSelectedCommand = new(contextAndService => {
            if (contextAndService?.Length > 1 && contextAndService[1] is IMdnsMatchedService service)
            {
                ServiceWasSelected?.Invoke(contextAndService[0], service);
            }
        });
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

    public RelayCommand<object[]> MatchedServiceSelectedCommand { get; }

    internal void Discovered(ServiceInstanceDiscoveryEventArgs args)
    {
        string? machineName = GetMachineNameFromTxt(args.Message);

        if (machineName != null && (_ignoredMachineName == null || machineName != _ignoredMachineName))
        {
            ConcurrentDictionary<IPEndPoint, Stopwatch> addresses = _foundHosts.GetOrAdd(machineName, (a) => new ConcurrentDictionary<IPEndPoint, Stopwatch>());
            addresses.AddOrUpdate(args.RemoteEndPoint, Stopwatch.StartNew(), (address, sw) => { sw.Restart(); return sw; });
            _foundAddresses.AddOrUpdate(args.RemoteEndPoint, machineName, (address, old) => machineName);
            UpdateConflictingServices();
        }
    }

    internal void Shutdown(ServiceInstanceShutdownEventArgs args)
    {
        if (_foundAddresses.TryRemove(args.RemoteEndPoint, out string? machineName))
        {
            if (_foundHosts.TryRemove(machineName, out _)) // Remove all records with this host name, because we might not get message for every individual address
            {
                UpdateConflictingServices();
            }
        }
    }

    internal void AnswerReceived(MessageEventArgs args)
    {
        if (_foundAddresses.TryGetValue(args.RemoteEndPoint, out string? machineName))
        {
            if (_foundHosts.TryGetValue(machineName, out ConcurrentDictionary<IPEndPoint, Stopwatch>? addresses))
            {
                addresses.AddOrUpdate(args.RemoteEndPoint, Stopwatch.StartNew(), (address, sw) => { sw.Restart(); return sw; });
            }
        }
    }

    internal void TrimExpiredServices()
    {
        bool change = false;
        try
        {
            foreach (KeyValuePair<string, ConcurrentDictionary<IPEndPoint, Stopwatch>> ha in _foundHosts)
            {
                ImmutableArray<IPEndPoint> expiredAddresses = [.. ha.Value.Where(a => a.Value.Elapsed > TimeSpan.FromSeconds(15)).Select(a => a.Key)];
                expiredAddresses.ForEach(expired =>
                {
                    ha.Value.TryRemove(expired, out _);
                    _foundAddresses.TryRemove(expired, out _);
                });
                change = expiredAddresses.Length > 0;
            }
            ImmutableArray<string> expiredHosts = [.. _foundHosts.Where(ha => ha.Value.IsEmpty).Select(ha => ha.Key)];
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
                .Select(ha => new MdnsMatchedService(this, ha.Key, [.. ha.Value.Select((a, s) => a.Key)]))
        ];
    }

    static string? GetMachineNameFromTxt(Message message)
        => GetMachineNameFromRecords(message.Answers) ?? GetMachineNameFromRecords(message.AdditionalRecords);

    static string? GetMachineNameFromRecords(List<ResourceRecord> records)
        => records.SelectMany(a => a is TXTRecord txt ? txt.Strings : []).Where(s => s.StartsWith(s_machineNamePrefix)).FirstOrDefault()?[s_machineNamePrefix.Length..];
}
