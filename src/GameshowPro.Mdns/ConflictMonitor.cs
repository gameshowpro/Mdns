using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using Makaretu.Dns;
using GameshowPro.Common.Model;
using System.Collections.Immutable;
using GameshowPro.Common;

namespace GameshowPro.Mdns;

public class ConflictMonitor : ObservableClass, IMdnsConflictMonitor
{
    private const string TxtRecordMachineName = "machineName";
    private readonly ILogger _logger;
    private readonly CancellationToken _cancellationToken;
    private readonly string _instanceName;
    private readonly string _serviceType;
    private readonly string _protocol;
    private readonly ushort _port;
    public ConflictMonitor(string instanceName, string serviceType, string protocol, ushort port, ILogger logger, CancellationToken cancellationToken)
    {
        _instanceName = instanceName;
        _serviceType = serviceType;
        _protocol = protocol;
        _port = port;
        _logger = logger;
        _cancellationToken = cancellationToken;
        Task.Run(Launch, _cancellationToken);
    }

    protected override bool CompareEnumerablesByContent => true;

    internal async Task Launch()
    {
        string thisMachineName = Environment.MachineName;
        string machineNamePrefix = TxtRecordMachineName + "=";
        ConcurrentDictionary<string, ConcurrentDictionary<IPAddress, Stopwatch>> conflictingHosts = [];
        ConcurrentDictionary<IPAddress, string> conflictingAddresses = [];
        ImmutableHashSet<string> localDnsHostNames = GetLocalDnsHostNames();
        ServiceProfile profile = new(_instanceName, _serviceType + "._" + _protocol, _port);
        profile.AddProperty(TxtRecordMachineName, thisMachineName);
        ServiceDiscovery discovery = new();

        discovery.ServiceInstanceDiscovered += (s, e) =>
        {
            if (e.ServiceInstanceName.Labels.ElementAtOrDefault(1) == _serviceType)
            {
                //Beware - this is often fired on many simultaneous threads
                _logger.LogTrace("ServiceInstanceDiscovered at {address}: {name}", e.RemoteEndPoint.Address, e.ServiceInstanceName.ToCanonical());
                
                string? machineName = GetMachineNameFromTxt(e.Message);

                if (machineName != null && machineName != thisMachineName)
                {
                    ConcurrentDictionary<IPAddress, Stopwatch> addresses = conflictingHosts.GetOrAdd(machineName, (a) => new ConcurrentDictionary<IPAddress, Stopwatch>());
                    addresses.AddOrUpdate(e.RemoteEndPoint.Address, Stopwatch.StartNew(), (address, sw) => { sw.Restart(); return sw; });
                    conflictingAddresses.AddOrUpdate(e.RemoteEndPoint.Address, machineName, (address, old) => machineName);
                };
                UpdateConflictingServices();
            }
        };
        discovery.ServiceInstanceShutdown += (s, e) =>
        {
            if (e.ServiceInstanceName.Labels.ElementAtOrDefault(1) == _serviceType)
            {
                _logger.LogTrace("ServiceInstanceShutdown at {address}: {name}", e.RemoteEndPoint.Address, e.ServiceInstanceName.ToCanonical());
                if (conflictingAddresses.TryRemove(e.RemoteEndPoint.Address, out string? machineName))
                {
                    if (conflictingHosts.TryRemove(machineName, out _)) // Remove all records with this host name, because we might not get message for every individual address
                    {
                        UpdateConflictingServices();
                    }
                }
            }
        };
        discovery.Mdns.AnswerReceived += (s, e) =>
        {
            if (GetServiceType(e.Message) == _serviceType)
            {
                if (conflictingAddresses.TryGetValue(e.RemoteEndPoint.Address, out string? machineName))
                {
                    if (conflictingHosts.TryGetValue(machineName, out ConcurrentDictionary<IPAddress, Stopwatch>? addresses))
                    {
                        addresses.AddOrUpdate(e.RemoteEndPoint.Address, Stopwatch.StartNew(), (address, sw) => { sw.Restart(); return sw; });
                    }
                }
            }
        };

        discovery.Advertise(profile);
        discovery.Announce(profile);
        _logger.LogInformation($"Advertising and announcing mdns service type {_serviceType}");
        
        while (!_cancellationToken.IsCancellationRequested)
        {
            discovery.QueryServiceInstances(profile.ServiceName);
            bool change = false;
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(10), _cancellationToken);
                foreach (KeyValuePair<string, ConcurrentDictionary<IPAddress, Stopwatch>> ha in conflictingHosts)
                {
                    ImmutableArray<IPAddress> expiredAddresses = [.. ha.Value.Where(a => a.Value.Elapsed > TimeSpan.FromSeconds(15)).Select(a => a.Key)];
                    expiredAddresses.ForEach(expired =>
                    {
                        ha.Value.TryRemove(expired, out _);
                        conflictingAddresses.TryRemove(expired, out _);
                    });
                    change = expiredAddresses.Length > 0;
                }
                ImmutableArray<string> expiredHosts = [.. conflictingHosts.Where(ha => ha.Value.IsEmpty).Select(ha => ha.Key)];
                expiredHosts.ForEach(expired =>
                {
                    conflictingHosts.TryRemove(expired, out _);
                });
                change = change || expiredHosts.Length > 0;
            }
            catch { }
            if (change)
            {
                UpdateConflictingServices();
            }
        }
        discovery.Unadvertise(profile);
        discovery.Dispose();

        string? GetServiceType(Message message)
            => message.Answers.Select(a => a.CanonicalName.Split('.').ElementAtOrDefault(1)).FirstOrDefault(n => n != null);

        string? GetMachineNameFromTxt(Message message)
            => message.Answers.SelectMany(a => a is TXTRecord txt ? txt.Strings : []).Where(s => s.StartsWith(machineNamePrefix)).FirstOrDefault()?[machineNamePrefix.Length..];

        void UpdateConflictingServices()
        {
            ConflictingServices = [.. conflictingHosts
                .OrderBy(ha => ha.Key)
                .Select(ha => new MdnsConflictingService(ha.Key, [.. ha.Value.Select((a, s) => a.Key)]))
            ];
        }

        static ImmutableHashSet<string> GetLocalDnsHostNames()
        {
            ImmutableHashSet<string>.Builder hostNames = ImmutableHashSet.CreateBuilder<string>();
            IPHostEntry hostEntries = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var address in hostEntries.AddressList)
            {
                _ = hostNames.Add(Dns.GetHostEntry(address).HostName.ToLower());
            }
            return hostNames.ToImmutable();
        }
    }

    private ImmutableArray<IMdnsConflictingService> _conflictingServices = [];
    public ImmutableArray<IMdnsConflictingService> ConflictingServices
    {
        get => _conflictingServices;
        private set {
            if (SetProperty(ref _conflictingServices, value))
            {
                if (value.Length > 0)
                {
                    _logger.LogWarning("Conflicting services detected: {services}", value.Select(s => s.HostName));
                }
                else
                {
                    _logger.LogInformation("Conflicting services no longer detected");
                }
            }
        }
    }
}

public record MdnsConflictingService(string HostName, ImmutableArray<IPAddress> Addresses) : IMdnsConflictingService;