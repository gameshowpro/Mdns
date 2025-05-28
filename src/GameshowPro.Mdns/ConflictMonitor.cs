namespace GameshowPro.Mdns;

/// <summary>
/// Allows applications to both advertise themselves as services and discover conflicting services elsewhere.
/// This is useful in the case of an application which must be singletons on a network, such as control application.
/// </summary>
public class ConflictMonitor : ObservableClass
{
    
    private readonly ILogger _logger;
    private readonly CancellationToken _cancellationToken;
    private readonly IMdnsInstanceProperties _instanceProperties;
    private readonly AdvertisedService _advertisedService;
    public ServiceFinder ServiceFinder { get; }
    public IMdnsMatchedServicesMonitor ConflictingServices { get; }

    public ConflictMonitor(IMdnsInstanceProperties instanceProperties, IEnumerable<IMdnsServiceSearchProfile> otherServices, ILogger logger, CancellationToken cancellationToken)
    {
        string thisMachineName = Environment.MachineName;
        _advertisedService = new(instanceProperties, thisMachineName, logger);
        IMdnsServiceSearchProfile serviceSearchProfile = new ServiceSearchProfile(instanceProperties.ServiceType, instanceProperties.Protocol, false);
        ServiceFinder = new(otherServices.Union(serviceSearchProfile), thisMachineName, logger);
        ConflictingServices = ServiceFinder.Services[serviceSearchProfile];
        _instanceProperties = instanceProperties;
        _logger = logger;
        _cancellationToken = cancellationToken;
        Task.Run(Launch, _cancellationToken);
    }

    protected override bool CompareEnumerablesByContent => true;

    internal async Task Launch()
    {
        ServiceDiscovery serviceDiscovery = new();
        await Task.WhenAll(ServiceFinder.SearchUntilCancelled(serviceDiscovery, _cancellationToken), _advertisedService.AdvertiseUntilCancelled(serviceDiscovery, _cancellationToken));
        serviceDiscovery.Dispose();
    }
}

public record MdnsMatchedService(IMdnsMatchedServicesMonitor Parent, string HostName, int Port, ImmutableArray<IPAddress> Addresses) : IMdnsMatchedService;   
