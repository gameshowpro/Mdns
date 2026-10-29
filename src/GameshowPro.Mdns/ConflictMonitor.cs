namespace GameshowPro.Mdns;

/// <summary>Advertises this service while discovering other instances of its type.</summary>
// Cancellation of the constructor token runs Launch's finally block and disposes the publisher.
#pragma warning disable CA1001
public class ConflictMonitor : ObservableClass
#pragma warning restore CA1001
{
    private static readonly Action<ILogger, Exception?> s_monitorStopped =
        LoggerMessage.Define(LogLevel.Error, new EventId(6103, nameof(Launch)),
            "mDNS conflict monitoring stopped unexpectedly");
    private readonly ILogger _logger;
    private readonly CancellationToken _cancellationToken;
    private readonly AdvertisedService _advertisedService;

    public ServiceFinder ServiceFinder { get; }
    public IMdnsMatchedServicesMonitor ConflictingServices { get; }

    public ConflictMonitor(IMdnsInstanceProperties instanceProperties,
        IEnumerable<IMdnsServiceSearchProfile> otherServices, ILogger logger,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(instanceProperties);
        ArgumentNullException.ThrowIfNull(otherServices);
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _cancellationToken = cancellationToken;
        _advertisedService = new(instanceProperties, logger);
        IMdnsServiceSearchProfile conflictProfile = new ServiceSearchProfile(
            instanceProperties.ServiceType, instanceProperties.Protocol, false);
        ServiceFinder = new(otherServices.Append(conflictProfile).Distinct(), Environment.MachineName, logger);
        ConflictingServices = ServiceFinder.Services[conflictProfile];
        Launch().FireAndForgetSafeAsync(ex => s_monitorStopped(_logger, ex));
    }

    protected override bool CompareEnumerablesByContent => true;

    internal async Task Launch()
    {
        using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(_cancellationToken);
        try
        {
            Task search = ServiceFinder.SearchUntilCancelled(linked.Token);
            Task advertise = _advertisedService.AdvertiseUntilCancelled(linked.Token);
            _ = await Task.WhenAny(search, advertise).ConfigureAwait(false);
            await linked.CancelAsync().ConfigureAwait(false);
            await Task.WhenAll(search, advertise).ConfigureAwait(false);
        }
        finally { await _advertisedService.DisposeAsync().ConfigureAwait(false); }
    }

}

public record MdnsMatchedService(IMdnsMatchedServicesMonitor Parent, string HostName,
    int Port, ImmutableArray<IPAddress> Addresses) : IMdnsMatchedService;
