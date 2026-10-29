namespace GameshowPro.Mdns;

/// <summary>Discovers requested DNS-SD services and maintains their current addresses.</summary>
public class ServiceFinder : IMdnsServiceFinder
{
    private static readonly Action<ILogger, Exception?> s_responseFailed =
        LoggerMessage.Define(LogLevel.Warning, new EventId(6101, nameof(Receive)),
            "Could not process an mDNS response");
    private static readonly Action<ILogger, Exception?> s_searchStopped =
        LoggerMessage.Define(LogLevel.Error, new EventId(6102, nameof(SearchUntilCancelled)),
            "mDNS discovery stopped unexpectedly");
    private readonly ILogger _logger;
    public IReadOnlyDictionary<IMdnsServiceSearchProfile, IMdnsMatchedServicesMonitor> Services { get; }
    internal FrozenDictionary<string, ImmutableArray<MatchedServicesMonitor>> ServicesByName { get; }

    public ServiceFinder(IEnumerable<IMdnsServiceSearchProfile> searchProfiles, ILogger logger,
        CancellationToken cancellationToken)
        : this(searchProfiles, Environment.MachineName, logger)
    {
        SearchUntilCancelled(cancellationToken).FireAndForgetSafeAsync(
            ex => s_searchStopped(_logger, ex));
    }

    internal ServiceFinder(IEnumerable<IMdnsServiceSearchProfile> searchProfiles,
        string thisMachineName, ILogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        ArgumentNullException.ThrowIfNull(searchProfiles);
        FrozenDictionary<IMdnsServiceSearchProfile, IMdnsMatchedServicesMonitor> services = searchProfiles.ToFrozenDictionary(profile => profile,
            profile => (IMdnsMatchedServicesMonitor)new MatchedServicesMonitor(profile, thisMachineName));
        Services = services;
        ServicesByName = services.Values.Cast<MatchedServicesMonitor>()
            .GroupBy(m => MatchedServicesMonitor.GetKey(m.SearchProfile.ServiceType,
                m.SearchProfile.Protocol), StringComparer.OrdinalIgnoreCase)
            .ToFrozenDictionary(g => g.Key, g => g.ToImmutableArray(),
                StringComparer.OrdinalIgnoreCase);
    }

    internal async Task SearchUntilCancelled(CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return;
        }

        await using MdnsBrowseSubscription subscription = await MdnsRuntime.BrowseAsync(
            ServicesByName.Keys.Select(k => k + ".local."), Receive, _logger,
            cancellationToken).ConfigureAwait(false);
        if (subscription.Failure is { } failure)
        {
            throw new InvalidOperationException(failure);
        }

        using PeriodicTimer timer = new(TimeSpan.FromSeconds(1));
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                if (subscription.Failure is { } runtimeFailure)
                {
                    throw new InvalidOperationException(runtimeFailure);
                }

                foreach (MatchedServicesMonitor monitor in ServicesByName.Values.SelectMany(m => m))
                {
                    monitor.TrimExpiredServices();
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
    }

    private void Receive(MdnsPacket packet)
    {
        try
        {
            foreach (MatchedServicesMonitor monitor in ServicesByName.Values.SelectMany(m => m))
            {
                monitor.Receive(packet);
            }
        }
        catch (Exception ex) { s_responseFailed(_logger, ex); }
    }

}
