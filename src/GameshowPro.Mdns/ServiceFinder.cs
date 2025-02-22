namespace GameshowPro.Mdns;

/// <summary>
/// Allows clients to specify a service they require and receive a list of available options.
/// </summary>
public class ServiceFinder : IMdnsServiceFinder
{
    private readonly ILogger _logger;
    /// <summary>
    /// Create a new service finder and begin searching for specified service types immediately.
    /// </summary>
    /// <param name="searchProfiles"></param>
    /// <param name="logger"></param>
    /// <param name="cancellationToken"></param>
    public ServiceFinder(IEnumerable<IMdnsServiceSearchProfile> searchProfiles, ILogger logger, CancellationToken cancellationToken) : this(searchProfiles, Environment.MachineName, logger)
    {

        Task.Run(() => SearchUntilCancelled(cancellationToken), cancellationToken);
    }

    /// <summary>
    /// Common overload used both internally and externally. Doesn't start the search.
    /// </summary>
    /// <param name="searchProfiles"></param>
    /// <param name="logger"></param>
    internal ServiceFinder(IEnumerable<IMdnsServiceSearchProfile> searchProfiles, string thisMachineName, ILogger logger)
    {
        _logger = logger;
        Services = searchProfiles.ToFrozenDictionary(t => t, t => (IMdnsMatchedServicesMonitor)new MatchedServicesMonitor(t, thisMachineName));
        ServicesByName = Services.ToFrozenDictionary(kvp => MatchedServicesMonitor.GetKey((ServiceSearchProfile)kvp.Key), kvp => (MatchedServicesMonitor)kvp.Value);
    }
    /// <summary>
    /// Used only when this class is publicly instantiated, so this class is managing the discovery lifecycle.
    /// </summary>
    private async Task SearchUntilCancelled(CancellationToken cancellationToken)
    {
        ServiceDiscovery discovery = new();
        await SearchUntilCancelled(discovery, cancellationToken);
        discovery.Dispose();
    }

    /// <summary>
    /// Common overload used both internally and externally. ServiceDiscovery is passed in so that the caller can manage the lifecycle.
    /// </summary>
    internal async Task SearchUntilCancelled(IServiceDiscovery serviceDiscovery, CancellationToken cancellationToken)
    {
        serviceDiscovery.ServiceInstanceDiscovered += (s, e) =>
        {
            if (TryGetServices(LabelsToKey(e.ServiceInstanceName.Labels), out MatchedServicesMonitor? services))
            {
                //Beware - this is often fired on many simultaneous threads
                _logger.LogTrace("ServiceInstanceDiscovered at {address}: {name}", e.RemoteEndPoint.Address, e.ServiceInstanceName.ToCanonical());

                services.Discovered(e);
            }
        };
        serviceDiscovery.ServiceInstanceShutdown += (s, e) =>
        {
            if (TryGetServices(LabelsToKey(e.ServiceInstanceName.Labels), out MatchedServicesMonitor? services))
            {
                _logger.LogTrace("ServiceInstanceShutdown at endpoint {endpoint}: {name}", e.RemoteEndPoint, e.ServiceInstanceName.ToCanonical());
                services.Shutdown(e);
            }
        };
        serviceDiscovery.Mdns.AnswerReceived += (s, e) =>
        {
            if (TryGetServices(GetServiceType(e.Message), out MatchedServicesMonitor? services))
            {
                services.AnswerReceived(e);
            }
        };

        while (!cancellationToken.IsCancellationRequested)
        {
            foreach (string serviceTypeAndProtocol in ServicesByName.Keys)
            {
                serviceDiscovery.QueryServiceInstances(serviceTypeAndProtocol);
            }
            ;
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken);
                foreach (MatchedServicesMonitor services in ServicesByName.Values)
                {
                    services.TrimExpiredServices();
                }
            }
            catch
            {
            }
        }
        
        bool TryGetServices(string? serviceTypeAndProtocol, [NotNullWhen(true)] out MatchedServicesMonitor? services)
        {
            if (serviceTypeAndProtocol == null)
            {
                services = null;
                return false;
            }
            return ServicesByName.TryGetValue(serviceTypeAndProtocol, out services);
        }

        string? LabelsToKey(IReadOnlyList<string>? labels)
        {
            if (labels?.Count >= 3)
            {
                return $"{labels[1]}.{labels[2]}";
            }
            return null;
        }

        string ? GetServiceType(Message message)
        {
            string[]? parts = message.Answers.Select(a => a.CanonicalName.Split('.')).FirstOrDefault(n => n.Length >= 3)?.ToArray();
            if (parts?.Length >= 2)
            {
                return $"{parts[0]}.{parts[1]}";
            }
            return null;
        }


    }

    internal FrozenDictionary<string, MatchedServicesMonitor> ServicesByName { get; }
    public IReadOnlyDictionary<IMdnsServiceSearchProfile, IMdnsMatchedServicesMonitor> Services { get; }
}
