namespace GameshowPro.Mdns;

/// <summary>
/// Allows services to advertise the availability of a service they to clients.
/// </summary>
public class AdvertisedService
{
    private readonly ILogger _logger;
    private readonly IMdnsInstanceProperties _instanceProperties;

    /// <summary>
    /// Create a new advertised service. Start by calling <see cref="AdvertiseUntilCancelled(CancellationToken)"/>.
    /// </summary>
    public AdvertisedService(IMdnsInstanceProperties instanceProperties, ILogger logger) : this(instanceProperties, Environment.MachineName, logger)
    {
    }

    /// <summary>
    /// Common overload used when thread to launch is created in this class or elsewhere.
    /// </summary>
    internal AdvertisedService(IMdnsInstanceProperties instanceProperties, string thisMachineName, ILogger logger)
    {
        _instanceProperties = instanceProperties;
        _logger = logger;
        ThisMachineName = thisMachineName;
        Profile = new(_instanceProperties.InstanceName, _instanceProperties.ServiceType + "._" + _instanceProperties.Protocol, _instanceProperties.Port);
        Profile.AddProperty(TxtRecordMachineName, ThisMachineName);
    }

    /// <summary>
    /// Returns a task that advertises the service until the cancellation token is cancelled.
    /// </summary>
    // Used only when this class is publicly instantiated, so this class is managing the discovery lifecycle.
    public async Task AdvertiseUntilCancelled(CancellationToken cancellationToken)
    {
        ServiceDiscovery serviceDiscovery = new();
        await AdvertiseUntilCancelled(serviceDiscovery, cancellationToken);
        serviceDiscovery.Dispose();
    }

    internal async Task AdvertiseUntilCancelled(IServiceDiscovery serviceDiscovery, CancellationToken cancellationToken)
    {
        serviceDiscovery.Advertise(Profile);
        serviceDiscovery.Announce(Profile);
        _logger.LogInformation("Advertising and announcing mdns service type {_instanceProperties.ServiceType}", _instanceProperties.ServiceType);
        try
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
        }
        finally
        {
            serviceDiscovery.Unadvertise(Profile);
        }
        _logger.LogInformation("Stopped advertising and announcing mdns service type {_instanceProperties.ServiceType}", _instanceProperties.ServiceType);
    }

    internal ServiceProfile Profile { get; }
    internal string ThisMachineName { get; }
}
