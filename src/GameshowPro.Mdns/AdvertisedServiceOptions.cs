namespace GameshowPro.Mdns;

/// <summary>Optional DNS-SD identity, interface scope, and TXT values.</summary>
public sealed class AdvertisedServiceOptions
{
    public string? InstanceName { get; init; }
    public string? NetworkInterfaceId { get; init; }
    public IPAddress? LocalAddress { get; init; }
    public IReadOnlyDictionary<string, string>? TxtProperties { get; init; }
}
