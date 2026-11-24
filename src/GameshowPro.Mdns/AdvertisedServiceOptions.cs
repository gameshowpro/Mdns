namespace GameshowPro.Mdns;

/// <summary>Optional DNS-SD identity, interface scope, and TXT values.</summary>
public sealed class AdvertisedServiceOptions
{
    public string? InstanceName { get; init; }

    /// <summary>
    /// Optional single DNS label (<c>a-z</c>, <c>0-9</c>, <c>-</c>; 1 to 63 characters; not starting or ending with
    /// <c>-</c>; letters are accepted in either case and published as given). When set, the SRV target and the A/AAAA
    /// records use <c>&lt;HostName&gt;.local</c>. Services in one process that share a HostName share its address
    /// records. When unset, the historical <c>&lt;instance&gt;.&lt;service&gt;.local</c> host is used.
    /// </summary>
    public string? HostName { get; init; }
    public string? NetworkInterfaceId { get; init; }
    public IPAddress? LocalAddress { get; init; }
    public IReadOnlyDictionary<string, string>? TxtProperties { get; init; }
}
