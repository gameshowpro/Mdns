namespace GameshowPro.Mdns.Tests;

[Collection("mDNS network")]
public sealed class AdvertisedServiceTests
{
    [Fact]
    public void ExplicitScopeRequiresInterfaceAndAddressTogether()
    {
        _ = Assert.Throws<ArgumentException>(() => new AdvertisedService(
            new InstanceProperties("_osc", "udp", 9000),
            new AdvertisedServiceOptions { NetworkInterfaceId = "nic" }, NullLogger.Instance));
        _ = Assert.Throws<ArgumentException>(() => new AdvertisedService(
            new InstanceProperties("_osc", "udp", 9000),
            new AdvertisedServiceOptions { LocalAddress = IPAddress.Loopback }, NullLogger.Instance));
    }

    [Fact]
    public async Task DisposedPublisherRejectsStartAndRepeatedDisposeIsSafe()
    {
        AdvertisedService publisher = new(new InstanceProperties("_osc", "udp", 9000),
            NullLogger.Instance);
        await publisher.DisposeAsync();
        await publisher.DisposeAsync();
        _ = await Assert.ThrowsAsync<ObjectDisposedException>(() => publisher.StartAsync());
    }

    [Fact]
    public async Task CancelledStartDoesNotPublishAndCanBeDisposed()
    {
        AdvertisedService publisher = new(new InstanceProperties("_osc", "udp", 9000),
            NullLogger.Instance);
        using CancellationTokenSource stop = new();
        await stop.CancelAsync();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => publisher.StartAsync(stop.Token));
        await publisher.DisposeAsync();
    }

    [Fact]
    public void PublicationRecordsCarryScopedIdentityPortAndMachineName()
    {
        MdnsPublication publication = new("listener-7", "_oscjson", "tcp", 47888,
            new Dictionary<string, string> { ["machineName"] = "host" });
        ImmutableArray<DnsRecord> records = MdnsEngine.CreateRecords(publication, [IPAddress.Parse("192.0.2.9")]);
        SrvData srv = Assert.IsType<SrvData>(Assert.Single(records.Where(r => r.Type == DnsTypes.Srv)).Data);
        Assert.Equal((ushort)47888, srv.Port);
        Assert.Contains("listener-7", srv.Target);
        Assert.Contains(records, r => r.Type == DnsTypes.Txt && r.Data is TxtData txt &&
            txt.Strings.Any(bytes => System.Text.Encoding.UTF8.GetString(bytes) == "machineName=host"));
    }

    [Fact]
    public async Task DefaultAndScopedPublicationsCoexistAndWithdrawIndependently()
    {
        (NetworkInterface Nic, IPAddress Address) selected = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork &&
                    !IPAddress.IsLoopback(a.Address))
                .Select(a => (Nic: n, Address: a.Address)))
            .FirstOrDefault();
        if (selected.Nic is null)
        {
            throw Xunit.Sdk.SkipException.ForSkip("No active non-loopback IPv4 interface is available.");
        }

        string serviceType = "_gsp" + Guid.NewGuid().ToString("N")[..10];
        string instanceName = "scope-" + Guid.NewGuid().ToString("N")[..10];
        using CancellationTokenSource finderStop = new();
        ServiceSearchProfile profile = new(serviceType, "tcp", true);
        ServiceFinder finder = new([profile], NullLogger.Instance, finderStop.Token);
        await using AdvertisedService standard = new(
            new InstanceProperties(serviceType, "tcp", 44001), NullLogger.Instance);
        await using AdvertisedService scoped = new(
            new InstanceProperties(serviceType, "tcp", 44002),
            new AdvertisedServiceOptions
            {
                InstanceName = instanceName,
                NetworkInterfaceId = selected.Nic.Id,
                LocalAddress = selected.Address,
            }, NullLogger.Instance);
        try
        {
            await standard.StartAsync();
            await scoped.StartAsync();
            await Until(() => finder.Services[profile].Services.Any(s => s.Port == 44001) &&
                finder.Services[profile].Services.Any(s => s.Port == 44002));
            ImmutableArray<IMdnsMatchedService> found = finder.Services[profile].Services;
            Assert.Equal(Environment.MachineName + ".local", found.Single(s => s.Port == 44001).HostName);
            Assert.Equal(selected.Address, Assert.Single(found.Single(s => s.Port == 44002).Addresses));
            await scoped.DisposeAsync();
            await Until(() => finder.Services[profile].Services.Any(s => s.Port == 44001) &&
                finder.Services[profile].Services.All(s => s.Port != 44002));
        }
        finally
        {
            await finderStop.CancelAsync();
        }
    }

    [Fact]
    public async Task ConflictMonitorExcludesOwnPublicationAndFindsRemoteIdentity()
    {
        if (!NetworkInterface.GetAllNetworkInterfaces().Any(n => n.OperationalStatus == OperationalStatus.Up &&
            n.GetIPProperties().UnicastAddresses.Any(a =>
                a.Address.AddressFamily == AddressFamily.InterNetwork &&
                !IPAddress.IsLoopback(a.Address))))
        {
            throw Xunit.Sdk.SkipException.ForSkip("No active non-loopback IPv4 interface is available.");
        }

        string serviceType = "_gsp" + Guid.NewGuid().ToString("N")[..10];
        using CancellationTokenSource stop = new();
        ConflictMonitor monitor = new(new InstanceProperties(serviceType, "tcp", 44011),
            [], NullLogger.Instance, stop.Token);
        await using MdnsRegistration remote = await MdnsRuntime.RegisterAsync(
            new MdnsPublication("remote-" + Guid.NewGuid().ToString("N")[..8],
                serviceType, "tcp", 44012,
                new Dictionary<string, string> { ["machineName"] = "another-machine" }),
            new MdnsScope(), NullLogger.Instance, CancellationToken.None);
        Assert.Null(remote.Failure);
        try
        {
            await Until(() => monitor.ConflictingServices.Services.Any(s => s.Port == 44012));
            Assert.DoesNotContain(monitor.ConflictingServices.Services, s => s.Port == 44011);
        }
        finally { await stop.CancelAsync(); }
    }

    private static async Task Until(Func<bool> condition)
    {
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(8));
        while (!condition())
        {
            await Task.Delay(100, timeout.Token);
        }
    }
}
