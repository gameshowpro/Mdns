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
    public void AddressSetRequiresInterfaceAndCannotBeCombinedWithSingleAddress()
    {
        InstanceProperties properties = new("_osc", "udp", 9000);
        _ = Assert.Throws<ArgumentException>(() => new AdvertisedService(properties,
            new AdvertisedServiceOptions { LocalAddresses = [IPAddress.Loopback] }, NullLogger.Instance));
        _ = Assert.Throws<ArgumentException>(() => new AdvertisedService(properties,
            new AdvertisedServiceOptions { NetworkInterfaceId = "nic", LocalAddresses = [] }, NullLogger.Instance));
        _ = Assert.Throws<ArgumentException>(() => new AdvertisedService(properties,
            new AdvertisedServiceOptions
            {
                NetworkInterfaceId = "nic", LocalAddresses = [IPAddress.Loopback], LocalAddress = IPAddress.Loopback
            }, NullLogger.Instance));
        _ = Assert.Throws<ArgumentException>(() => new AdvertisedService(properties,
            new AdvertisedServiceOptions
            {
                NetworkInterfaceId = "nic", LocalAddresses = new IPAddress[] { null! }
            }, NullLogger.Instance));
    }

    [Fact]
    public void AddressOptionsSnapshotCollectionAndMutableIpAddressValues()
    {
        IPAddress ipv6 = new(IPAddress.Parse("fe80::1").GetAddressBytes(), 7);
        IPAddress ipv4 = IPAddress.Parse("192.0.2.1");
        List<IPAddress> addresses = [ipv6, ipv4];
        AdvertisedService publisher = new(new InstanceProperties("_osc", "udp", 9000),
            new AdvertisedServiceOptions { NetworkInterfaceId = "nic", LocalAddresses = addresses },
            NullLogger.Instance);
        ipv6.ScopeId = 9;
        addresses[1] = IPAddress.Parse("192.0.2.2");
        addresses.Add(IPAddress.Parse("192.0.2.3"));

        System.Reflection.FieldInfo field = Assert.IsAssignableFrom<System.Reflection.FieldInfo>(
            typeof(AdvertisedService).GetField("_options",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic));
        AdvertisedServiceOptions snapshot = Assert.IsType<AdvertisedServiceOptions>(field.GetValue(publisher));
        IReadOnlyList<IPAddress> copied = Assert.IsAssignableFrom<IReadOnlyList<IPAddress>>(snapshot.LocalAddresses);
        Assert.Equal(2, copied.Count);
        Assert.Equal(7, copied[0].ScopeId);
        Assert.NotSame(ipv6, copied[0]);
        Assert.Equal(IPAddress.Parse("192.0.2.1"), copied[1]);
        Assert.NotSame(ipv4, copied[1]);
    }

    [Fact]
    public void SingleAddressIsAlsoSnapshotted()
    {
        IPAddress ipv6 = new(IPAddress.Parse("fe80::1").GetAddressBytes(), 7);
        AdvertisedService publisher = new(new InstanceProperties("_osc", "udp", 9000),
            new AdvertisedServiceOptions { NetworkInterfaceId = "nic", LocalAddress = ipv6 },
            NullLogger.Instance);
        ipv6.ScopeId = 9;

        System.Reflection.FieldInfo field = Assert.IsAssignableFrom<System.Reflection.FieldInfo>(
            typeof(AdvertisedService).GetField("_options",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic));
        AdvertisedServiceOptions snapshot = Assert.IsType<AdvertisedServiceOptions>(field.GetValue(publisher));
        Assert.Equal(7, Assert.IsAssignableFrom<IPAddress>(snapshot.LocalAddress).ScopeId);
        Assert.NotSame(ipv6, snapshot.LocalAddress);
    }

    [Theory]
    [InlineData("")]
    [InlineData("-leading")]
    [InlineData("trailing-")]
    [InlineData("has.dot")]
    [InlineData("has_underscore")]
    [InlineData("has space")]
    [InlineData("café")]
    public void InvalidHostNameIsRejected(string hostName)
    {
        _ = Assert.Throws<ArgumentException>(() => new AdvertisedService(
            new InstanceProperties("_https", "tcp", 9443),
            new AdvertisedServiceOptions { HostName = hostName }, NullLogger.Instance));
    }

    [Fact]
    public void OverlongHostNameIsRejectedAndLongestLabelAccepted()
    {
        _ = Assert.Throws<ArgumentException>(() => new AdvertisedService(
            new InstanceProperties("_https", "tcp", 9443),
            new AdvertisedServiceOptions { HostName = new string('a', 64) }, NullLogger.Instance));
        _ = new AdvertisedService(new InstanceProperties("_https", "tcp", 9443),
            new AdvertisedServiceOptions { HostName = new string('a', 63) }, NullLogger.Instance);
        _ = new AdvertisedService(new InstanceProperties("_https", "tcp", 9443),
            new AdvertisedServiceOptions { HostName = "Studio-PC-1" }, NullLogger.Instance);
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
    public void MultiAddressQueriesReturnCompleteRrsetAndSuppressOnlyKnownAddresses()
    {
        MdnsPublication publication = new("listener-7", "_oscjson", "tcp", 47888,
            new Dictionary<string, string>(), "studio-pc");
        IPAddress firstV4 = IPAddress.Parse("192.0.2.9");
        IPAddress secondV4 = IPAddress.Parse("192.0.2.10");
        IPAddress firstV6 = new(IPAddress.Parse("fe80::9").GetAddressBytes(), 7);
        IPAddress secondV6 = IPAddress.Parse("2001:db8::10");
        IPAddress sameV6DifferentScope = new(firstV6.GetAddressBytes(), 8);
        ImmutableArray<DnsRecord> records = MdnsEngine.CreateRecords(publication,
            [firstV4, secondV4, firstV6, sameV6DifferentScope, secondV6]);
        Assert.Equal(2, records.Count(record => record.Type == DnsTypes.A));
        Assert.Equal(2, records.Count(record => record.Type == DnsTypes.Aaaa));

        string host = "studio-pc.local.";
        ImmutableArray<DnsRecord> v4 = MdnsEngine.Query(new DnsMessage
        {
            Questions = [new(host, DnsTypes.A)]
        }, records);
        Assert.Equal(2, v4.Count(record => record.Type == DnsTypes.A));
        ImmutableArray<DnsRecord> v6 = MdnsEngine.Query(new DnsMessage
        {
            Questions = [new(host, DnsTypes.Aaaa)]
        }, records);
        Assert.Equal(2, v6.Count(record => record.Type == DnsTypes.Aaaa));

        DnsRecord knownAddress = Assert.Single(records.Where(record => record.Type == DnsTypes.A &&
            Assert.IsType<AddressData>(record.Data).Address.Equals(firstV4)));
        ImmutableArray<DnsRecord> unknown = MdnsEngine.Query(new DnsMessage
        {
            Questions = [new(host, DnsTypes.A)],
            Answers = [knownAddress with { Ttl = knownAddress.Ttl / 2 }]
        }, records);
        Assert.Equal(secondV4, Assert.IsType<AddressData>(Assert.Single(unknown).Data).Address);

        ImmutableArray<DnsRecord> ptrAnswer = MdnsEngine.Query(new DnsMessage
        {
            Questions = [new("_oscjson._tcp.local.", DnsTypes.Ptr)]
        }, records);
        Assert.Equal(2, ptrAnswer.Count(record => record.Type == DnsTypes.A));
        Assert.Equal(2, ptrAnswer.Count(record => record.Type == DnsTypes.Aaaa));
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
