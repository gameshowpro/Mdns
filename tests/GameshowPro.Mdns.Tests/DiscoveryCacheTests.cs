namespace GameshowPro.Mdns.Tests;

public sealed class DiscoveryCacheTests
{
    private const string Service = "_osc._udp.local.";
    private const string First = "first._osc._udp.local.";
    private const string Second = "second._osc._udp.local.";
    private const string Host = "shared.local.";
    private static readonly IPAddress s_address = IPAddress.Parse("192.0.2.7");

    [Fact]
    public void SplitRecordsJoinByNameAndDoNotAssociateAnUnknownAddress()
    {
        TestClock clock = new();
        MatchedServicesMonitor monitor = NewMonitor(clock);
        Send(monitor, 1, Ptr(First));
        Send(monitor, 1, Srv(First, Host, 9000));
        Assert.Empty(monitor.Services);
        Send(monitor, 1, new DnsRecord("unrelated.local.", DnsTypes.A, 1, 20,
            new AddressData(s_address)));
        Assert.Empty(monitor.Services);
        Send(monitor, 1, AddressRecord());
        IMdnsMatchedService found = Assert.Single(monitor.Services);
        Assert.Equal(9000, found.Port);
        Assert.Equal(s_address, Assert.Single(found.Addresses));
        Send(monitor, 1, Srv(First, Host, 9001));
        Assert.Equal(9001, Assert.Single(monitor.Services).Port);
    }

    [Fact]
    public void SharedAddressWithdrawalRemovesOnlyMatchingInstance()
    {
        TestClock clock = new();
        MatchedServicesMonitor monitor = NewMonitor(clock);
        Send(monitor, 1, Ptr(First), Ptr(Second), Srv(First, Host, 9000),
            Srv(Second, Host, 9001), AddressRecord());
        Assert.Equal(2, monitor.Services.Length);
        Send(monitor, 1, Ptr(First) with { Ttl = 0 });
        Assert.Equal(2, monitor.Services.Length);
        clock.Advance(TimeSpan.FromSeconds(2));
        monitor.TrimExpiredServices();
        Assert.Equal(9001, Assert.Single(monitor.Services).Port);
    }

    [Fact]
    public void PositiveRefreshRescuesGoodbyeWithinGracePeriod()
    {
        TestClock clock = new();
        MatchedServicesMonitor monitor = NewMonitor(clock);
        Send(monitor, 1, Ptr(First), Srv(First, Host, 9000), AddressRecord());
        Send(monitor, 1, Ptr(First) with { Ttl = 0 });
        clock.Advance(TimeSpan.FromMilliseconds(500));
        Send(monitor, 1, Ptr(First));
        clock.Advance(TimeSpan.FromSeconds(2));
        monitor.TrimExpiredServices();
        Assert.Equal(9000, Assert.Single(monitor.Services).Port);
    }

    [Fact]
    public void TtlExpiryAndInterfaceBoundaryAreRespected()
    {
        TestClock clock = new();
        MatchedServicesMonitor monitor = NewMonitor(clock);
        Send(monitor, 1, Ptr(First), Srv(First, Host, 9000));
        Send(monitor, 2, AddressRecord());
        Assert.Empty(monitor.Services);
        Send(monitor, 1, AddressRecord());
        _ = Assert.Single(monitor.Services);
        clock.Advance(TimeSpan.FromSeconds(21));
        monitor.TrimExpiredServices();
        Assert.Empty(monitor.Services);
    }

    [Fact]
    public void MachineNameTxtFiltersLocalhostAndCustomHostRemainsQualified()
    {
        MatchedServicesMonitor monitor = NewMonitor(machine: "this-machine");
        Send(monitor, 1, Ptr(First), Srv(First, "custom.osc.local.", 9000),
            new DnsRecord(First, DnsTypes.Txt, 1, 20,
                new TxtData([Encoding.UTF8.GetBytes("machineName=this-machine")])),
            new DnsRecord("custom.osc.local.", DnsTypes.A, 1, 20,
                new AddressData(s_address)));
        Assert.Empty(monitor.Services);
        Send(monitor, 1, new DnsRecord(First, DnsTypes.Txt, 1, 20,
            new TxtData([Encoding.UTF8.GetBytes("machineName=remote")])));
        Assert.Equal("custom.osc.local", Assert.Single(monitor.Services).HostName);
    }

    [Fact]
    public void CustomSearchProfileImplementationIsAccepted()
    {
        IMdnsServiceSearchProfile profile = new CustomProfile("_osc", "udp", true);
        ServiceFinder finder = new([profile], "local", NullLogger.Instance);
        Assert.Same(profile, finder.Services.Keys.Single());
        _ = Assert.Single(finder.ServicesByName);
    }

    [Fact]
    public void SameInstanceAcrossInterfacesMergesAddresses()
    {
        MatchedServicesMonitor monitor = NewMonitor();
        Send(monitor, 1, Ptr(First), Srv(First, Host, 9000), AddressRecord());
        Send(monitor, 2, Ptr(First), Srv(First, Host, 9000),
            new DnsRecord(Host, DnsTypes.A, 1, 20,
                new AddressData(IPAddress.Parse("192.0.2.8"))));
        Assert.Equal(2, Assert.Single(monitor.Services).Addresses.Length);
    }

    [Fact]
    public void LegacyMachineHostSelectionIsPreserved()
    {
        MatchedServicesMonitor monitor = NewMonitor();
        Send(monitor, 1, Ptr(First), Srv(First, "remote.osc.local.", 9000),
            new DnsRecord(First, DnsTypes.Txt, 1, 20,
                new TxtData([Encoding.UTF8.GetBytes("machineName=remote")])),
            new DnsRecord("remote.osc.local.", DnsTypes.A, 1, 20,
                new AddressData(s_address)));
        Assert.Equal("remote.local", Assert.Single(monitor.Services).HostName);
    }

    [Fact]
    public void CacheFlushRetainsFreshSiblingAddressesAndExpiresReplacedAddressAfterGrace()
    {
        TestClock clock = new();
        MatchedServicesMonitor monitor = NewMonitor(clock);
        Send(monitor, 1, Ptr(First), Srv(First, Host, 9000), AddressRecord());
        clock.Advance(TimeSpan.FromSeconds(2));
        IPAddress replacement = IPAddress.Parse("192.0.2.8");
        IPAddress sibling = IPAddress.Parse("192.0.2.9");
        Send(monitor, 1,
            new DnsRecord(Host, DnsTypes.A, 0x8001, 20, new AddressData(replacement)),
            new DnsRecord(Host, DnsTypes.A, 0x8001, 20, new AddressData(sibling)));
        Assert.Equal(3, Assert.Single(monitor.Services).Addresses.Length);
        clock.Advance(TimeSpan.FromSeconds(2));
        monitor.TrimExpiredServices();
        ImmutableArray<IPAddress> addresses = Assert.Single(monitor.Services).Addresses;
        Assert.Equal(2, addresses.Length);
        Assert.DoesNotContain(s_address, addresses);
        Assert.Contains(replacement, addresses);
        Assert.Contains(sibling, addresses);
    }

    private static MatchedServicesMonitor NewMonitor(TestClock? clock = null, string machine = "local") =>
        new(new ServiceSearchProfile("_osc", "udp", false), machine, clock);

    private static DnsRecord Ptr(string instance) =>
        new(Service, DnsTypes.Ptr, 1, 20, new NameData(instance));
    private static DnsRecord Srv(string instance, string host, ushort port) =>
        new(instance, DnsTypes.Srv, 1, 20, new SrvData(0, 0, port, host));
    private static DnsRecord AddressRecord() =>
        new(Host, DnsTypes.A, 1, 20, new AddressData(s_address));
    private static void Send(MatchedServicesMonitor monitor, int nic, params DnsRecord[] records) =>
        monitor.Receive(new MdnsPacket(new DnsMessage { Flags = 0x8400,
            Answers = [.. records] }, nic, IPAddress.Parse("224.0.0.251"), s_address));

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UnixEpoch;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan time) => _now += time;
    }

    private sealed record CustomProfile(string ServiceType, string Protocol, bool AllowLocalhost)
        : IMdnsServiceSearchProfile;
}
