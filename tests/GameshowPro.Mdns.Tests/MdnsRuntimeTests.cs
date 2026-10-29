namespace GameshowPro.Mdns.Tests;

[CollectionDefinition("mDNS network", DisableParallelization = true)]
public sealed class MdnsNetworkTestGroup;

[Collection("mDNS network")]
public sealed class MdnsRuntimeTests
{
    private static readonly IPAddress s_local = IPAddress.Parse("192.0.2.44");

    [Fact]
    public void CatalogueAnswersPtrWithSrvTxtAndAddressAndSuppressesFreshKnownAnswer()
    {
        MdnsPublication publication = new("node-1", "_oscjson", "tcp", 4567,
            new Dictionary<string, string> { ["path"] = "/osc" });
        ImmutableArray<DnsRecord> records = MdnsEngine.CreateRecords(publication, [s_local]);
        DnsRecord ptr = Assert.Single(records.Where(r => r.Type == DnsTypes.Ptr &&
            DnsNames.Equals(r.Name, "_oscjson._tcp.local.")));
        Assert.Equal("node-1._oscjson._tcp.local.", Assert.IsType<NameData>(ptr.Data).Name);
        Assert.Contains(records, r => r.Type == DnsTypes.Srv &&
            Assert.IsType<SrvData>(r.Data).Port == 4567);
        Assert.Contains(records, r => r.Type == DnsTypes.Txt &&
            Assert.IsType<TxtData>(r.Data).Strings.Any(s =>
                System.Text.Encoding.UTF8.GetString(s) == "path=/osc"));
        Assert.Contains(records, r => r.Type == DnsTypes.A &&
            Assert.IsType<AddressData>(r.Data).Address.Equals(s_local));
        DnsMessage query = new() { Questions = [new("_oscjson._tcp.local.", DnsTypes.Ptr)] };
        ImmutableArray<DnsRecord> answer = MdnsEngine.Query(query, records);
        Assert.Contains(answer, r => DnsRecords.Equivalent(r, ptr));
        Assert.Contains(answer, r => r.Type == DnsTypes.Srv);
        Assert.Contains(answer, r => r.Type == DnsTypes.A);
        DnsMessage known = query with { Answers = [ptr with { Ttl = ptr.Ttl / 2 }] };
        Assert.DoesNotContain(MdnsEngine.Query(known, records), r => DnsRecords.Equivalent(r, ptr));
    }

    [Fact]
    public void GoodbyeKeepsSharedRecordsAndRestartGetsPositiveTtl()
    {
        MdnsPublication publication = new("node-1", "_osc", "udp", 9000,
            new Dictionary<string, string>());
        ImmutableArray<DnsRecord> first = MdnsEngine.CreateRecords(publication, [s_local]);
        ImmutableArray<DnsRecord> sibling = MdnsEngine.CreateRecords(publication with { Port = 9001 }, [s_local]);
        ImmutableArray<DnsRecord> goodbye = MdnsEngine.Goodbye(first, sibling);
        Assert.DoesNotContain(goodbye, r => r.Type == DnsTypes.A);
        Assert.All(goodbye, r => Assert.Equal(0u, r.Ttl));
        Assert.All(MdnsEngine.CreateRecords(publication, [s_local]), r => Assert.True(r.Ttl > 0));
    }

    [Fact]
    public void ConflictChecksWholeOwnedAddressSet()
    {
        MdnsPublication publication = new("node-1", "_osc", "udp", 9000,
            new Dictionary<string, string>());
        ImmutableArray<DnsRecord> records = MdnsEngine.CreateRecords(publication, [s_local, IPAddress.Parse("192.0.2.45")]);
        DnsRecord secondAddress = records.Last(r => r.Type == DnsTypes.A);
        Assert.False(MdnsEngine.HasConflict(new DnsMessage { Answers = [secondAddress] }, records));
        Assert.True(MdnsEngine.HasConflict(new DnsMessage
        {
            Answers = [secondAddress with { Data = new AddressData(IPAddress.Parse("192.0.2.99")) }]
        }, records));
    }

    [Fact]
    public async Task ScopedRegistrationsShareTransportAndWithdrawalPreservesSibling()
    {
        (NetworkInterface Nic, IPAddress Address) selected = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => (Nic: n, Address: a.Address)))
            .OrderByDescending(x => IPAddress.IsLoopback(x.Address)).FirstOrDefault();
        if (selected.Nic is null)
        {
            throw Xunit.Sdk.SkipException.ForSkip("No active IPv4 interface is available.");
        }

        MdnsScope scope = new(selected.Nic.Id, selected.Address);
        string service = "_mdnstest" + Guid.NewGuid().ToString("N")[..6];
        MdnsPublication first = new("first-" + service, service, "tcp", 49001,
            new Dictionary<string, string>());
        MdnsPublication second = first with { InstanceName = "second-" + service, Port = 49002 };
        await using MdnsRegistration one = await MdnsRuntime.RegisterAsync(first, scope, NullLogger.Instance);
        await using MdnsRegistration two = await MdnsRuntime.RegisterAsync(second, scope, NullLogger.Instance);
        Assert.Null(one.Failure);
        Assert.Null(two.Failure);
        using UdpClient probe = new(new IPEndPoint(selected.Address, 0));
        ImmutableArray<DnsRecord> before = await Query(probe, selected.Address, service, 2);
        Assert.Contains(before, r => r.Data is NameData n && n.Name.Contains(first.InstanceName));
        Assert.Contains(before, r => r.Data is NameData n && n.Name.Contains(second.InstanceName));
        await one.DisposeAsync();
        ImmutableArray<DnsRecord> after = await Query(probe, selected.Address, service, 1);
        Assert.DoesNotContain(after, r => r.Data is NameData n && n.Name.Contains(first.InstanceName));
        Assert.Contains(after, r => r.Data is NameData n && n.Name.Contains(second.InstanceName));
    }

    [Fact]
    public async Task DefaultAndScopedRegistrationsCoexistOnSelectedNetwork()
    {
        (NetworkInterface Nic, IPAddress Address) selected = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork &&
                    !IPAddress.IsLoopback(a.Address))
                .Select(a => (Nic: n, Address: a.Address))).FirstOrDefault();
        if (selected.Nic is null)
        {
            throw Xunit.Sdk.SkipException.ForSkip("No non-loopback IPv4 interface is available.");
        }

        string service = "_mdnsboth" + Guid.NewGuid().ToString("N")[..6];
        MdnsPublication publication = new("default-" + service, service, "tcp", 49003,
            new Dictionary<string, string>());
        await using MdnsRegistration defaultRegistration = await MdnsRuntime.RegisterAsync(publication,
            new MdnsScope(), NullLogger.Instance);
        await using MdnsRegistration scopedRegistration = await MdnsRuntime.RegisterAsync(
            publication with { InstanceName = "scoped-" + service, Port = 49004 },
            new MdnsScope(selected.Nic.Id, selected.Address), NullLogger.Instance);
        Assert.Null(defaultRegistration.Failure);
        Assert.Null(scopedRegistration.Failure);
        // A second process may own this IP:5353. Multicast reaches each listener,
        // while Windows self-unicast delivery to a reused port is nondeterministic.
        using Socket probe = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        probe.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastLoopback, true);
        probe.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface,
            selected.Address.GetAddressBytes());
        probe.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 0);
        probe.Bind(new IPEndPoint(selected.Address, 0));
        ImmutableArray<DnsRecord> records;
        try { records = await QueryMulticast(probe, service, 2); }
        catch (Exception ex)
        {
            Assert.Fail($"selected={selected.Address}, {ex}; default failure: {defaultRegistration.Failure}; scoped failure: {scopedRegistration.Failure}");
            throw;
        }
        Assert.Contains(records, r => r.Data is NameData n && n.Name.Contains("default-" + service));
        Assert.Contains(records, r => r.Data is NameData n && n.Name.Contains("scoped-" + service));
    }

    [Fact]
    public async Task InvalidPublicationDoesNotPoisonNextRegistration()
    {
        (NetworkInterface Nic, IPAddress Address) selected = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => (Nic: n, Address: a.Address))).FirstOrDefault();
        if (selected.Nic is null)
        {
            throw Xunit.Sdk.SkipException.ForSkip("No active IPv4 interface is available.");
        }

        MdnsScope scope = new(selected.Nic.Id, selected.Address);
        MdnsPublication bad = new(new string('x', 64), "_badtest", "tcp", 49005,
            new Dictionary<string, string>());
        _ = await Assert.ThrowsAnyAsync<Exception>(() => MdnsRuntime.RegisterAsync(bad, scope, NullLogger.Instance));
        await using MdnsRegistration good = await MdnsRuntime.RegisterAsync(bad with
        { InstanceName = "valid-" + Guid.NewGuid().ToString("N")[..6] }, scope, NullLogger.Instance);
        Assert.Null(good.Failure);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TtlZeroMulticastQueryGetsReplyFromSelectedInterface(bool loopback)
    {
        // Allow a hardware-specific run on hosts that enumerate virtual adapters first.
        string? requestedInterface = Environment.GetEnvironmentVariable("GSP_MDNS_TEST_INTERFACE");
        (NetworkInterface Nic, IPAddress Address) selected = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .Where(n => loopback || requestedInterface is null ||
                string.Equals(n.Id, requestedInterface, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(n.Name, requestedInterface, StringComparison.OrdinalIgnoreCase))
            .SelectMany(n => n.GetIPProperties().UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork &&
                    IPAddress.IsLoopback(a.Address) == loopback)
                .Select(a => (Nic: n, Address: a.Address))).FirstOrDefault();
        if (selected.Nic is null)
        {
            throw Xunit.Sdk.SkipException.ForSkip(loopback
                ? "No active IPv4 loopback interface is available."
                : "No active non-loopback IPv4 interface is available.");
        }

        string service = "_ttlzero" + Guid.NewGuid().ToString("N")[..6];
        MdnsPublication publication = new("ttl-" + service, service, "udp", 49006,
            new Dictionary<string, string>());
        await using MdnsRegistration registration = await MdnsRuntime.RegisterAsync(publication,
            new MdnsScope(selected.Nic.Id, selected.Address), NullLogger.Instance);
        Assert.Null(registration.Failure);
        using Socket probe = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        probe.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
        probe.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastLoopback, true);
        probe.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface,
            selected.Address.GetAddressBytes());
        probe.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 0);
        probe.Bind(new IPEndPoint(selected.Address, 0));
        ushort id = checked((ushort)Random.Shared.Next(1, ushort.MaxValue));
        DnsMessage query = new()
        {
            Id = id,
            Questions = [new($"{service}._udp.local.", DnsTypes.Ptr)]
        };
        _ = probe.SendTo(DnsCodec.Write(query), new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353));
        byte[] buffer = new byte[9000];
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        while (true)
        {
            SocketReceiveMessageFromResult packet = await probe.ReceiveMessageFromAsync(buffer, SocketFlags.None,
                new IPEndPoint(IPAddress.Any, 0), timeout.Token);
            if (!DnsCodec.TryRead(buffer.AsSpan(0, packet.ReceivedBytes), out DnsMessage? response) ||
                !response!.IsResponse || response.Id != id ||
                !response.Answers.Any(r => r.Type == DnsTypes.Ptr &&
                    r.Data is NameData name && name.Name.Contains(publication.InstanceName)))
            {
                continue;
            }

            Assert.Equal(5353, ((IPEndPoint)packet.RemoteEndPoint).Port);
            Assert.Equal(selected.Nic.GetIPProperties().GetIPv4Properties()!.Index,
                packet.PacketInformation.Interface);
            break;
        }
    }

    [Fact]
    public async Task TwoIpv6AddressesShareOneMembershipUntilLastChannelLeaves()
    {
        (NetworkInterface Nic, IPAddress[] Addresses) selected = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .Select(n => (Nic: n, Addresses: n.GetIPProperties().UnicastAddresses
                .Select(a => a.Address)
                .Where(a => a.AddressFamily == AddressFamily.InterNetworkV6)
                .Distinct().Take(2).ToArray()))
            .FirstOrDefault(x => x.Addresses.Length == 2);
        // A host with only one IPv6 address cannot exercise duplicate membership.
        if (selected.Nic is null)
        {
            return;
        }

        int index = selected.Nic.GetIPProperties().GetIPv6Properties()!.Index;
        using Socket receiver = new(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
        receiver.DualMode = false;
        receiver.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        receiver.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.PacketInformation, true);
        receiver.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastLoopback, true);
        receiver.Bind(new IPEndPoint(IPAddress.IPv6Any, 5353));
        using CancellationTokenSource stop = new();
        using MdnsChannel first = new(new MdnsAddress(selected.Nic.Id, index,
            selected.Addresses[0]), receiver, (_, _) => Task.CompletedTask, stop.Token);
        using MdnsChannel second = new(new MdnsAddress(selected.Nic.Id, index,
            selected.Addresses[1]), receiver, (_, _) => Task.CompletedTask, stop.Token);
        Assert.Equal(2, MdnsChannel.MembershipCount(receiver, AddressFamily.InterNetworkV6, index));
        first.Dispose();
        Assert.Equal(1, MdnsChannel.MembershipCount(receiver, AddressFamily.InterNetworkV6, index));
        byte[] marker = Guid.NewGuid().ToByteArray();
        second.Send(marker, null);
        byte[] buffer = new byte[9000];
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        while (true)
        {
            SocketReceiveMessageFromResult packet = await receiver.ReceiveMessageFromAsync(buffer, SocketFlags.None,
                new IPEndPoint(IPAddress.IPv6Any, 0), timeout.Token);
            if (!buffer.AsSpan(0, packet.ReceivedBytes).SequenceEqual(marker))
            {
                continue;
            }

            Assert.Equal(index, packet.PacketInformation.Interface);
            break;
        }
        second.Dispose();
        Assert.Equal(0, MdnsChannel.MembershipCount(receiver, AddressFamily.InterNetworkV6, index));
    }

    private static async Task<ImmutableArray<DnsRecord>> Query(UdpClient probe, IPAddress address,
        string serviceType, int expected)
    {
        ushort id = checked((ushort)Random.Shared.Next(1, ushort.MaxValue));
        DnsMessage message = new()
        {
            Id = id,
            Questions = [new($"{serviceType}._tcp.local.", DnsTypes.Ptr, 0x8001)]
        };
        _ = await probe.SendAsync(DnsCodec.Write(message), new IPEndPoint(address, 5353));
        ImmutableArray<DnsRecord>.Builder answers = ImmutableArray.CreateBuilder<DnsRecord>();
        int received = 0;
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        while (answers.Count < expected)
        {
            UdpReceiveResult response;
            try { response = await probe.ReceiveAsync(timeout.Token); }
            catch (OperationCanceledException ex)
            {
                throw new InvalidOperationException($"Timed out with {received} datagrams and {answers.Count} PTR answers", ex);
            }
            received++;
            if (response.RemoteEndPoint.Port != 5353 ||
                !DnsCodec.TryRead(response.Buffer, out DnsMessage? decoded) || decoded!.Id != id)
            {
                continue;
            }

            answers.AddRange(decoded.Answers.Where(r => r.Type == DnsTypes.Ptr));
        }
        return answers.ToImmutable();
    }

    private static async Task<ImmutableArray<DnsRecord>> QueryMulticast(Socket probe,
        string serviceType, int expected)
    {
        ushort id = checked((ushort)Random.Shared.Next(1, ushort.MaxValue));
        DnsMessage query = new()
        {
            Id = id,
            Questions = [new($"{serviceType}._tcp.local.", DnsTypes.Ptr)]
        };
        _ = probe.SendTo(DnsCodec.Write(query), new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353));
        byte[] buffer = new byte[9000];
        ImmutableArray<DnsRecord>.Builder answers = ImmutableArray.CreateBuilder<DnsRecord>();
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        while (answers.Count < expected)
        {
            SocketReceiveFromResult response = await probe.ReceiveFromAsync(buffer, SocketFlags.None,
                new IPEndPoint(IPAddress.Any, 0), timeout.Token);
            if (response.RemoteEndPoint is not IPEndPoint source || source.Port != 5353 ||
                !DnsCodec.TryRead(buffer.AsSpan(0, response.ReceivedBytes), out DnsMessage? decoded) ||
                !decoded!.IsResponse || decoded.Id != id)
            {
                continue;
            }

            answers.AddRange(decoded.Answers.Where(r => r.Type == DnsTypes.Ptr));
        }
        return answers.ToImmutable();
    }

}
