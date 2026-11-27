namespace GameshowPro.Mdns.Tests;

[Collection("mDNS network")]
public sealed class MdnsRuntimeAddressSetTests
{
    private sealed class FakeTransport : IDisposable
    {
        private readonly object _gate = new();
        private readonly List<(DateTimeOffset Due, TaskCompletionSource Source)> _delays = [];
        private readonly IDisposable _lease;
        internal List<MdnsAddress> Addresses { get; }
        internal List<(MdnsAddress Channel, byte[] Bytes)> Sent { get; } = [];
        internal DateTimeOffset Now { get; private set; } = DateTimeOffset.UtcNow;
        internal bool HoldProbeDelays { get; set; }

        internal FakeTransport(params MdnsAddress[] addresses)
        {
            Addresses = [.. addresses];
            _lease = MdnsRuntime.InstallTestTransport(Addresses, Send, () => Now, Delay);
        }

        private void Send(MdnsAddress channel, byte[] bytes, IPEndPoint? destination)
        {
            if (!Addresses.Any(address => address.Key == channel.Key))
            {
                throw new InvalidOperationException("Removed address was used to send.");
            }
            lock (_gate) { Sent.Add((channel, [.. bytes])); }
        }

        private Task Delay(TimeSpan duration)
        {
            if (duration < TimeSpan.FromSeconds(1) && !HoldProbeDelays) { return Task.CompletedTask; }
            TaskCompletionSource source = new(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_gate) { _delays.Add((Now + duration, source)); }
            return source.Task;
        }

        internal void Advance(TimeSpan duration)
        {
            lock (_gate)
            {
                Now += duration;
                foreach ((DateTimeOffset due, TaskCompletionSource source) in _delays.Where(item => item.Due <= Now))
                {
                    _ = source.TrySetResult();
                }
                _ = _delays.RemoveAll(item => item.Due <= Now);
            }
        }

        internal void AdvanceClock(TimeSpan duration)
        {
            lock (_gate) { Now += duration; }
        }

        internal (MdnsAddress Channel, byte[] Bytes)[] Snapshot()
        {
            lock (_gate) { return [.. Sent]; }
        }

        public void Dispose() => _lease.Dispose();
    }

    private static MdnsPublication Publication(string host) => new("instance-" + host, "_faketest", "tcp", 49420,
        new Dictionary<string, string>(), host);

    private static byte[] ConflictingResponse(MdnsPublication publication, IPAddress address)
    {
        ImmutableArray<DnsRecord> records = MdnsEngine.CreateRecords(publication, [address]);
        return DnsCodec.Write(new DnsMessage { Flags = 0x8400, Answers = records });
    }

    private static async Task Until(Func<bool> predicate)
    {
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(3));
        while (!predicate()) { await Task.Delay(10, timeout.Token); }
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(true, true, false)]
    [InlineData(false, false, true)]
    [InlineData(false, true, true)]
    [InlineData(true, false, true)]
    [InlineData(true, true, true)]
    public async Task DelayedOwnAddressEchoSurvivesTwoSecondsAcrossAdapters(
        bool scoped, bool ipv6Source, bool secondAdapterJoins)
    {
        IPAddress first4 = IPAddress.Parse("192.0.2.110");
        IPAddress firstUla = IPAddress.Parse("fd00::110");
        IPAddress first6 = new(IPAddress.Parse("fe80::110").GetAddressBytes(), 11);
        IPAddress second4 = IPAddress.Parse("192.0.2.120");
        IPAddress secondUla = IPAddress.Parse("fd00::120");
        IPAddress second6 = new(IPAddress.Parse("fe80::120").GetAddressBytes(), 12);
        using FakeTransport fake = new(new MdnsAddress("one", 11, first4),
            new MdnsAddress("one", 11, firstUla), new MdnsAddress("one", 11, first6));
        if (!secondAdapterJoins)
        {
            fake.Addresses.Add(new MdnsAddress("two", 12, second4));
            fake.Addresses.Add(new MdnsAddress("two", 12, secondUla));
            fake.Addresses.Add(new MdnsAddress("two", 12, second6));
        }
        string host = "delay-" + Guid.NewGuid().ToString("N")[..6];
        MdnsPublication tls = Publication(host);
        MdnsPublication soundling = tls with { InstanceName = "soundling-" + host,
            ServiceType = "_soundling", Port = 49421 };
        List<MdnsRegistration> registrations = [];
        try
        {
            foreach (MdnsPublication publication in new[] { tls, soundling })
            {
                registrations.Add(await MdnsRuntime.RegisterAsync(publication,
                    scoped ? new MdnsScope("one", null, [first4, firstUla, first6]) : new MdnsScope(), NullLogger.Instance));
            }
            if (secondAdapterJoins)
            {
                fake.Addresses.Add(new MdnsAddress("two", 12, second4));
                fake.Addresses.Add(new MdnsAddress("two", 12, secondUla));
                fake.Addresses.Add(new MdnsAddress("two", 12, second6));
                MdnsRuntime.ReconcileForTest();
            }
            if (scoped)
            {
                foreach (MdnsPublication publication in new[] { tls, soundling })
                {
                    registrations.Add(await MdnsRuntime.RegisterAsync(publication,
                        new MdnsScope("two", null, [second4, secondUla, second6]), NullLogger.Instance));
                }
            }
            Assert.All(registrations, registration => Assert.Null(registration.Failure));
            IPAddress source = ipv6Source
                ? new IPAddress(first6.GetAddressBytes(), 12) : first4;
            ImmutableArray<DnsRecord> firstAddressRecords = [.. MdnsEngine.CreateRecords(tls, [first4, firstUla, first6])
                .Where(record => record.Type is DnsTypes.A or DnsTypes.Aaaa)];
            byte[] delayed = DnsCodec.Write(new DnsMessage { Flags = 0x8400, Answers = firstAddressRecords });
            MdnsRuntime.RememberTransmission(ipv6Source ? first6 : first4, delayed, fake.Now);
            fake.Advance(TimeSpan.FromSeconds(3));
            Assert.False(MdnsRuntime.IsOwnPacket(new IPEndPoint(source, 5353), delayed,
                [first4, firstUla, first6, second4, secondUla, second6], fake.Now));
            IPAddress destination = IPAddress.Parse(ipv6Source ? "ff02::fb" : "224.0.0.251");
            MdnsRuntime.DispatchForTest(delayed, 12, destination,
                new IPEndPoint(source, 5353));
            MdnsRuntime.DispatchForTest(delayed, 12, destination,
                new IPEndPoint(source, 5353));
            Assert.All(registrations, registration =>
            {
                Assert.Null(registration.LastConflict);
                Assert.True(registration.Active);
                Assert.Null(registration.Failure);
            });
        }
        finally
        {
            foreach (MdnsRegistration registration in registrations)
            {
                await registration.DisposeAsync();
            }
        }
    }

    [Theory]
    [InlineData("remote-address")]
    [InlineData("local-address")]
    [InlineData("local-txt")]
    [InlineData("local-srv")]
    [InlineData("owned-address-plus-txt")]
    public async Task DelayedOwnFilteringPreservesRealConflicts(string scenario)
    {
        IPAddress first = IPAddress.Parse("192.0.2.130");
        IPAddress second = IPAddress.Parse("198.51.100.131");
        IPAddress unknown = IPAddress.Parse("203.0.113.132");
        using FakeTransport fake = new(new MdnsAddress("one", 13, first), new MdnsAddress("two", 14, second));
        MdnsPublication publication = Publication("negative-" + Guid.NewGuid().ToString("N")[..6]);
        await using MdnsRegistration registration = await MdnsRuntime.RegisterAsync(publication,
            new MdnsScope(), NullLogger.Instance);
        Assert.Null(registration.Failure);
        fake.Advance(TimeSpan.FromSeconds(3));
        ImmutableArray<DnsRecord> ours = MdnsEngine.CreateRecords(publication, [first]);
        DnsRecord ownedAddress = Assert.Single(ours.Where(record => record.Type == DnsTypes.A));
        DnsRecord conflicting = scenario switch
        {
            "remote-address" or "local-address" => ownedAddress with { Data = new AddressData(unknown) },
            "local-txt" or "owned-address-plus-txt" => Assert.Single(ours.Where(record => record.Type == DnsTypes.Txt))
                with { Data = new TxtData([Encoding.UTF8.GetBytes("other=process")]) },
            _ => Assert.Single(ours.Where(record => record.Type == DnsTypes.Srv))
                with { Data = new SrvData(0, 0, 49422, publication.HostName + ".local.") }
        };
        byte[] bytes = DnsCodec.Write(new DnsMessage { Flags = 0x8400,
            Answers = scenario == "owned-address-plus-txt" ? [ownedAddress, conflicting] : [conflicting] });
        IPEndPoint source = new(scenario == "remote-address" ? unknown : first, 5353);
        MdnsRuntime.DispatchForTest(bytes, 14, IPAddress.Parse("224.0.0.251"), source);
        _ = Assert.NotNull(registration.LastConflict);
        MdnsRuntime.DispatchForTest(bytes, 14, IPAddress.Parse("224.0.0.251"), source);
        Assert.True(registration.Conflict);
        Assert.NotNull(registration.Failure);
    }

    [Fact]
    public async Task DelayedCrossAdapterAddressProbeDoesNotRejectStartingScopedRegistration()
    {
        IPAddress first = new(IPAddress.Parse("fe80::140").GetAddressBytes(), 15);
        IPAddress second = new(IPAddress.Parse("fe80::141").GetAddressBytes(), 16);
        using FakeTransport fake = new(new MdnsAddress("one", 15, first), new MdnsAddress("two", 16, second));
        string host = "probe-" + Guid.NewGuid().ToString("N")[..6];
        MdnsPublication firstPublication = Publication(host);
        MdnsPublication secondPublication = firstPublication with { InstanceName = "other-" + host,
            ServiceType = "_otherfake" };
        await using MdnsRegistration existing = await MdnsRuntime.RegisterAsync(firstPublication,
            new MdnsScope("one", null, [first]), NullLogger.Instance);
        Assert.Null(existing.Failure);
        fake.HoldProbeDelays = true;
        Task<MdnsRegistration> pending = MdnsRuntime.RegisterAsync(secondPublication,
            new MdnsScope("two", null, [second]), NullLogger.Instance);
        await Until(() => fake.Snapshot().Any(packet => packet.Channel.InterfaceIndex == 16 &&
            DnsCodec.TryRead(packet.Bytes, out DnsMessage? message) &&
            !message!.Authorities.IsEmpty));
        DnsRecord address = Assert.Single(MdnsEngine.CreateRecords(firstPublication, [first])
            .Where(record => record.Type == DnsTypes.Aaaa));
        byte[] delayed = DnsCodec.Write(new DnsMessage { Authorities = [address] });
        MdnsRuntime.RememberTransmission(first, delayed, fake.Now);
        fake.AdvanceClock(TimeSpan.FromSeconds(3));
        Assert.False(MdnsRuntime.IsOwnPacket(new IPEndPoint(new IPAddress(first.GetAddressBytes(), 16), 5353),
            delayed, [first, second], fake.Now));
        MdnsRuntime.DispatchForTest(delayed, 16, IPAddress.Parse("ff02::fb"),
            new IPEndPoint(new IPAddress(first.GetAddressBytes(), 16), 5353));
        for (int i = 0; i < 4 && !pending.IsCompleted; i++)
        {
            fake.Advance(TimeSpan.FromSeconds(1));
            await Task.Delay(10);
        }
        await using MdnsRegistration starting = await pending.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Null(starting.Failure);
        Assert.True(starting.Active);
        Assert.Null(existing.LastConflict);
    }

    [Fact]
    public async Task LocalSourceDoesNotExcuseAnAddressOutsideCurrentScopedSet()
    {
        IPAddress sourceAddress = IPAddress.Parse("192.0.2.151");
        IPAddress publishedAddress = IPAddress.Parse("192.0.2.152");
        using FakeTransport fake = new(new MdnsAddress("same", 17, sourceAddress),
            new MdnsAddress("same", 17, publishedAddress));
        MdnsPublication publication = Publication("narrow-" + Guid.NewGuid().ToString("N")[..6]);
        await using MdnsRegistration registration = await MdnsRuntime.RegisterAsync(publication,
            new MdnsScope("same", null, [publishedAddress]), NullLogger.Instance);
        Assert.Null(registration.Failure);
        fake.Advance(TimeSpan.FromSeconds(3));
        DnsRecord unpublished = Assert.Single(MdnsEngine.CreateRecords(publication, [sourceAddress])
            .Where(record => record.Type == DnsTypes.A));
        byte[] bytes = DnsCodec.Write(new DnsMessage { Flags = 0x8400, Answers = [unpublished] });
        IPEndPoint source = new(sourceAddress, 5353);
        MdnsRuntime.DispatchForTest(bytes, 17, IPAddress.Parse("224.0.0.251"), source);
        _ = Assert.NotNull(registration.LastConflict);
        MdnsRuntime.DispatchForTest(bytes, 17, IPAddress.Parse("224.0.0.251"), source);
        Assert.True(registration.Conflict);
    }

    [Fact]
    public async Task RejectedLocalRegistrationDoesNotOwnItsAddressForConflictFiltering()
    {
        IPAddress first = IPAddress.Parse("192.0.2.161");
        IPAddress second = IPAddress.Parse("192.0.2.162");
        using FakeTransport fake = new(new MdnsAddress("same", 18, first),
            new MdnsAddress("same", 18, second));
        string host = "rejected-" + Guid.NewGuid().ToString("N")[..6];
        MdnsPublication firstPublication = Publication(host);
        MdnsPublication rejectedPublication = firstPublication with { InstanceName = "other-" + host,
            ServiceType = "_otherfake" };
        await using MdnsRegistration active = await MdnsRuntime.RegisterAsync(firstPublication,
            new MdnsScope("same", null, [first]), NullLogger.Instance);
        await using MdnsRegistration rejected = await MdnsRuntime.RegisterAsync(rejectedPublication,
            new MdnsScope("same", null, [second]), NullLogger.Instance);
        Assert.Null(active.Failure);
        Assert.NotNull(rejected.Failure);
        fake.Advance(TimeSpan.FromSeconds(3));
        DnsRecord address = Assert.Single(MdnsEngine.CreateRecords(rejectedPublication, [second])
            .Where(record => record.Type == DnsTypes.A));
        byte[] bytes = DnsCodec.Write(new DnsMessage { Flags = 0x8400, Answers = [address] });
        IPEndPoint source = new(first, 5353);
        MdnsRuntime.DispatchForTest(bytes, 18, IPAddress.Parse("224.0.0.251"), source);
        _ = Assert.NotNull(active.LastConflict);
        MdnsRuntime.DispatchForTest(bytes, 18, IPAddress.Parse("224.0.0.251"), source);
        Assert.True(active.Conflict);
    }

    [Fact]
    public async Task EchoAcrossAdaptersIsOwnButDifferentLocalPacketIsAConflict()
    {
        IPAddress first = IPAddress.Parse("192.0.2.30");
        IPAddress second = IPAddress.Parse("198.51.100.31");
        using FakeTransport fake = new(new MdnsAddress("one", 1, first), new MdnsAddress("two", 2, second));
        MdnsPublication publication = Publication("echo-" + Guid.NewGuid().ToString("N")[..6]);
        await using MdnsRegistration registration = await MdnsRuntime.RegisterAsync(publication,
            new MdnsScope(), NullLogger.Instance);
        Assert.Null(registration.Failure);
        byte[] own = fake.Snapshot().First(packet => packet.Channel.InterfaceIndex == 1 &&
            DnsCodec.TryRead(packet.Bytes, out DnsMessage? message) && message!.IsResponse).Bytes;
        MdnsRuntime.DispatchForTest(own, 2, IPAddress.Parse("224.0.0.251"), new IPEndPoint(first, 5353));
        Assert.Null(registration.LastConflict);
        byte[] different = ConflictingResponse(publication, IPAddress.Parse("203.0.113.5"));
        MdnsRuntime.DispatchForTest(different, 1, IPAddress.Parse("224.0.0.251"), new IPEndPoint(first, 5353));
        _ = Assert.NotNull(registration.LastConflict);
        MdnsRuntime.DispatchForTest(different, 1, IPAddress.Parse("224.0.0.251"), new IPEndPoint(first, 5353));
        Assert.True(registration.Conflict);
        Assert.NotNull(registration.Failure);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RemoteConflictOnEitherAdapterRecoversOnlyAfterQuietCooldown(bool secondPacketOnOtherAdapter)
    {
        IPAddress first = IPAddress.Parse("192.0.2.40");
        IPAddress second = IPAddress.Parse("198.51.100.41");
        using FakeTransport fake = new(new MdnsAddress("one", 1, first), new MdnsAddress("two", 2, second));
        MdnsPublication publication = Publication("recover-" + Guid.NewGuid().ToString("N")[..6]);
        await using MdnsRegistration registration = await MdnsRuntime.RegisterAsync(publication,
            new MdnsScope(), NullLogger.Instance);
        Assert.Null(registration.Failure);
        int probesBefore = fake.Snapshot().Count(packet => DnsCodec.TryRead(packet.Bytes, out DnsMessage? message) &&
            !message!.IsResponse && !message.Authorities.IsEmpty && packet.Channel.InterfaceIndex == 1);
        byte[] conflict = ConflictingResponse(publication, IPAddress.Parse("203.0.113.9"));
        IPEndPoint remote = new(IPAddress.Parse("203.0.113.9"), 5353);
        MdnsRuntime.DispatchForTest(conflict, 1, IPAddress.Parse("224.0.0.251"), remote);
        MdnsRuntime.DispatchForTest(conflict, secondPacketOnOtherAdapter ? 2 : 1,
            IPAddress.Parse("224.0.0.251"), remote);
        Assert.False(registration.Active);
        Assert.NotNull(registration.Failure);
        await Until(() => registration.Recovering);
        fake.Advance(TimeSpan.FromSeconds(9));
        Assert.False(registration.Active);
        MdnsRuntime.DispatchForTest(conflict, 2, IPAddress.Parse("224.0.0.251"), remote);
        fake.Advance(TimeSpan.FromSeconds(2));
        Assert.False(registration.Active);
        await Task.Delay(50);
        fake.Advance(TimeSpan.FromSeconds(9));
        await Until(() => registration.Active);
        Assert.Null(registration.Failure);
        Assert.Equal(probesBefore + 3, fake.Snapshot().Count(packet => DnsCodec.TryRead(packet.Bytes,
            out DnsMessage? message) && !message!.IsResponse && !message.Authorities.IsEmpty &&
            packet.Channel.InterfaceIndex == 1));
    }

    [Fact]
    public async Task SeparateScopedRegistrationsIgnoreCrossAdapterEchoOfSharedHost()
    {
        IPAddress first = IPAddress.Parse("192.0.2.70");
        IPAddress second = IPAddress.Parse("198.51.100.71");
        using FakeTransport fake = new(new MdnsAddress("one", 1, first), new MdnsAddress("two", 2, second));
        string host = "cross-" + Guid.NewGuid().ToString("N")[..6];
        MdnsPublication publication = Publication(host);
        await using MdnsRegistration one = await MdnsRuntime.RegisterAsync(publication,
            new MdnsScope("one", first), NullLogger.Instance);
        await using MdnsRegistration two = await MdnsRuntime.RegisterAsync(publication with
        { InstanceName = "other-" + host, ServiceType = "_otherfake" },
            new MdnsScope("two", second), NullLogger.Instance);
        Assert.Null(one.Failure);
        Assert.Null(two.Failure);
        byte[] sent = fake.Snapshot().First(packet => packet.Channel.InterfaceIndex == 1 &&
            DnsCodec.TryRead(packet.Bytes, out DnsMessage? message) && message!.IsResponse).Bytes;
        Assert.True(DnsCodec.TryRead(sent, out DnsMessage? decoded));
        Assert.True(MdnsEngine.HasConflict(decoded!, MdnsEngine.CreateRecords(two.Publication, [second])));
        MdnsRuntime.DispatchForTest(sent, 2, IPAddress.Parse("224.0.0.251"), new IPEndPoint(first, 5353));
        Assert.Null(two.LastConflict);
        Assert.Null(two.Failure);
    }

    [Theory]
    [InlineData("v4", "v6")]
    [InlineData("v6", "v4")]
    [InlineData("both", "v4")]
    [InlineData("v4", "both")]
    public async Task ExplicitHostSetsRejectDifferentEffectiveSetsInEitherOrder(string firstSet, string secondSet)
    {
        IPAddress ipv4 = IPAddress.Parse("192.0.2.80");
        IPAddress ipv6 = new(IPAddress.Parse("fe80::80").GetAddressBytes(), 8);
        using FakeTransport fake = new(new MdnsAddress("same", 8, ipv4), new MdnsAddress("same", 8, ipv6));
        IPAddress[] Set(string name) => name switch
        {
            "v4" => [ipv4],
            "v6" => [ipv6],
            _ => [ipv4, ipv6]
        };
        string host = "sets-" + Guid.NewGuid().ToString("N")[..6];
        MdnsPublication first = Publication(host);
        MdnsPublication second = first with { InstanceName = "other-" + host, ServiceType = "_otherfake" };
        await using MdnsRegistration one = await MdnsRuntime.RegisterAsync(first,
            new MdnsScope("same", null, Set(firstSet)), NullLogger.Instance);
        await using MdnsRegistration two = await MdnsRuntime.RegisterAsync(second,
            new MdnsScope("same", null, Set(secondSet)), NullLogger.Instance);
        Assert.Null(one.Failure);
        Assert.NotNull(two.Failure);
    }

    [Fact]
    public async Task NewlyAvailableAddressWithdrawsLaterIncompatibleHostUntilSetsMatchAgain()
    {
        IPAddress first = IPAddress.Parse("192.0.2.82");
        IPAddress second = IPAddress.Parse("192.0.2.83");
        using FakeTransport fake = new(new MdnsAddress("same", 8, first));
        string host = "return-" + Guid.NewGuid().ToString("N")[..6];
        MdnsPublication publication = Publication(host);
        MdnsPublication sibling = publication with { InstanceName = "other-" + host,
            ServiceType = "_otherfake" };
        await using MdnsRegistration one = await MdnsRuntime.RegisterAsync(publication,
            new MdnsScope("same", null, [first, second]), NullLogger.Instance);
        await using MdnsRegistration two = await MdnsRuntime.RegisterAsync(sibling,
            new MdnsScope("same", null, [first]), NullLogger.Instance);
        Assert.Null(one.Failure);
        Assert.Null(two.Failure);
        int before = fake.Snapshot().Length;
        fake.Addresses.Add(new MdnsAddress("same", 8, second));
        MdnsRuntime.ReconcileForTest();
        Assert.True(one.Active);
        Assert.False(two.Active);
        Assert.NotNull(two.Failure);
        Assert.DoesNotContain(fake.Snapshot()[before..], packet => DnsCodec.TryRead(packet.Bytes,
            out DnsMessage? message) && message!.Answers.Any(record => record.Ttl > 0 &&
            record.Type == DnsTypes.Srv && record.Name.Contains("other-" + host, StringComparison.Ordinal)));
        _ = fake.Addresses.RemoveAll(address => address.Address.Equals(second));
        MdnsRuntime.ReconcileForTest();
        for (int i = 0; i < 5 && !two.Active; i++)
        {
            await Task.Delay(20);
            fake.Advance(TimeSpan.FromSeconds(1));
        }
        await Until(() => two.Active);
        Assert.Null(two.Failure);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task LegacyHostSubsetKeepsDirectionalRegistrationRule(bool fullFirst)
    {
        IPAddress first = IPAddress.Parse("192.0.2.90");
        IPAddress second = IPAddress.Parse("192.0.2.91");
        using FakeTransport fake = new(new MdnsAddress("same", 9, first), new MdnsAddress("same", 9, second));
        string host = "legacy-" + Guid.NewGuid().ToString("N")[..6];
        MdnsPublication publication = Publication(host);
        MdnsScope full = new("same");
        MdnsScope subset = new("same", first);
        await using MdnsRegistration one = await MdnsRuntime.RegisterAsync(publication,
            fullFirst ? full : subset, NullLogger.Instance);
        await using MdnsRegistration two = await MdnsRuntime.RegisterAsync(publication with
        { InstanceName = "other-" + host, ServiceType = "_otherfake" },
            fullFirst ? subset : full, NullLogger.Instance);
        Assert.Null(one.Failure);
        Assert.Equal(!fullFirst, two.Failure is not null);
    }

    [Fact]
    public async Task RemovingAddressSendsGoodbyeAndRefreshFromSurvivingChannel()
    {
        IPAddress first = IPAddress.Parse("192.0.2.50");
        IPAddress second = IPAddress.Parse("192.0.2.51");
        using FakeTransport fake = new(new MdnsAddress("one", 1, first), new MdnsAddress("one", 1, second));
        MdnsPublication publication = Publication("remove-" + Guid.NewGuid().ToString("N")[..6]);
        await using MdnsRegistration registration = await MdnsRuntime.RegisterAsync(publication,
            new MdnsScope("one", null, [first, second]), NullLogger.Instance);
        Assert.Null(registration.Failure);
        int before = fake.Snapshot().Length;
        _ = fake.Addresses.RemoveAll(address => address.Address.Equals(second));
        MdnsRuntime.ReconcileForTest();
        Assert.Null(registration.Failure);
        (MdnsAddress Channel, byte[] Bytes)[] sent = fake.Snapshot()[before..];
        Assert.All(sent, packet => Assert.Equal(first, packet.Channel.Address));
        Assert.Contains(sent, packet => DnsCodec.TryRead(packet.Bytes, out DnsMessage? message) &&
            message!.Answers.Any(record => record.Ttl == 0 && record.Data is AddressData data &&
                data.Address.Equals(second)));
        Assert.Contains(sent, packet => DnsCodec.TryRead(packet.Bytes, out DnsMessage? message) &&
            message!.Answers.Any(record => record.Ttl > 0 && record.Data is AddressData data &&
                data.Address.Equals(first)) && !message.Answers.Any(record => record.Data is AddressData data &&
                data.Address.Equals(second)));
    }

    [Fact]
    public async Task FakeDualStackAnswerContainsWholeSelectedSetAndDisjointHostIsRejected()
    {
        IPAddress ipv4 = IPAddress.Parse("192.0.2.60");
        IPAddress ipv6 = new(IPAddress.Parse("fe80::60").GetAddressBytes(), 6);
        IPAddress ula = IPAddress.Parse("fd00::60");
        using FakeTransport fake = new(new MdnsAddress("dual", 6, ipv4), new MdnsAddress("dual", 6, ipv6),
            new MdnsAddress("dual", 6, ula));
        MdnsPublication publication = Publication("dual-" + Guid.NewGuid().ToString("N")[..6]);
        await using MdnsRegistration full = await MdnsRuntime.RegisterAsync(publication,
            new MdnsScope("dual", null, [ipv4, ipv6, ula]), NullLogger.Instance);
        Assert.Null(full.Failure);
        MdnsPublication sibling = publication with { InstanceName = "sibling-" + publication.InstanceName,
            ServiceType = "_siblingtest" };
        await using MdnsRegistration disjoint = await MdnsRuntime.RegisterAsync(sibling,
            new MdnsScope("dual", null, [ipv6]), NullLogger.Instance);
        Assert.NotNull(disjoint.Failure);
        foreach (ushort type in new[] { DnsTypes.A, DnsTypes.Aaaa })
        {
            int before = fake.Snapshot().Length;
            DnsMessage query = new() { Questions = [new(publication.HostName + ".local.", type, 0x8001)] };
            MdnsRuntime.DispatchForTest(DnsCodec.Write(query), 6, ipv4,
                new IPEndPoint(IPAddress.Parse("203.0.113.60"), 5353));
            (MdnsAddress Channel, byte[] Bytes)[] sent = fake.Snapshot()[before..];
            Assert.Contains(sent, packet => DnsCodec.TryRead(packet.Bytes, out DnsMessage? message) &&
                (type == DnsTypes.A
                    ? message!.Answers.Count(record => record.Type == DnsTypes.A && record.Data is AddressData data &&
                        data.Address.Equals(ipv4)) == 1
                    : message!.Answers.Count(record => record.Type == DnsTypes.Aaaa) == 2 &&
                      message.Answers.Any(record => record.Data is AddressData data &&
                          data.Address.GetAddressBytes().SequenceEqual(ipv6.GetAddressBytes())) &&
                      message.Answers.Any(record => record.Data is AddressData data && data.Address.Equals(ula))));
        }
    }
    [Fact]
    public void TransmissionHistoryRequiresExactBytesLocalSourceAndMdnsPort()
    {
        IPAddress first = IPAddress.Parse("192.0.2.201");
        IPAddress second = IPAddress.Parse("192.0.2.202");
        byte[] bytes = [1, 2, 3, 4];
        DateTimeOffset now = DateTimeOffset.UtcNow;
        MdnsRuntime.RememberTransmission(first, bytes, now);
        Assert.True(MdnsRuntime.IsOwnPacket(new IPEndPoint(first, 5353), bytes,
            [first, second], now.AddMilliseconds(20)));
        Assert.False(MdnsRuntime.IsOwnPacket(new IPEndPoint(first, 5353), [1, 2, 3, 5],
            [first, second], now.AddMilliseconds(20)));
        Assert.False(MdnsRuntime.IsOwnPacket(new IPEndPoint(second, 5353), bytes,
            [first, second], now.AddMilliseconds(20)));
        Assert.False(MdnsRuntime.IsOwnPacket(new IPEndPoint(first, 5354), bytes,
            [first, second], now.AddMilliseconds(20)));
        Assert.False(MdnsRuntime.IsOwnPacket(new IPEndPoint(first, 5353), bytes,
            [first, second], now.AddSeconds(3)));
    }

    [Fact]
    public void TransmissionHistoryMatchesLinkLocalBytesAcrossScopeIds()
    {
        IPAddress sent = new(IPAddress.Parse("fe80::1234").GetAddressBytes(), 7);
        IPAddress received = new(IPAddress.Parse("fe80::1234").GetAddressBytes(), 9);
        byte[] bytes = [4, 3, 2, 1];
        DateTimeOffset now = DateTimeOffset.UtcNow;
        MdnsRuntime.RememberTransmission(sent, bytes, now);
        Assert.True(MdnsRuntime.IsOwnPacket(new IPEndPoint(received, 5353), bytes,
            [sent], now.AddMilliseconds(20)));
    }

    [Fact]
    public void SelectedAddressesTrackAvailableAdaptersAndWithdrawalRecords()
    {
        IPAddress first = IPAddress.Parse("192.0.2.21");
        IPAddress second = IPAddress.Parse("192.0.2.22");
        IPAddress otherAdapter = IPAddress.Parse("198.51.100.23");
        MdnsAddress[] available = [new("adapter-one", 1, first), new("adapter-one", 1, second),
            new("adapter-two", 2, otherAdapter)];
        MdnsScope scope = new("adapter-one", null, [second, first, second, otherAdapter]);
        IPAddress[] selected = [.. MdnsRuntime.Select(available, scope).Select(address => address.Address)];
        Assert.Equal([first, second], selected);
        MdnsPublication publication = new("selected", "_scope", "tcp", 49410,
            new Dictionary<string, string>());
        ImmutableArray<DnsRecord> oldRecords = MdnsEngine.CreateRecords(publication, selected);
        IPAddress[] remaining = [.. MdnsRuntime.Select(available.Where(address => !address.Address.Equals(second)), scope)
            .Select(address => address.Address)];
        ImmutableArray<DnsRecord> newRecords = MdnsEngine.CreateRecords(publication, remaining);
        ImmutableArray<DnsRecord> goodbyes = MdnsEngine.Goodbye(oldRecords, newRecords);
        _ = Assert.Single(goodbyes);
        Assert.Equal(second, Assert.IsType<AddressData>(goodbyes[0].Data).Address);
        Assert.Equal(0u, goodbyes[0].Ttl);
        Assert.Contains(newRecords, record => record.Data is AddressData data && data.Address.Equals(first));
        Assert.DoesNotContain(newRecords, record => record.Data is AddressData data && data.Address.Equals(second));
    }

    [Fact]
    public async Task ExplicitAddressSetAllowsEquivalentSharedHostAndRejectsMissingFamily()
    {
        (NetworkInterface Nic, IPAddress[] Addresses) selected = NetworkInterface.GetAllNetworkInterfaces()
            .Where(nic => nic.OperationalStatus == OperationalStatus.Up)
            .Select(nic => (Nic: nic, Addresses: nic.GetIPProperties().UnicastAddresses
                .Select(entry => entry.Address)
                .Where(address => address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                .DistinctBy(address => Convert.ToHexString(address.GetAddressBytes()))
                .Take(2).ToArray()))
            .FirstOrDefault(pair => pair.Addresses.Length == 2 &&
                pair.Addresses.Any(address => address.AddressFamily == AddressFamily.InterNetwork) &&
                pair.Addresses.Any(address => address.AddressFamily == AddressFamily.InterNetworkV6));
        if (selected.Nic is null)
        {
            throw Xunit.Sdk.SkipException.ForSkip("No active dual-stack interface is available.");
        }

        string suffix = Guid.NewGuid().ToString("N")[..6];
        string host = "sharedset-" + suffix;
        MdnsPublication first = new("first-" + suffix, "_setfirst" + suffix, "tcp", 49401,
            new Dictionary<string, string>(), host);
        MdnsPublication second = first with { InstanceName = "second-" + suffix,
            ServiceType = "_setsecond" + suffix, Port = 49402 };
        MdnsScope full = new(selected.Nic.Id, null, selected.Addresses);
        MdnsScope reversed = new(selected.Nic.Id, null, [.. selected.Addresses.Reverse()]);
        MdnsScope missingFamily = new(selected.Nic.Id, null,
            [selected.Addresses.First(address => address.AddressFamily == AddressFamily.InterNetwork)]);
        await using MdnsRegistration one = await MdnsRuntime.RegisterAsync(first, full, NullLogger.Instance);
        if (one.Failure is not null)
        {
            throw Xunit.Sdk.SkipException.ForSkip(one.Failure);
        }
        await using MdnsRegistration two = await MdnsRuntime.RegisterAsync(second, reversed, NullLogger.Instance);
        Assert.Null(two.Failure);
        await using MdnsRegistration three = await MdnsRuntime.RegisterAsync(second with
        { InstanceName = "third-" + suffix }, missingFamily, NullLogger.Instance);
        Assert.NotNull(three.Failure);
    }
}
