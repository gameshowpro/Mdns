namespace GameshowPro.Mdns.Tests;

public sealed class DnsCodecTests
{
    // Fixed wire fixture with an answer owner pointer and a PTR target suffix pointer.
    private static readonly byte[] s_compressedPtr = Convert.FromHexString(
        "000084000001000100000000" +
        "055F64656D6F045F746370056C6F63616C00" +
        "000C0001" +
        "C00C000C0001000000780007" +
        "0454657374C00C");

    [Fact]
    public void ReadsCompressedFixture()
    {
        Assert.True(DnsCodec.TryRead(s_compressedPtr, out DnsMessage? message));
        Assert.NotNull(message);
        Assert.True(message.IsResponse);
        Assert.Equal("_demo._tcp.local.", Assert.Single(message.Questions).Name);
        DnsRecord answer = Assert.Single(message.Answers);
        Assert.Equal("_demo._tcp.local.", answer.Name);
        Assert.Equal("Test._demo._tcp.local.", Assert.IsType<NameData>(answer.Data).Name);
        Assert.Equal((uint)120, answer.Ttl);
    }

    [Fact]
    public void ReadsIndependentAddressSrvAndTxtFixture()
    {
        byte[] packet = Convert.FromHexString(
            "000084000000000300000000" +
            "04686F7374056C6F63616C00" +
            "00018001000000780004C0000201" +
            "0454657374055F64656D6F045F746370056C6F63616C00" +
            "00218001000000780008000000002412C00C" +
            "C02600108001000000780005036B3DFF00");
        Assert.True(DnsCodec.TryRead(packet, out DnsMessage? parsed));
        Assert.NotNull(parsed);
        Assert.Equal(IPAddress.Parse("192.0.2.1"), Assert.IsType<AddressData>(parsed.Answers[0].Data).Address);
        SrvData srv = Assert.IsType<SrvData>(parsed.Answers[1].Data);
        Assert.Equal((ushort)9234, srv.Port);
        Assert.Equal("host.local.", srv.Target);
        Assert.Equal("Test._demo._tcp.local.", parsed.Answers[2].Name);
        TxtData txt = Assert.IsType<TxtData>(parsed.Answers[2].Data);
        Assert.Equal(new byte[] { 0x6b, 0x3d, 0xff }, txt.Strings[0]);
        Assert.Empty(txt.Strings[1]);
    }

    [Fact]
    public void ReadsLegacyCompressedUnicodeDnsSdPacket()
    {
        // Captured from Makaretu.Dns.New 3.1.2's writer; this test has no package dependency.
        byte[] packet = Convert.FromHexString(
            "000084000000000500000000055F64656D6F045F746370056C6F63616C00" +
            "000C000100000078000D0A436166C3A92E526F6F6DC00C" +
            "C0280021000100000078000D00000000241204686F7374C017" +
            "C0280010000100000078000F076B3D76616C7565066E756C3D0078" +
            "C04700010001000000780004C0000211" +
            "C047001C000100000078001020010DB8000000000000000000000017");
        Assert.True(DnsCodec.TryRead(packet, out DnsMessage? parsed));
        Assert.NotNull(parsed);
        Assert.Equal(5, parsed.Answers.Length);
        Assert.Equal("Café.Room", DnsNames.Labels(Assert.IsType<NameData>(parsed.Answers[0].Data).Name)[0]);
        Assert.Equal((ushort)9234, Assert.IsType<SrvData>(parsed.Answers[1].Data).Port);
        Assert.Equal(new byte[] { 0x6e, 0x75, 0x6c, 0x3d, 0x00, 0x78 }, Assert.IsType<TxtData>(parsed.Answers[2].Data).Strings[1]);
        Assert.Equal(IPAddress.Parse("192.0.2.17"), Assert.IsType<AddressData>(parsed.Answers[3].Data).Address);
        Assert.Equal(IPAddress.Parse("2001:db8::17"), Assert.IsType<AddressData>(parsed.Answers[4].Data).Address);
    }

    [Fact]
    public void RoundTripsUsedRecordTypesAndBinaryTxt()
    {
        const string Service = "_soundling._tcp.local.";
        const string Instance = "Living\\. Room._soundling._tcp.local.";
        const string Host = "unit.local.";
        ImmutableArray<DnsRecord> records = ImmutableArray.Create(
            new DnsRecord(Service, DnsTypes.Ptr, 1, 4500, new NameData(Instance)),
            new DnsRecord(Instance, DnsTypes.Srv, 0x8001, 120, new SrvData(0, 0, 9234, Host)),
            new DnsRecord(Instance, DnsTypes.Txt, 0x8001, 120,
                new TxtData([[0, 255, 65], [], [0x6b, 0x3d, 0x80]])),
            new DnsRecord(Host, DnsTypes.A, 0x8001, 120, new AddressData(IPAddress.Parse("192.0.2.17"))),
            new DnsRecord(Host, DnsTypes.Aaaa, 0x8001, 120, new AddressData(IPAddress.Parse("2001:db8::17"))),
            new DnsRecord(Host, DnsTypes.Nsec, 0x8001, 120, new NsecData(Host, [DnsTypes.A, DnsTypes.Aaaa, DnsTypes.Srv])),
            new DnsRecord(Host, 65000, 1, 120, new UnknownData([0, 255, 4, 3])));
        DnsMessage original = new()
        {
            Flags = 0x8400,
            Questions = [new DnsQuestion(Service, DnsTypes.Ptr)],
            Answers = records
        };
        byte[] wire = DnsCodec.Write(original);
        Assert.True(DnsCodec.TryRead(wire, out DnsMessage? parsed));
        Assert.NotNull(parsed);
        Assert.Equal(records.Length, parsed.Answers.Length);
        for (int i = 0; i < records.Length; i++)
        {
            Assert.True(DnsRecords.Equivalent(records[i], parsed.Answers[i]));
        }

        Assert.True(parsed.Answers[1].CacheFlush);
        Assert.Equal((ushort)1, parsed.Answers[1].BaseClass);
        Assert.Equal(new byte[] { 0, 255, 65 }, Assert.IsType<TxtData>(parsed.Answers[2].Data).Strings[0]);
        Assert.Equal(new byte[] { 0, 255, 4, 3 }, Assert.IsType<UnknownData>(parsed.Answers[^1].Data).Bytes);
    }

    [Fact]
    public void EveryTruncatedPrefixIsRejected()
    {
        for (int length = 0; length < s_compressedPtr.Length; length++)
        {
            Assert.False(DnsCodec.TryRead(s_compressedPtr.AsSpan(0, length), out _));
        }
    }

    [Fact]
    public void RejectsInvalidCompressionAndRdata()
    {
        // One question, name pointer to itself; forward pointer; pointer beyond packet.
        byte[] header = Convert.FromHexString("000000000001000000000000");
        foreach (string? pointer in new[] { "C00C", "C00E", "C0FF" })
        {
            byte[] bytes = [.. header, .. Convert.FromHexString(pointer + "00010001")];
            Assert.False(DnsCodec.TryRead(bytes, out _));
        }
        byte[] badPtrLength = (byte[])s_compressedPtr.Clone();
        badPtrLength[^9] = 0;
        badPtrLength[^8] = 6;
        Assert.False(DnsCodec.TryRead(badPtrLength, out _));
        byte[] badTxt = DnsCodec.Write(new DnsMessage { Answers = [new DnsRecord("x.local.", DnsTypes.Txt, 1, 1, new TxtData([[1, 2]]))] });
        badTxt[^3] = 3;
        Assert.False(DnsCodec.TryRead(badTxt, out _));
        byte[] badNsec = DnsCodec.Write(new DnsMessage { Answers = [new DnsRecord("x.local.", DnsTypes.Nsec, 1, 1, new NsecData("x.local.", [DnsTypes.A]))] });
        badNsec[^2] = 33;
        Assert.False(DnsCodec.TryRead(badNsec, out _));
    }

    [Fact]
    public void NamesAndEquivalentRecordsRespectDnsSemantics()
    {
        Assert.Equal("Living\\. Room._demo.local.", DnsNames.FromLabels("Living. Room", "_demo", "local"));
        Assert.Equal("Living. Room", DnsNames.Labels("Living\\. Room._demo.local.")[0]);
        Assert.True(DnsNames.Equals("HOST.Local", "host.local."));
        Assert.False(DnsNames.Equals("Étage.local.", "étage.local."));
        DnsRecord a = new("HOST.Local", DnsTypes.A, 0x8001, 1, new AddressData(IPAddress.Parse("192.0.2.1")));
        DnsRecord b = new("host.local.", DnsTypes.A, 1, 500, new AddressData(IPAddress.Parse("192.0.2.1")));
        Assert.True(DnsRecords.Equivalent(a, b));
        DnsRecord scoped = new("host.local.", DnsTypes.Aaaa, 0x8001, 120,
            new AddressData(new IPAddress(IPAddress.Parse("fe80::1").GetAddressBytes(), 7)));
        DnsRecord unscoped = new("HOST.LOCAL", DnsTypes.Aaaa, 1, 1,
            new AddressData(IPAddress.Parse("fe80::1")));
        Assert.True(DnsRecords.Equivalent(scoped, unscoped));
    }

    [Fact]
    public void FuzzInputNeverThrowsAndOnlyAcceptsBoundedPackets()
    {
        Random random = new(20261028);
        for (int i = 0; i < 2000; i++)
        {
            byte[] packet = new byte[random.Next(0, 300)];
            random.NextBytes(packet);
            _ = DnsCodec.TryRead(packet, out _);
        }
        Assert.False(DnsCodec.TryRead(new byte[65536], out _));
    }

    [Fact]
    public void MutatingValidWirePacketsNeverEscapesTryRead()
    {
        Random random = new(6762);
        for (int i = 0; i < 5000; i++)
        {
            byte[] packet = (byte[])s_compressedPtr.Clone();
            int mutations = random.Next(1, 5);
            for (int j = 0; j < mutations; j++)
            {
                packet[random.Next(packet.Length)] = (byte)random.Next(256);
            }

            if (random.Next(4) == 0)
            {
                Array.Resize(ref packet, random.Next(packet.Length + 1));
            }

            if (DnsCodec.TryRead(packet, out DnsMessage? parsed))
            {
                Assert.NotNull(parsed);
                Assert.True(DnsCodec.TryRead(DnsCodec.Write(parsed), out _));
            }
        }
    }

    [Fact]
    public void UnicodeInstanceAndOpaqueTxtRoundTrip()
    {
        DnsMessage message = new()
        {
            Answers =
            [
                new DnsRecord("Café\\. Room._demo._tcp.local.", DnsTypes.Txt, 1, 120,
                    new TxtData([[0x6b, 0x3d, 0xff, 0x00]]))
            ]
        };
        Assert.True(DnsCodec.TryRead(DnsCodec.Write(message), out DnsMessage? parsed));
        Assert.NotNull(parsed);
        Assert.Equal("Café. Room", DnsNames.Labels(parsed.Answers[0].Name)[0]);
        Assert.Equal(new byte[] { 0x6b, 0x3d, 0xff, 0x00 }, Assert.IsType<TxtData>(parsed.Answers[0].Data).Strings[0]);
    }
}
