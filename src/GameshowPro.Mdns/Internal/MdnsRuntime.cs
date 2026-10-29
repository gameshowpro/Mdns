namespace GameshowPro.Mdns.Internal;

internal sealed class MdnsRegistration : IAsyncDisposable
{
    internal MdnsRegistration(MdnsPublication publication, MdnsScope scope, ILogger logger)
        => (Publication, Scope, Logger) = (publication, scope, logger);
    internal MdnsPublication Publication { get; }
    internal MdnsScope Scope { get; }
    internal ILogger Logger { get; }
    internal ImmutableArray<DnsRecord> Records { get; set; } = [];
    internal bool Active { get; set; }
    internal bool EverActive { get; set; }
    internal bool Disposed { get; set; }
    internal bool Conflict { get; set; }
    internal DateTimeOffset? LastConflict { get; set; }
    internal bool Recovering { get; set; }
    public string? Failure { get; internal set; }
    public ValueTask DisposeAsync() => MdnsRuntime.RemoveAsync(this);
}

internal sealed class MdnsBrowseSubscription : IAsyncDisposable
{
    internal MdnsBrowseSubscription(IEnumerable<string> names, Action<MdnsPacket> callback, ILogger logger)
        => (Names, Callback, Logger) = (names.Select(DnsNames.Canonical).ToImmutableArray(), callback, logger);
    internal ImmutableArray<string> Names { get; }
    internal Action<MdnsPacket> Callback { get; }
    internal ILogger Logger { get; }
    internal bool Disposed { get; set; }
    internal Dictionary<string, DateTimeOffset> Followups { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string? Failure { get; internal set; }
    public ValueTask DisposeAsync() => MdnsRuntime.RemoveAsync(this);
}

/// <summary>One process owner for mDNS sockets, publications, queries, and responses.</summary>
internal static class MdnsRuntime
{
    private static readonly object s_gate = new();
    // These mutable collections are owned by the shared transport and accessed under s_gate.
    private static readonly List<MdnsRegistration> s_registrations = [];
    private static readonly List<MdnsBrowseSubscription> s_browsers = [];
    private static readonly Dictionary<string, MdnsChannel> s_channels = new(StringComparer.Ordinal);
    private static readonly SemaphoreSlim s_lifecycle = new(1, 1);
    private static readonly HashSet<Task> s_backgroundTasks = [];
    private static Socket? s_receive4, s_receive6;
    private static CancellationTokenSource? s_stop;
    private static Task? s_maintenance;
    private static long s_generation;
    private static long s_runtimeGeneration;
    private static readonly Action<ILogger, IPAddress, Exception?> s_logInterfaceUnavailable =
        LoggerMessage.Define<IPAddress>(LogLevel.Warning, new EventId(1, nameof(s_logInterfaceUnavailable)),
            "mDNS interface {Address} is unavailable");
    private static readonly Action<ILogger, AddressFamily, Exception?> s_logReceiveFailure =
        LoggerMessage.Define<AddressFamily>(LogLevel.Warning, new EventId(2, nameof(s_logReceiveFailure)),
            "mDNS receive failed on {Family}");
    private static readonly Action<ILogger, AddressFamily, Exception?> s_logBrowseReceiveFailure =
        LoggerMessage.Define<AddressFamily>(LogLevel.Warning, new EventId(3, nameof(s_logBrowseReceiveFailure)),
            "mDNS browse receive failed on {Family}");
    private static readonly Action<ILogger, Exception?> s_logBrowseCallbackFailure =
        LoggerMessage.Define(LogLevel.Warning, new EventId(4, nameof(s_logBrowseCallbackFailure)),
            "mDNS browse callback failed");
    private static readonly Action<ILogger, IPAddress, Exception?> s_logSendFailure =
        LoggerMessage.Define<IPAddress>(LogLevel.Warning, new EventId(5, nameof(s_logSendFailure)),
            "mDNS send failed on {Address}");
    private static readonly Action<ILogger, IPAddress, Exception?> s_logBrowseSendFailure =
        LoggerMessage.Define<IPAddress>(LogLevel.Warning, new EventId(6, nameof(s_logBrowseSendFailure)),
            "mDNS browse query send failed on {Address}");

    public static async Task<MdnsRegistration> RegisterAsync(MdnsPublication publication, MdnsScope scope,
        ILogger logger, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publication);
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(logger);
        cancellationToken.ThrowIfCancellationRequested();
        // Validate DNS names and TXT lengths before the object enters shared state.
        ImmutableArray<DnsRecord> validation = MdnsEngine.CreateRecords(publication, [IPAddress.Loopback]);
        _ = DnsCodec.Write(new DnsMessage { Flags = 0x8400, Answers = validation });
        MdnsRegistration registration = new(publication, scope, logger);
        await s_lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (s_gate)
            {
                s_registrations.Add(registration);
                ReconcileLocked();
                if (registration.Failure is null && s_channels.Values.Any(channel =>
                    ScopeIncludesChannel(scope, channel) && s_registrations.Any(other => other != registration &&
                    other.Active && ScopeIncludesChannel(other.Scope, channel) &&
                    MdnsEngine.HasConflict(new DnsMessage
                    {
                        Answers = RecordsForInterface(registration, channel)
                    }, RecordsForInterface(other, channel)))))
                {
                    registration.Failure = "The selected mDNS service or host name is already owned by another local registration.";
                }
            }
        }
        catch
        {
            lock (s_gate)
            {
                _ = s_registrations.Remove(registration);
            }

            await ReconcileOrShutdown().ConfigureAwait(false);
            throw;
        }
        finally { _ = s_lifecycle.Release(); }
        if (registration.Failure is not null)
        {
            return registration;
        }

        try
        {
            // Probe unique names before exposing the registration to the responder.
            for (int i = 0; i < 3; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                Probe(registration);
                await Task.Delay(250, cancellationToken).ConfigureAwait(false);
                if (registration.Failure is not null)
                {
                    return registration;
                }
            }
            lock (s_gate)
            {
                if (registration.Disposed || registration.Failure is not null)
                {
                    return registration;
                }

                registration.Active = registration.EverActive = true;
            }
            Announce(registration);
            // The caller token only governs startup; registration disposal guards the later announcement.
            Track(Task.Run(async () =>
            {
                await Task.Delay(1000).ConfigureAwait(false);
                if (!registration.Disposed && registration.Failure is null)
                {
                    Announce(registration);
                }
            }, CancellationToken.None));
        }
        catch (OperationCanceledException)
        {
            await registration.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        return registration;
    }

    public static async Task<MdnsBrowseSubscription> BrowseAsync(IEnumerable<string> fullyQualifiedServiceNames,
        Action<MdnsPacket> onPacket, ILogger logger, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(fullyQualifiedServiceNames);
        ArgumentNullException.ThrowIfNull(onPacket);
        cancellationToken.ThrowIfCancellationRequested();
        MdnsBrowseSubscription browser = new(fullyQualifiedServiceNames, onPacket, logger);
        await s_lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (s_gate)
            {
                s_browsers.Add(browser);
                ReconcileLocked();
                if (s_channels.Count == 0)
                {
                    browser.Failure = "No eligible mDNS network interface is available.";
                }
            }
        }
        finally { _ = s_lifecycle.Release(); }
        if (browser.Failure is null)
        {
            Query(browser);
        }

        return browser;
    }

    internal static async ValueTask RemoveAsync(MdnsRegistration registration)
    {
        await s_lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            List<(MdnsChannel Channel, ImmutableArray<DnsRecord> Records)> goodbyes;
            lock (s_gate)
            {
                if (registration.Disposed)
                {
                    return;
                }

                registration.Disposed = true;
                _ = s_registrations.Remove(registration);
                s_generation++;
                goodbyes = [.. s_channels.Values.Where(c => ScopeIncludesChannel(registration.Scope, c))
                    .Select(channel => (channel, MdnsEngine.Goodbye(
                        RecordsForInterface(registration, channel),
                        s_registrations.Where(r => r.Active && ScopeIncludesChannel(r.Scope, channel))
                            .SelectMany(r => RecordsForInterface(r, channel)))))];
            }
            if (registration.Active)
            {
                foreach ((MdnsChannel channel, ImmutableArray<DnsRecord> records) in goodbyes)
                {
                    if (!records.IsEmpty)
                    {
                        SendMessage(channel, new DnsMessage { Flags = 0x8400, Answers = records }, null);
                    }
                }
            }

            await ReconcileOrShutdown().ConfigureAwait(false);
        }
        finally { _ = s_lifecycle.Release(); }
    }

    internal static async ValueTask RemoveAsync(MdnsBrowseSubscription browser)
    {
        await s_lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            lock (s_gate)
            {
                browser.Disposed = true;
                _ = s_browsers.Remove(browser);
            }
            await ReconcileOrShutdown().ConfigureAwait(false);
        }
        finally { _ = s_lifecycle.Release(); }
    }

    private static async Task ReconcileOrShutdown()
    {
        Task[] tasks;
        CancellationTokenSource? stop;
        lock (s_gate)
        {
            if (s_registrations.Count != 0 || s_browsers.Count != 0)
            {
                ReconcileLocked();
                return;
            }
            s_runtimeGeneration++;
            s_generation++;
            stop = s_stop;
            stop?.Cancel();
            foreach (MdnsChannel channel in s_channels.Values)
            {
                channel.Dispose();
            }

            s_channels.Clear();
            s_receive4?.Dispose(); s_receive6?.Dispose();
            s_receive4 = s_receive6 = null;
            s_stop = null;
            tasks = [.. s_backgroundTasks];
        }
        try { await Task.WhenAll(tasks).ConfigureAwait(false); }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        finally { stop?.Dispose(); }
    }

    private static void Track(Task task)
    {
        lock (s_gate)
        {
            _ = s_backgroundTasks.Add(task);
        }

        _ = task.ContinueWith(completed =>
        {
            lock (s_gate)
            {
                _ = s_backgroundTasks.Remove(completed);
            }
        }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    private static void EnsureReceiversLocked()
    {
        if (s_stop is not null)
        {
            return;
        }

        long generation = ++s_runtimeGeneration;
        s_stop = new CancellationTokenSource();
        s_receive4 = OpenReceiver(AddressFamily.InterNetwork);
        s_receive6 = OpenReceiver(AddressFamily.InterNetworkV6);
        if (s_receive4 is not null)
        {
            Track(ReceiveLoop(s_receive4, generation, s_stop.Token));
        }

        if (s_receive6 is not null)
        {
            Track(ReceiveLoop(s_receive6, generation, s_stop.Token));
        }

        s_maintenance = Maintenance(generation, s_stop.Token);
        Track(s_maintenance);
    }

    private static Socket? OpenReceiver(AddressFamily family)
    {
        Socket? socket = null;
        try
        {
            socket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            socket.SetSocketOption(family == AddressFamily.InterNetwork ? SocketOptionLevel.IP : SocketOptionLevel.IPv6,
                SocketOptionName.PacketInformation, true);
            socket.SetSocketOption(family == AddressFamily.InterNetwork ? SocketOptionLevel.IP : SocketOptionLevel.IPv6,
                SocketOptionName.MulticastLoopback, true);
            if (family == AddressFamily.InterNetworkV6)
            {
                socket.DualMode = false;
            }

            socket.Bind(new IPEndPoint(family == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 5353));
            return socket;
        }
        catch (Exception) { socket?.Dispose(); return null; }
    }

    private static void ReconcileLocked()
    {
        // The process owns the transport for its lifetime. Keeping the receivers alive
        // avoids racing a closing socket against a registration created immediately after disposal.
        if (s_registrations.Count == 0 && s_browsers.Count == 0)
        {
            return;
        }

        EnsureReceiversLocked();
        List<MdnsAddress> available = EnumerateAddresses();
        foreach (MdnsRegistration registration in s_registrations)
        {
            MdnsAddress[] selected = [.. Select(available, registration.Scope)];
            if (selected.Length == 0)
            {
                registration.Failure = "Selected mDNS interface or address is unavailable.";
                registration.Records = [];
                registration.Active = false;
            }
            else if (!registration.Conflict)
            {
                registration.Failure = null;
                registration.Records = MdnsEngine.CreateRecords(registration.Publication,
                    selected.Select(x => x.Address).ToArray());
                if (registration.EverActive && !registration.Active && !registration.Recovering)
                {
                    registration.Recovering = true;
                    Track(Task.Run(() => Recover(registration)));
                }
            }
        }
        MdnsAddress[] desired = [.. s_registrations.SelectMany(r => Select(available, r.Scope))
            .Concat(s_browsers.Count > 0 ? available : [])
            .DistinctBy(x => x.Key)];
        foreach (string? old in s_channels.Keys.Except(desired.Select(x => x.Key)).ToArray())
        {
            s_channels[old].Dispose(); _ = s_channels.Remove(old);
        }
        foreach (MdnsAddress endpoint in desired)
        {
            if (s_channels.ContainsKey(endpoint.Key))
            {
                continue;
            }

            try
            {
                MdnsChannel channel = new(endpoint, endpoint.Address.AddressFamily == AddressFamily.InterNetwork
                    ? s_receive4 : s_receive6,
                    (socket, token) => ReceiveLoop(socket, s_runtimeGeneration, token), s_stop!.Token);
                s_channels.Add(endpoint.Key, channel);
                Track(channel.ReceiveTask);
                foreach (MdnsRegistration registration in s_registrations.Where(r => r.Active && r.Failure is null &&
                             ScopeIncludesChannel(r.Scope, channel)))
                {
                    SendMessage(channel, new DnsMessage
                    {
                        Flags = 0x8400,
                        Answers = RecordsForInterface(registration, channel)
                    }, null);
                }
            }
            catch (Exception ex)
            {
                foreach (MdnsRegistration registration in s_registrations.Where(r => Select(available, r.Scope).Any(x => x.Key == endpoint.Key)))
                {
                    s_logInterfaceUnavailable(registration.Logger, endpoint.Address, ex);
                }
            }
        }
        foreach (MdnsRegistration registration in s_registrations.Where(r => !r.Conflict && r.Failure is null))
        {
            if (!s_channels.Values.Any(channel => ScopeIncludesChannel(registration.Scope, channel)))
            {
                registration.Failure = "No usable mDNS socket is available for the selected scope.";
            }
        }

        foreach (MdnsBrowseSubscription browser in s_browsers)
        {
            browser.Failure = s_channels.Count == 0 ? "No eligible mDNS network interface is available." : null;
        }
    }

    private static List<MdnsAddress> EnumerateAddresses()
    {
        List<MdnsAddress> result = [];
        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up)
            {
                continue;
            }

            IPInterfaceProperties properties;
            try { properties = nic.GetIPProperties(); } catch { continue; }
            foreach (UnicastIPAddressInformation entry in properties.UnicastAddresses)
            {
                IPAddress address = entry.Address;
                if (address.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6) ||
                    address.IsIPv6LinkLocal && address.ScopeId == 0)
                {
                    continue;
                }

                int? index;
                try
                {
                    index = address.AddressFamily == AddressFamily.InterNetwork
                        ? properties.GetIPv4Properties()?.Index : properties.GetIPv6Properties()?.Index;
                }
                catch (NetworkInformationException) { continue; }
                if (index is > 0)
                {
                    result.Add(new(nic.Id, index.Value, address));
                }
            }
        }
        // Keep loopback available for an explicitly selected scope and for machines
        // whose only usable network is loopback.
        return result;
    }

    private static IEnumerable<MdnsAddress> Select(IEnumerable<MdnsAddress> available, MdnsScope scope)
    {
        MdnsAddress[] all = [.. available];
        IEnumerable<MdnsAddress> candidates = scope.NetworkInterfaceId is null && scope.LocalAddress is null &&
            all.Any(x => !IPAddress.IsLoopback(x.Address))
            ? all.Where(x => !IPAddress.IsLoopback(x.Address)) : all.AsEnumerable();
        return candidates.Where(x => (scope.NetworkInterfaceId is null ||
                string.Equals(scope.NetworkInterfaceId, x.InterfaceId, StringComparison.OrdinalIgnoreCase)) &&
            (scope.LocalAddress is null || scope.LocalAddress.Equals(x.Address)));
    }

    private static async Task Recover(MdnsRegistration registration)
    {
        try
        {
            for (int i = 0; i < 3; i++)
            {
                if (registration.Disposed || registration.Failure is not null)
                {
                    return;
                }

                Probe(registration);
                await Task.Delay(250).ConfigureAwait(false);
            }
            lock (s_gate)
            {
                if (registration.Disposed || registration.Failure is not null)
                {
                    return;
                }

                registration.Active = true;
            }
            Announce(registration);
        }
        catch (Exception ex) { registration.Failure = ex.Message; }
        finally { registration.Recovering = false; }
    }

    private static async Task Maintenance(long generation, CancellationToken cancellationToken)
    {
        using PeriodicTimer timer = new(TimeSpan.FromSeconds(10));
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                MdnsBrowseSubscription[] browsers;
                lock (s_gate)
                {
                    if (generation != s_runtimeGeneration)
                    {
                        break;
                    }

                    ReconcileLocked();
                    browsers = [.. s_browsers];
                }
                foreach (MdnsBrowseSubscription browser in browsers)
                {
                    Query(browser);
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    private static async Task ReceiveLoop(Socket socket, long generation, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[9000];
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                AddressFamily family = socket.AddressFamily;
                SocketReceiveMessageFromResult received = await socket.ReceiveMessageFromAsync(buffer, SocketFlags.None,
                    new IPEndPoint(family == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0),
                    cancellationToken).ConfigureAwait(false);
                if (received.RemoteEndPoint is not IPEndPoint source ||
                    !DnsCodec.TryRead(buffer.AsSpan(0, received.ReceivedBytes), out DnsMessage? decoded))
                {
                    continue;
                }

                if (generation == Volatile.Read(ref s_runtimeGeneration))
                {
                    Dispatch(decoded!, received.PacketInformation.Interface,
                        received.PacketInformation.Address, source);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) when (cancellationToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                ReportReceiveFailure(socket, ex);
                try { await Task.Delay(100, cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }
    }

    private static void ReportReceiveFailure(Socket socket, Exception exception)
    {
        lock (s_gate)
        {
            foreach (MdnsRegistration registration in s_registrations)
            {
                s_logReceiveFailure(registration.Logger, socket.AddressFamily, exception);
                if (registration.Scope.NetworkInterfaceId is not null || registration.Scope.LocalAddress is not null)
                {
                    bool affected = s_channels.Values.Any(c => c.UsesSocket(socket) &&
                        ScopeIncludesChannel(registration.Scope, c));
                    if (affected)
                    {
                        registration.Failure = exception.Message;
                    }
                }
            }
            foreach (MdnsBrowseSubscription browser in s_browsers)
            {
                s_logBrowseReceiveFailure(browser.Logger, socket.AddressFamily, exception);
            }
        }
    }

    private static void Dispatch(DnsMessage message, int interfaceIndex, IPAddress destination, IPEndPoint source)
    {
        if ((message.Flags & 0x780f) != 0 || message.IsResponse && source.Port != 5353)
        {
            return;
        }

        MdnsChannel[] channels;
        MdnsBrowseSubscription[] browsers;
        lock (s_gate)
        {
            channels = [.. s_channels.Values.Where(c => c.Address.InterfaceIndex == interfaceIndex &&
                (destination.Equals(c.Address.Address) || IsGroupDestination(destination, c.Group)))];
            if (channels.Length == 0)
            {
                return;
            }

            browsers = [.. s_browsers.Where(b => !b.Disposed)];
            if (message.IsResponse || source.Port == 5353 && !message.Authorities.IsEmpty)
            {
                foreach (MdnsRegistration registration in s_registrations.Where(r => !r.Disposed && r.Failure is null))
                {
                    if ((!registration.Active || message.IsResponse) &&
                        channels.Any(channel => ScopeIncludesChannel(registration.Scope, channel) &&
                        MdnsEngine.HasConflict(message, RecordsForInterface(registration, channel))))
                    {
                        DateTimeOffset now = DateTimeOffset.UtcNow;
                        if (registration.Active &&
                            (registration.LastConflict is null || now - registration.LastConflict > TimeSpan.FromSeconds(10)))
                        {
                            registration.LastConflict = now;
                            Announce(registration);
                        }
                        else
                        {
                            registration.Conflict = true;
                            registration.Active = false;
                            registration.Failure = "Another mDNS responder owns this service or host name.";
                        }
                    }
                }
            }
        }
        if (message.IsResponse)
        {
            MdnsPacket packet = new(message, interfaceIndex, destination, source.Address);
            foreach (MdnsBrowseSubscription browser in browsers)
            {
                try { browser.Callback(packet); }
                catch (Exception ex) { s_logBrowseCallbackFailure(browser.Logger, ex); }
                QueryFollowups(browser, channels[0], message);
            }
            return;
        }
        if (message.Questions.IsEmpty)
        {
            return;
        }

        foreach (MdnsChannel channel in channels)
        {
            if (source.Port != 5353) { Respond(channel, message, source); continue; }
            ImmutableArray<DnsQuestion> multicast = [.. message.Questions.Where(q => (q.Class & 0x8000) == 0)];
            ImmutableArray<DnsQuestion> unicast = [.. message.Questions.Where(q => (q.Class & 0x8000) != 0)];
            if (!multicast.IsEmpty)
            {
                Respond(channel, message with { Questions = multicast }, source);
            }

            if (!unicast.IsEmpty)
            {
                Respond(channel, message with { Questions = unicast }, source);
            }
        }
    }

    private static void Respond(MdnsChannel channel, DnsMessage message, IPEndPoint source)
    {
        MdnsRegistration[] registrations;
        lock (s_gate)
        {
            registrations = [.. s_registrations.Where(r => r.Active && r.Failure is null &&
            ScopeIncludesChannel(r.Scope, channel))];
        }

        ImmutableArray<DnsRecord> records = MdnsEngine.Query(message,
            registrations.SelectMany(r => RecordsForInterface(r, channel)),
            source.Port == 5353);
        if (records.IsEmpty)
        {
            return;
        }

        bool legacy = source.Port != 5353;
        bool unicast = legacy || message.Questions.Any(q => (q.Class & 0x8000) != 0);
        DnsMessage response = new()
        {
            Id = legacy ? message.Id : (ushort)0,
            Flags = 0x8400,
            Questions = legacy ? message.Questions : [],
            Answers = legacy ? [.. records.Select(r => r with
                { Ttl = Math.Min(r.Ttl, 10u), Class = r.BaseClass })] : records
        };
        long generation;
        lock (s_gate)
        {
            generation = s_generation;
        }

        bool truncated = (message.Flags & 0x0200) != 0;
        if (unicast && !truncated)
        {
            lock (s_gate)
            {
                if (s_generation == generation && registrations.All(r => r.Active && !r.Disposed))
                {
                    SendMessage(channel, response, source);
                }
            }
        }
        else
        {
            Track(Task.Run(async () =>
            {
                await Task.Delay(truncated ? Random.Shared.Next(400, 501) : Random.Shared.Next(20, 120))
                    .ConfigureAwait(false);
                lock (s_gate)
                {
                    if (s_generation == generation && registrations.All(r => r.Active && !r.Disposed))
                    {
                        SendMessage(channel, response, unicast ? source : null);
                    }
                }
            }));
        }
    }

    private static bool IsGroupDestination(IPAddress destination, IPAddress group) =>
        destination.AddressFamily == group.AddressFamily &&
        destination.GetAddressBytes().AsSpan().SequenceEqual(group.GetAddressBytes());

    private static void Probe(MdnsRegistration registration)
    {
        foreach (MdnsChannel channel in ChannelsFor(registration.Scope))
        {
            ImmutableArray<DnsRecord> owned = RecordsForInterface(registration, channel);
            ImmutableArray<DnsQuestion> questions = [.. owned.Where(r => r.CacheFlush)
                .Select(r => new DnsQuestion(r.Name, DnsTypes.Any)).DistinctBy(q => q.Name)];
            SendMessage(channel, new DnsMessage
            {
                Questions = questions,
                Authorities = [.. owned.Where(r => r.CacheFlush)]
            }, null);
        }
    }

    private static void Announce(MdnsRegistration registration)
    {
        lock (s_gate)
        {
            if (registration.Disposed || !registration.Active || registration.Failure is not null)
            {
                return;
            }

            foreach (MdnsChannel channel in ChannelsFor(registration.Scope))
            {
                SendMessage(channel, new DnsMessage
                {
                    Flags = 0x8400,
                    Answers = RecordsForInterface(registration, channel)
                }, null);
            }
        }
    }

    private static void Query(MdnsBrowseSubscription browser)
    {
        if (browser.Disposed)
        {
            return;
        }

        ImmutableArray<DnsQuestion> questions = [.. browser.Names.Select(n => new DnsQuestion(n, DnsTypes.Ptr))];
        MdnsChannel[] channels;
        lock (s_gate)
        {
            channels = [.. s_channels.Values];
        }

        foreach (MdnsChannel channel in channels)
        {
            SendMessage(channel, new DnsMessage { Questions = questions }, null);
        }
    }

    private static void QueryFollowups(MdnsBrowseSubscription browser, MdnsChannel channel, DnsMessage response)
    {
        ImmutableArray<DnsQuestion>.Builder questions = ImmutableArray.CreateBuilder<DnsQuestion>();
        foreach (DnsRecord record in response.Answers.Concat(response.Additionals))
        {
            if (record.Ttl == 0)
            {
                continue;
            }

            if (record.Type == DnsTypes.Ptr && record.Data is NameData instance &&
                browser.Names.Any(n => DnsNames.Equals(n, record.Name)))
            {
                questions.Add(new(instance.Name, DnsTypes.Srv));
                questions.Add(new(instance.Name, DnsTypes.Txt));
            }
            else if (record.Type == DnsTypes.Srv && record.Data is SrvData srv &&
                browser.Names.Any(n => IsInstanceOf(record.Name, n)))
            {
                questions.Add(new(srv.Target, DnsTypes.A));
                questions.Add(new(srv.Target, DnsTypes.Aaaa));
            }
        }
        DateTimeOffset now = DateTimeOffset.UtcNow;
        foreach (DnsQuestion question in questions.DistinctBy(q => (q.Name, q.Type)))
        {
            string key = $"{channel.Address.Key}|{question.Name}|{question.Type}";
            bool shouldSend;
            lock (s_gate)
            {
                shouldSend = !browser.Disposed &&
                    (!browser.Followups.TryGetValue(key, out DateTimeOffset last) || now - last > TimeSpan.FromSeconds(5));
                if (shouldSend)
                {
                    if (browser.Followups.Count >= 256)
                    {
                        _ = browser.Followups.Remove(browser.Followups.MinBy(p => p.Value).Key);
                    }

                    browser.Followups[key] = now;
                }
            }
            if (shouldSend)
            {
                SendMessage(channel, new DnsMessage { Questions = [question] }, null);
            }
        }
    }

    private static bool IsInstanceOf(string instanceName, string serviceName)
    {
        IReadOnlyList<string> instance = DnsNames.Labels(instanceName);
        IReadOnlyList<string> service = DnsNames.Labels(serviceName);
        return instance.Count == service.Count + 1 &&
            instance.Skip(1).Zip(service).All(pair =>
                string.Equals(pair.First, pair.Second, StringComparison.OrdinalIgnoreCase));
    }

    private static MdnsChannel[] ChannelsFor(MdnsScope scope)
    {
        lock (s_gate)
        {
            return [.. s_channels.Values.Where(x => ScopeIncludesChannel(scope, x))];
        }
    }

    private static bool ScopeIncludesChannel(MdnsScope scope, MdnsChannel channel)
        => Select(s_channels.Values.Select(c => c.Address), scope).Any(x => x.Key == channel.Address.Key);

    private static ImmutableArray<DnsRecord> RecordsForInterface(MdnsRegistration registration,
        MdnsChannel channel)
    {
        // Cache-flush address records form one RRset per host on an interface.
        IPAddress[] addresses = [.. Select(s_channels.Values.Select(c => c.Address), registration.Scope)
            .Where(x => string.Equals(x.InterfaceId, channel.Address.InterfaceId,
                StringComparison.OrdinalIgnoreCase))
            .Select(x => x.Address)];
        return MdnsEngine.CreateRecords(registration.Publication, addresses);
    }

    private static void SendMessage(MdnsChannel channel, DnsMessage message, IPEndPoint? destination)
    {
        // Keep datagrams under the conventional Ethernet mDNS payload. The codec writes
        // uncompressed names, so large catalogues are split into several responses.
        ImmutableArray<DnsRecord> records = message.Answers;
        if (records.Length == 0)
        {
            try { channel.Send(DnsCodec.Write(message), destination); }
            catch (Exception ex) { ReportSendFailure(channel, ex); }
            return;
        }
        ImmutableArray<DnsRecord>.Builder batch = ImmutableArray.CreateBuilder<DnsRecord>();
        foreach (DnsRecord record in records)
        {
            batch.Add(record);
            DnsMessage candidate = message with { Answers = batch.ToImmutable() };
            try
            {
                if (DnsCodec.Write(candidate).Length <= 1300)
                {
                    continue;
                }
            }
            catch (Exception ex) { ReportSendFailure(channel, ex); return; }
            batch.RemoveAt(batch.Count - 1);
            if (batch.Count > 0)
            {
                TrySend(channel, message with { Answers = batch.ToImmutable() }, destination);
            }

            batch.Clear(); batch.Add(record);
        }
        if (batch.Count > 0)
        {
            TrySend(channel, message with { Answers = batch.ToImmutable() }, destination);
        }
    }

    private static void TrySend(MdnsChannel channel, DnsMessage message, IPEndPoint? destination)
    {
        try
        {
            byte[] bytes = DnsCodec.Write(message);
            if (bytes.Length > 9000)
            {
                throw new InvalidOperationException("An mDNS record exceeds the maximum supported datagram size.");
            }

            channel.Send(bytes, destination);
        }
        catch (Exception ex) { ReportSendFailure(channel, ex); }
    }

    private static void ReportSendFailure(MdnsChannel channel, Exception exception)
    {
        lock (s_gate)
        {
            foreach (MdnsRegistration registration in s_registrations.Where(r => !r.Disposed &&
                         ScopeIncludesChannel(r.Scope, channel)))
            {
                s_logSendFailure(registration.Logger, channel.Address.Address, exception);
                if (registration.Scope.NetworkInterfaceId is not null || registration.Scope.LocalAddress is not null)
                {
                    registration.Failure = exception.Message;
                }
            }
            foreach (MdnsBrowseSubscription browser in s_browsers)
            {
                s_logBrowseSendFailure(browser.Logger, channel.Address.Address, exception);
            }
        }
    }
}

internal sealed record MdnsAddress(string InterfaceId, int InterfaceIndex, IPAddress Address)
{
    public string Key => $"{InterfaceId}|{Address}";
}

internal sealed class MdnsChannel : IDisposable
{
    private static readonly object s_membershipGate = new();
    private static readonly Dictionary<(Socket Receiver, AddressFamily Family, int Index),
        (int References, IPAddress LocalAddress)> s_memberships = [];
    private readonly Socket _sender;
    private readonly Socket? _receiver;
    private readonly object _sendGate = new();
    private bool _hasMembership;
    private bool _disposed;
    public MdnsAddress Address { get; }
    public IPAddress Group { get; }
    public Task ReceiveTask { get; }
    public bool UsesSocket(Socket socket) => ReferenceEquals(socket, _sender) || ReferenceEquals(socket, _receiver);

    public MdnsChannel(MdnsAddress address, Socket? receiver,
        Func<Socket, CancellationToken, Task> receiveLoop, CancellationToken stop)
    {
        Address = address;
        Group = address.Address.AddressFamily == AddressFamily.InterNetwork
            ? IPAddress.Parse("224.0.0.251") : IPAddress.Parse("ff02::fb");
        _receiver = receiver ?? throw new SocketException((int)SocketError.AddressNotAvailable);
        AddressFamily family = address.Address.AddressFamily;
        _sender = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            _sender.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _sender.SetSocketOption(family == AddressFamily.InterNetwork ? SocketOptionLevel.IP : SocketOptionLevel.IPv6,
                SocketOptionName.PacketInformation, true);
            _sender.SetSocketOption(family == AddressFamily.InterNetwork ? SocketOptionLevel.IP : SocketOptionLevel.IPv6,
                SocketOptionName.MulticastLoopback, true);
            _sender.SetSocketOption(family == AddressFamily.InterNetwork ? SocketOptionLevel.IP : SocketOptionLevel.IPv6,
                SocketOptionName.MulticastTimeToLive, 255);
            _sender.Ttl = 255;
            if (family == AddressFamily.InterNetwork)
            {
                _sender.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, address.Address.GetAddressBytes());
            }
            else
            {
                _sender.DualMode = false;
                _sender.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface, address.InterfaceIndex);
            }
            AcquireMembership();
            _sender.Bind(new IPEndPoint(address.Address, 5353));
            ReceiveTask = receiveLoop(_sender, stop);
        }
        catch
        {
            _sender.Dispose();
            ReleaseMembership();
            throw;
        }
    }

    internal static int MembershipCount(Socket receiver, AddressFamily family, int index)
    {
        lock (s_membershipGate)
        {
            return s_memberships.TryGetValue((receiver, family, index), out (int References, IPAddress LocalAddress) state)
                ? state.References : 0;
        }
    }

    private void AcquireMembership()
    {
        (Socket Receiver, AddressFamily Family, int Index) key =
            (_receiver!, Address.Address.AddressFamily, Address.InterfaceIndex);
        lock (s_membershipGate)
        {
            if (s_memberships.TryGetValue(key, out (int References, IPAddress LocalAddress) existing))
            {
                s_memberships[key] = (existing.References + 1, existing.LocalAddress);
            }
            else
            {
                if (key.Item2 == AddressFamily.InterNetwork)
                {
                    _receiver!.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership,
                        new MulticastOption(Group, Address.Address));
                }
                else
                {
                    _receiver!.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership,
                        new IPv6MulticastOption(Group, Address.InterfaceIndex));
                }

                s_memberships.Add(key, (1, Address.Address));
            }
            _hasMembership = true;
        }
    }

    private void ReleaseMembership()
    {
        if (!_hasMembership)
        {
            return;
        }

        (Socket Receiver, AddressFamily Family, int Index) key =
            (_receiver!, Address.Address.AddressFamily, Address.InterfaceIndex);
        lock (s_membershipGate)
        {
            if (!s_memberships.TryGetValue(key, out (int References, IPAddress LocalAddress) existing))
            {
                return;
            }

            if (existing.References > 1)
            {
                s_memberships[key] = (existing.References - 1, existing.LocalAddress);
            }
            else
            {
                _ = s_memberships.Remove(key);
                try
                {
                    if (key.Item2 == AddressFamily.InterNetwork)
                    {
                        _receiver!.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.DropMembership,
                            new MulticastOption(Group, existing.LocalAddress));
                    }
                    else
                    {
                        _receiver!.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.DropMembership,
                            new IPv6MulticastOption(Group, Address.InterfaceIndex));
                    }
                }
                catch (ObjectDisposedException) { }
                catch (SocketException) { }
            }
            _hasMembership = false;
        }
    }

    public void Send(byte[] bytes, IPEndPoint? destination)
    {
        lock (_sendGate)
        {
            IPEndPoint target = destination ?? new IPEndPoint(
                Address.Address.AddressFamily == AddressFamily.InterNetworkV6
                    ? new IPAddress(Group.GetAddressBytes(), Address.InterfaceIndex) : Group, 5353);
            _ = _sender.SendTo(bytes, target);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _sender.Dispose();
        ReleaseMembership();
    }
}
