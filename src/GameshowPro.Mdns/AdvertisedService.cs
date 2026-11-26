namespace GameshowPro.Mdns;

/// <summary>Publishes a DNS-SD service on all local interfaces or one selected interface.</summary>
public class AdvertisedService : IAsyncDisposable
{
    private readonly IMdnsInstanceProperties _properties;
    private readonly AdvertisedServiceOptions _options;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private MdnsRegistration? _registration;
    private volatile bool _disposed;
    private string? _failure;

    public AdvertisedService(IMdnsInstanceProperties instanceProperties, ILogger logger)
        : this(instanceProperties, new AdvertisedServiceOptions(), logger) { }

    public AdvertisedService(IMdnsInstanceProperties instanceProperties, AdvertisedServiceOptions options, ILogger logger)
    {
        _properties = instanceProperties ?? throw new ArgumentNullException(nameof(instanceProperties));
        ArgumentNullException.ThrowIfNull(options);
        if (options.LocalAddress is not null && options.LocalAddresses is not null)
        {
            throw new ArgumentException("LocalAddress and LocalAddresses cannot be supplied together.", nameof(options));
        }

        if ((options.NetworkInterfaceId is null) !=
            (options.LocalAddress is null && options.LocalAddresses is null))
        {
            throw new ArgumentException("NetworkInterfaceId requires LocalAddress or LocalAddresses, and vice versa.",
                nameof(options));
        }

        if (options.LocalAddresses is { Count: 0 })
        {
            throw new ArgumentException("LocalAddresses cannot be empty.", nameof(options));
        }

        if (options.LocalAddresses?.Any(address => address is null) == true)
        {
            throw new ArgumentException("LocalAddresses cannot contain a null address.", nameof(options));
        }

        _options = new AdvertisedServiceOptions
        {
            InstanceName = options.InstanceName,
            HostName = options.HostName,
            NetworkInterfaceId = options.NetworkInterfaceId,
            LocalAddress = options.LocalAddress is { } address ? CloneAddress(address) : null,
            LocalAddresses = options.LocalAddresses?.Select(CloneAddress).ToImmutableArray(),
            TxtProperties = options.TxtProperties?.ToFrozenDictionary(pair => pair.Key, pair => pair.Value,
                StringComparer.OrdinalIgnoreCase),
        };
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        if (_options.NetworkInterfaceId is { Length: 0 })
        {
            throw new ArgumentException("NetworkInterfaceId cannot be empty.", nameof(options));
        }

        if (_options.InstanceName is { Length: 0 })
        {
            throw new ArgumentException("InstanceName cannot be empty.", nameof(options));
        }

        if (_options.LocalAddress is { AddressFamily: not (System.Net.Sockets.AddressFamily.InterNetwork or System.Net.Sockets.AddressFamily.InterNetworkV6) })
        {
            throw new ArgumentException("LocalAddress must be IPv4 or IPv6.", nameof(options));
        }

        if (_options.LocalAddresses?.Any(address => address.AddressFamily is not
            (System.Net.Sockets.AddressFamily.InterNetwork or System.Net.Sockets.AddressFamily.InterNetworkV6)) == true)
        {
            throw new ArgumentException("LocalAddresses must contain only IPv4 or IPv6 addresses.", nameof(options));
        }

        if (_options.HostName is { } hostName && !IsValidHostLabel(hostName))
        {
            throw new ArgumentException(
                "HostName must be a single DNS label of 1 to 63 letters, digits, or hyphens, not starting or ending with a hyphen.",
                nameof(options));
        }
    }

    private static bool IsValidHostLabel(string label) =>
        label.Length is >= 1 and <= 63 && label[0] != '-' && label[^1] != '-' &&
        label.All(c => c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '-');

    private static IPAddress CloneAddress(IPAddress address) => address.AddressFamily ==
        System.Net.Sockets.AddressFamily.InterNetworkV6
            ? new IPAddress(address.GetAddressBytes(), address.ScopeId)
            : new IPAddress(address.GetAddressBytes());

    public string? Failure => _registration?.Failure ?? Volatile.Read(ref _failure);

    /// <summary>Starts publication; repeated calls while active share the same registration.</summary>
    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_registration is not null)
            {
                return;
            }

            Dictionary<string, string> txt = new(StringComparer.OrdinalIgnoreCase);
            if (_options.TxtProperties is not null)
            {
                foreach (KeyValuePair<string, string> pair in _options.TxtProperties)
                {
                    txt.Add(pair.Key, pair.Value);
                }
            }

            txt[TxtRecordMachineName] = Environment.MachineName;
            MdnsPublication publication = new(
                _options.InstanceName ?? Environment.MachineName,
                _properties.ServiceType, _properties.Protocol, _properties.Port, txt, _options.HostName);
            try
            {
                MdnsRegistration registration = await MdnsRuntime.RegisterAsync(publication,
                    new MdnsScope(_options.NetworkInterfaceId, _options.LocalAddress, _options.LocalAddresses), _logger,
                    cancellationToken).ConfigureAwait(false);
                if (registration.Failure is { } failure)
                {
                    await registration.DisposeAsync().ConfigureAwait(false);
                    throw new InvalidOperationException(failure);
                }
                _registration = registration;
                Volatile.Write(ref _failure, null);
            }
            catch (Exception ex)
            {
                Volatile.Write(ref _failure, ex.Message);
                throw;
            }
        }
        finally { _ = _gate.Release(); }
    }

    /// <summary>Publishes until cancellation, then withdraws the registration.</summary>
    public async Task AdvertiseUntilCancelled(CancellationToken cancellationToken)
    {
        await StartAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using PeriodicTimer timer = new(TimeSpan.FromMilliseconds(500));
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                if (_disposed)
                {
                    return;
                }

                if (Failure is { } failure)
                {
                    throw new InvalidOperationException(failure);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        finally { await DisposeAsync().ConfigureAwait(false); }
    }

    public async ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            if (_registration is not null)
            {
                Volatile.Write(ref _failure, _registration.Failure);
                await _registration.DisposeAsync().ConfigureAwait(false);
            }
            _registration = null;
        }
        finally { _ = _gate.Release(); }
    }
}
