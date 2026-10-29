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
        _options = new AdvertisedServiceOptions
        {
            InstanceName = options.InstanceName,
            NetworkInterfaceId = options.NetworkInterfaceId,
            LocalAddress = options.LocalAddress,
            TxtProperties = options.TxtProperties?.ToFrozenDictionary(pair => pair.Key, pair => pair.Value,
                StringComparer.OrdinalIgnoreCase),
        };
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        if ((_options.NetworkInterfaceId is null) != (_options.LocalAddress is null))
        {
            throw new ArgumentException("NetworkInterfaceId and LocalAddress must be supplied together.", nameof(options));
        }

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
    }

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
                _properties.ServiceType, _properties.Protocol, _properties.Port, txt);
            try
            {
                MdnsRegistration registration = await MdnsRuntime.RegisterAsync(publication,
                    new MdnsScope(_options.NetworkInterfaceId, _options.LocalAddress), _logger,
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
