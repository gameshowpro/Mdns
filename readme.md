# GameshowPro.Mdns

DNS Service Discovery publication and browsing for GameshowPro applications. The library owns its mDNS sockets, record codec, announcements, queries, and cache; it does not depend on Makaretu packages.

## Publish a service

The original constructor still publishes on eligible local IPv4 and IPv6 interfaces with the machine name as its instance name. `AdvertiseUntilCancelled` remains available for an application-lifetime advertisement:

```csharp
// GlobalUsings.cs
global using GameshowPro.Mdns;

AdvertisedService publisher = new(
    new InstanceProperties("_gp-soundling", "tcp", 9096), logger);
await publisher.AdvertiseUntilCancelled(stoppingToken);
```

For a listener bound to a selected interface, supply both its interface ID and local IP address. Each service gets its own handle. Await `StartAsync` after the application endpoint has bound, using its actual port, and call `DisposeAsync` when it stops:

```csharp
// GlobalUsings.cs
global using System.Net;
global using GameshowPro.Mdns;

AdvertisedServiceOptions options = new()
{
    InstanceName = "Soundling-host-project-listener",
    NetworkInterfaceId = selectedNic.Id,
    LocalAddress = IPAddress.Parse(selectedNicAddress),
    TxtProperties = new Dictionary<string, string> { ["role"] = "oscquery" },
};
await using AdvertisedService publisher = new(
    new InstanceProperties("_oscjson", "tcp", checked((ushort)actualHttpPort)),
    options, logger);
await publisher.StartAsync(stoppingToken);
```

If the service is reachable on several addresses of the same adapter, use `LocalAddresses` to publish the complete configured set with one registration. It requires `NetworkInterfaceId`, must be nonempty, and cannot be combined with `LocalAddress`. The publisher constructor snapshots the collection and clones its IP addresses. Include every configured IPv4 and IPv6 address, such as an IPv4 address, an IPv6 ULA, and a link-local IPv6 address with its scope ID:

```csharp
AdvertisedServiceOptions options = new()
{
    InstanceName = "Soundling-host-project-listener",
    NetworkInterfaceId = selectedNic.Id,
    LocalAddresses = new IPAddress[]
    {
        IPAddress.Parse("192.0.2.10"),
        IPAddress.Parse("fd00::10"),
        IPAddress.Parse("fe80::10%12"),
    },
};
```

When either same-host registration uses `LocalAddresses`, conflict checks compare the currently available selected addresses on each shared adapter; unavailable configured addresses do not participate. Order and duplicates do not matter. If sets differ, the existing active registration is retained and the new registration fails to start. Checks run again on network topology changes before announcements: if previously compatible sets diverge, the earlier registration is retained and the later one stops publishing until compatibility returns. Legacy registrations using only `LocalAddress` retain their existing asymmetric conflict behavior: adding a single address after a registration containing it can succeed, while the reverse order can conflict. Consumers should still specify the same complete configured scope for every service sharing a host and adapter, so their scopes do not diverge when addresses become available or disappear. When intentionally changing scopes, withdraw old handles across all services before registering replacements.

`HostName` is optional. It is a single DNS label (`a-z`, `0-9`, `-`; 1 to 63 characters; no leading or trailing `-`; letters in either case, published as given). When set, the SRV target and the A/AAAA records use `<HostName>.local`, so the name answers address queries directly. Services in one process that share a `HostName` (for example `_https._tcp` and `_http._tcp`) share its address records when their scopes agree: they do not conflict with each other, and withdrawing one keeps the addresses live for the other. Choose a `HostName` that no other process or machine owns. Unset, the host stays `<InstanceName>.<service>.local` as before. An invalid label throws `ArgumentException` from the constructor.

`InstanceName` and `TxtProperties` are optional. The library adds a `machineName` TXT value for localhost filtering. An explicit interface requires `LocalAddress` or `LocalAddresses`; omitted scope uses the default eligible interfaces. For `LocalAddresses`, runtime publication follows the configured addresses that are currently available on the selected adapter. Removed addresses are withdrawn, and newly available addresses are not included unless configured. Adapter and address reconciliation polls every 10 seconds; topology changes are checked before announcements. `StartAsync` reports startup failures as exceptions, and `Failure` exposes a later runtime failure. A conflicted active registration retries after 10 quiet seconds, probes three times 250 ms apart, and resumes after a successful retry; a continuing conflict leaves it failed. A handle started with `StartAsync` can recover automatically. `AdvertiseUntilCancelled` fails fast on startup failure and throws if a later `Failure` occurs, then disposes the registration, so it does not provide that automatic recovery. A disposed publisher cannot restart; create a new one to retry.

The runtime suppresses packet comparisons for recently transmitted datagrams with matching bytes, source local address, and source port 5353. The history lasts two seconds and holds up to 4096 transmissions. IPv6 scope IDs are ignored for source matching because the receiving adapter can differ. A delayed or repacked echo may no longer match that history. For a packet from a current local address on port 5353, conflict checking therefore ignores only A/AAAA records that exactly match this runtime's currently selected, usable publication addresses, even when the packet arrives on another adapter. Different address data and conflicting SRV or TXT records still count as conflicts; an address omitted from the current configured scope is not treated as owned. UDP provides no process identity, so a byte-identical copy from the same endpoint during the history window cannot be distinguished from the runtime's own transmission.

## Find services

`ServiceFinder` starts searching when constructed. Use the original profile object as the key in `Services` and cancel the supplied token when discovery is no longer needed:

```csharp
// GlobalUsings.cs
global using GameshowPro.Common.Model;
global using GameshowPro.Mdns;

ServiceSearchProfile profile = new("_oscjson", "tcp", AllowLocalhost: false);
using CancellationTokenSource stop = new();
ServiceFinder finder = new([profile], logger, stop.Token);
IMdnsMatchedServicesMonitor monitor = finder.Services[profile];
```

The monitor keeps current hosts, ports, and addresses from PTR, SRV, TXT, A, and AAAA records, including records that arrive in separate packets. Records expire by their DNS TTL; withdrawals use the standard one-second goodbye grace. `ConflictMonitor` combines the existing publication and discovery contracts for applications that need to find other instances of their own service type.

The library targets `net11.0` and `net11.0-windows` (the Windows configurations retain WPF support), with C# 14 pinned in the project and test projects. Deployment validation, cross-platform network runs, and interoperability checks with third-party applications remain future work.

## Network limits

Contributor build and analyzer requirements are documented in [coding standards](docs/coding-standards.md).

When independent processes share UDP port 5353, the operating system may deliver incoming unicast packets to only one of them. This was observed on Windows with another mDNS responder already bound: self-unicast to the selected external IP did not reach this library's socket. The library requests multicast (QM) replies for browsing, avoiding dependence on QU unicast delivery. Loopback unicast and selected-interface multicast are separate paths; neither establishes that external self-unicast works when another responder owns the binding. See [RFC 6762, section 15.1](https://www.rfc-editor.org/rfc/rfc6762.html#section-15.1). This port-sharing limit concerns mDNS discovery, not an application's OSC UDP listener port.

The receiver does not currently validate the packet's IP TTL or IPv6 hop limit of 255 because .NET packet information does not expose that value here. Simultaneous probe conflict handling is simplified. The implementation should not be treated as a complete RFC 6762 conformance claim.
