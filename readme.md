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

`InstanceName` and `TxtProperties` are optional. The library adds a `machineName` TXT value for localhost filtering. An explicit interface requires its local IPv4 or IPv6 address; omitted scope uses the default eligible interfaces. `StartAsync` reports startup failures as exceptions, and `Failure` exposes a later runtime failure. A disposed publisher cannot restart; create a new one to retry. `AdvertiseUntilCancelled` uses the same publication lifecycle and withdraws on cancellation.

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

The library targets `net10.0` and `net10.0-windows` (the Windows configurations retain WPF support), with C# 14 pinned in the project and test projects. Soundling's `net11.0` projects also pin C# 14. Deployment validation, cross-platform network runs, and interoperability checks with third-party applications remain future work.

## Network limits

Contributor build and analyzer requirements are documented in [coding standards](docs/coding-standards.md).

When independent processes share UDP port 5353, the operating system may deliver incoming unicast packets to only one of them. This was observed on Windows with another mDNS responder already bound: self-unicast to the selected external IP did not reach this library's socket. The library requests multicast (QM) replies for browsing, avoiding dependence on QU unicast delivery. Loopback unicast and selected-interface multicast are separate paths; neither establishes that external self-unicast works when another responder owns the binding. See [RFC 6762, section 15.1](https://www.rfc-editor.org/rfc/rfc6762.html#section-15.1). This port-sharing limit concerns mDNS discovery, not an application's OSC UDP listener port.

The receiver does not currently validate the packet's IP TTL or IPv6 hop limit of 255 because .NET packet information does not expose that value here. Simultaneous probe conflict handling is simplified. The implementation should not be treated as a complete RFC 6762 conformance claim.
