using AccessWatch.Core;
using AccessWatch.Detection;

namespace AccessWatch.Tests;

/// <summary>
/// Tests local-network device discovery behavior.
/// </summary>
public sealed class NetworkDeviceDiscoveryServiceTests
{
    /// <summary>
    /// Verifies ARP output is parsed into unknown local-network devices.
    /// </summary>
    [Fact]
    public void ParseArpOutput_ReturnsUnknownDevices()
    {
        var service = new NetworkDeviceDiscoveryService(new FakeArpTableRunner(string.Empty), new FakeHostnameResolver());
        var output = string.Join(Environment.NewLine,
            "Interface: 192.168.1.10 --- 0x7",
            "  Internet Address      Physical Address      Type",
            "  192.168.1.20          aa-bb-cc-dd-ee-ff     dynamic",
            "  not-a-device-line");

        var devices = service.ParseArpOutput(output, DateTimeOffset.UnixEpoch);

        var device = Assert.Single(devices);
        Assert.Equal("192.168.1.20", device.IpAddress);
        Assert.Equal("AA:BB:CC:DD:EE:FF", device.MacAddress);
        Assert.Equal("Unknown", device.DeviceTypeGuess);
        Assert.Equal(TrustStatus.Unknown, device.TrustStatus);
        Assert.Equal(RiskStatus.Normal, device.RiskStatus);
        Assert.Equal(DateTimeOffset.UnixEpoch, device.LastConfirmedUtc);
        Assert.Contains("ARP table", device.Notes);
    }

    /// <summary>
    /// Verifies ARP output labels likely gateway addresses with useful context.
    /// </summary>
    [Fact]
    public void ParseArpOutput_LabelsLikelyRouterGateway()
    {
        var service = new NetworkDeviceDiscoveryService(new FakeArpTableRunner(string.Empty), new FakeHostnameResolver());
        var output = "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic";

        var device = Assert.Single(service.ParseArpOutput(output, DateTimeOffset.UnixEpoch));

        Assert.Equal("Router / gateway", device.DeviceTypeGuess);
    }

    /// <summary>
    /// Verifies ARP broadcast and multicast rows are not shown as real devices.
    /// </summary>
    [Fact]
    public void ParseArpOutput_FiltersBroadcastAndMulticastRows()
    {
        var service = new NetworkDeviceDiscoveryService(new FakeArpTableRunner(string.Empty), new FakeHostnameResolver());
        var output = string.Join(Environment.NewLine,
            "  172.31.191.255       ff-ff-ff-ff-ff-ff     static",
            "  255.255.255.255      ff-ff-ff-ff-ff-ff     static",
            "  224.0.0.251          01-00-5e-00-00-fb     static",
            "  239.255.255.250      01-00-5e-7f-ff-fa     static",
            "  999.999.999.999      00-11-22-33-44-55     dynamic",
            "  192.168.1.25         02-ac-ce-55-20-25     dynamic");

        var devices = service.ParseArpOutput(output, DateTimeOffset.UnixEpoch);

        var device = Assert.Single(devices);
        Assert.Equal("192.168.1.25", device.IpAddress);
        Assert.Equal("02:AC:CE:55:20:25", device.MacAddress);
    }

    /// <summary>
    /// Verifies malformed MAC addresses are ignored without allocating normalized device rows.
    /// </summary>
    [Fact]
    public void ParseArpOutput_SkipsMalformedMacAddresses()
    {
        var service = new NetworkDeviceDiscoveryService(new FakeArpTableRunner(string.Empty), new FakeHostnameResolver());
        var output = string.Join(Environment.NewLine,
            "  192.168.1.20          00-11                 dynamic",
            "  192.168.1.21          00:11:22:33:44:55     dynamic",
            "  192.168.1.22          0g-11-22-33-44-55     dynamic",
            "  192.168.1.23          00-11-22-33-44-55     dynamic");

        var devices = service.ParseArpOutput(output, DateTimeOffset.UnixEpoch);

        var device = Assert.Single(devices);
        Assert.Equal("192.168.1.23", device.IpAddress);
        Assert.Equal("00:11:22:33:44:55", device.MacAddress);
    }

    /// <summary>
    /// Verifies discovery delegates to the ARP runner and sorts devices consistently.
    /// </summary>
    [Fact]
    public async Task DiscoverAsync_UsesRunnerAndSortsDevices()
    {
        var output = string.Join(Environment.NewLine,
            "  192.168.1.20          00-11-22-33-44-55     dynamic",
            "  192.168.1.10          66-77-88-99-aa-bb     dynamic");
        var service = new NetworkDeviceDiscoveryService(new FakeArpTableRunner(output), new FakeHostnameResolver());

        var devices = await service.DiscoverAsync(CancellationToken.None);

        Assert.Collection(
            devices,
            first => Assert.Equal("192.168.1.10", first.IpAddress),
            second => Assert.Equal("192.168.1.20", second.IpAddress));
    }

    /// <summary>
    /// Verifies active subnet probing runs before passive table reads.
    /// </summary>
    [Fact]
    public async Task DiscoverAsync_RunsActiveSubnetProbeBeforeReadingTables()
    {
        var output = "  192.168.1.30          00-11-22-33-44-55     dynamic";
        var probeRunner = new FakeSubnetProbeRunner();
        var service = new NetworkDeviceDiscoveryService(new FakeArpTableRunner(output), new FakeHostnameResolver(), null, probeRunner);

        var device = Assert.Single(await service.DiscoverAsync(CancellationToken.None));

        Assert.True(probeRunner.WasCalled);
        Assert.Equal("192.168.1.30", device.IpAddress);
    }

    /// <summary>
    /// Verifies discovery includes reverse-DNS hostnames when they can be resolved.
    /// </summary>
    [Fact]
    public async Task DiscoverAsync_AddsResolvedDeviceNames()
    {
        var output = "  192.168.1.44          00-11-22-33-44-55     dynamic";
        var service = new NetworkDeviceDiscoveryService(
            new FakeArpTableRunner(output),
            new FakeHostnameResolver(new Dictionary<string, string> { ["192.168.1.44"] = "office-printer.local" }));

        var devices = await service.DiscoverAsync(CancellationToken.None);

        Assert.Equal("office-printer.local", Assert.Single(devices).Hostname);
    }

    /// <summary>
    /// Verifies hostnames are used to fingerprint common device types.
    /// </summary>
    /// <param name="hostname">Resolved hostname.</param>
    /// <param name="expectedType">Expected device type label.</param>
    [Theory]
    [InlineData("pixel-phone.local", "Phone")]
    [InlineData("family-ipad.local", "Tablet")]
    [InlineData("office-printer.local", "Printer")]
    [InlineData("media-nas.local", "Network storage")]
    [InlineData("home-router.local", "Router / gateway")]
    [InlineData("wifi-gateway.local", "Router / gateway")]
    [InlineData("bedroom-roku.local", "Media device")]
    [InlineData("office-chromecast.local", "Media device")]
    [InlineData("office-echo.local", "Smart speaker")]
    [InlineData("living-room-tv.local", "Media device")]
    [InlineData("kitchen-speaker.local", "Smart speaker")]
    [InlineData("unknown-host.local", "Unknown")]
    public async Task DiscoverAsync_InfersDeviceTypeFromResolvedHostname(string hostname, string expectedType)
    {
        var output = "  192.168.1.44          00-11-22-33-44-55     dynamic";
        var service = new NetworkDeviceDiscoveryService(
            new FakeArpTableRunner(output),
            new FakeHostnameResolver(new Dictionary<string, string> { ["192.168.1.44"] = hostname }));

        var device = Assert.Single(await service.DiscoverAsync(CancellationToken.None));

        Assert.Equal(expectedType, device.DeviceTypeGuess);
    }

    /// <summary>
    /// Verifies router fingerprinting adds context to resolved device notes.
    /// </summary>
    [Fact]
    public async Task DiscoverAsync_AddsRouterContextToResolvedGatewayNotes()
    {
        var output = "  192.168.1.2           00-11-22-33-44-55     dynamic";
        var service = new NetworkDeviceDiscoveryService(
            new FakeArpTableRunner(output),
            new FakeHostnameResolver(new Dictionary<string, string> { ["192.168.1.2"] = "home-router.local" }));

        var device = Assert.Single(await service.DiscoverAsync(CancellationToken.None));

        Assert.Equal("Router / gateway", device.DeviceTypeGuess);
        Assert.Contains("router or default gateway", device.Notes);
    }

    /// <summary>
    /// Verifies discovery keeps devices visible when reverse-DNS lookup has no name.
    /// </summary>
    [Fact]
    public async Task DiscoverAsync_KeepsDeviceWhenNameCannotBeResolved()
    {
        var output = "  192.168.1.45          00-11-22-33-44-66     dynamic";
        var service = new NetworkDeviceDiscoveryService(new FakeArpTableRunner(output), new FakeHostnameResolver());

        var devices = await service.DiscoverAsync(CancellationToken.None);

        Assert.Null(Assert.Single(devices).Hostname);
    }

    /// <summary>
    /// Verifies hostname enrichment uses a small fixed worker pool for large device inventories.
    /// </summary>
    [Fact]
    public async Task DiscoverAsync_CapsConcurrentHostnameLookups()
    {
        var output = string.Join(
            Environment.NewLine,
            Enumerable.Range(1, 48).Select(index => $"  192.168.1.{index}          02-00-00-00-00-{index:X2}     dynamic"));
        var resolver = new TrackingHostnameResolver();
        var service = new NetworkDeviceDiscoveryService(new FakeArpTableRunner(output), resolver);

        var devices = await service.DiscoverAsync(CancellationToken.None);

        Assert.Equal(48, devices.Count);
        Assert.InRange(resolver.MaximumConcurrentLookups, 1, 16);
        Assert.Equal(48, resolver.LookupCount);
    }

    /// <summary>
    /// Verifies Windows neighbor table output can surface quiet phone-like devices.
    /// </summary>
    [Fact]
    public void ParseNeighborOutput_ReturnsPhoneFriendlyNeighborDevices()
    {
        var service = new NetworkDeviceDiscoveryService(new FakeArpTableRunner(string.Empty), new FakeHostnameResolver());
        var output = string.Join(Environment.NewLine,
            "Interface 12: Wi-Fi",
            "Internet Address                              Physical Address   Type",
            "192.168.1.72                                  aa-bb-cc-dd-ee-12  Reachable",
            "fe80::1                                       aa-bb-cc-dd-ee-13  Reachable",
            "192.168.1.255                                 ff-ff-ff-ff-ff-ff  Permanent");

        var devices = service.ParseNeighborOutput(output, DateTimeOffset.UnixEpoch);

        Assert.Collection(
            devices,
            device =>
            {
                Assert.Equal("192.168.1.72", device.IpAddress);
                Assert.Equal("AA:BB:CC:DD:EE:12", device.MacAddress);
                Assert.Equal("Network neighbor", device.DeviceTypeGuess);
                Assert.Contains("Phone Link", device.Notes);
            },
            device =>
            {
                Assert.Equal("fe80::1", device.IpAddress);
                Assert.Equal("AA:BB:CC:DD:EE:13", device.MacAddress);
                Assert.Equal("Network neighbor", device.DeviceTypeGuess);
            });
    }

    /// <summary>
    /// Verifies IPv6 neighbor table entries are kept for quiet phones.
    /// </summary>
    [Fact]
    public void ParseNeighborOutput_ReturnsIpv6PhoneNeighborDevices()
    {
        var service = new NetworkDeviceDiscoveryService(new FakeArpTableRunner(string.Empty), new FakeHostnameResolver());
        var output = string.Join(Environment.NewLine,
            "Interface 12: Wi-Fi",
            "Internet Address                              Physical Address   Type",
            "fe80::1234:abcd                               aa-bb-cc-dd-ee-12  Reachable",
            "ff02::fb                                      33-33-00-00-00-fb  Permanent");

        var devices = service.ParseNeighborOutput(output, DateTimeOffset.UnixEpoch);

        var device = Assert.Single(devices);
        Assert.Equal("fe80::1234:abcd", device.IpAddress);
        Assert.Equal("AA:BB:CC:DD:EE:12", device.MacAddress);
        Assert.Equal("Network neighbor", device.DeviceTypeGuess);
        Assert.Contains("Phone Link", device.Notes);
    }

    /// <summary>
    /// Verifies discovery merges ARP and neighbor-table observations without duplicate devices.
    /// </summary>
    [Fact]
    public async Task DiscoverAsync_MergesNeighborTableDevices()
    {
        var arpOutput = string.Join(Environment.NewLine,
            "  192.168.1.10          00-11-22-33-44-55     dynamic",
            "  192.168.1.11          00-11-22-33-44-66     dynamic");
        var neighborOutput = string.Join(Environment.NewLine,
            "  192.168.1.11          00-11-22-33-44-66     Reachable",
            "  192.168.1.99          00-11-22-33-44-55     Reachable",
            "  192.168.1.72          aa-bb-cc-dd-ee-12     Reachable");
        var service = new NetworkDeviceDiscoveryService(
            new FakeArpTableRunner(arpOutput),
            new FakeHostnameResolver(new Dictionary<string, string> { ["192.168.1.72"] = "pixel-phone.local" }),
            new FakeNeighborTableRunner(neighborOutput));

        var devices = await service.DiscoverAsync(CancellationToken.None);

        Assert.Collection(
            devices,
            first => Assert.Equal("192.168.1.10", first.IpAddress),
            second => Assert.Equal("192.168.1.11", second.IpAddress),
            third =>
            {
                Assert.Equal("192.168.1.72", third.IpAddress);
                Assert.Equal("pixel-phone.local", third.Hostname);
                Assert.Equal("Phone", third.DeviceTypeGuess);
                Assert.Contains("neighbor table", third.Notes);
            });
    }

    /// <summary>
    /// Verifies discovery keeps ARP devices when the neighbor table has no usable devices.
    /// </summary>
    [Fact]
    public async Task DiscoverAsync_KeepsArpDevicesWhenNeighborTableIsEmpty()
    {
        var arpOutput = "  192.168.1.30          00-11-22-33-44-77     dynamic";
        var neighborOutput = string.Join(Environment.NewLine,
            "Internet Address                              Physical Address   Type",
            "192.168.1.255                                 ff-ff-ff-ff-ff-ff  Permanent");
        var service = new NetworkDeviceDiscoveryService(
            new FakeArpTableRunner(arpOutput),
            new FakeHostnameResolver(),
            new FakeNeighborTableRunner(neighborOutput));

        var device = Assert.Single(await service.DiscoverAsync(CancellationToken.None));

        Assert.Equal("192.168.1.30", device.IpAddress);
    }

    /// <summary>
    /// Verifies the ARP-only constructor remains available for tests and simple callers.
    /// </summary>
    [Fact]
    public async Task DiscoverAsync_WithArpOnlyConstructor_UsesProvidedRunner()
    {
        var output = "  192.168.1.31          00-11-22-33-44-88     dynamic";
        var service = new NetworkDeviceDiscoveryService(new FakeArpTableRunner(output));

        var device = Assert.Single(await service.DiscoverAsync(CancellationToken.None));

        Assert.Equal("192.168.1.31", device.IpAddress);
    }

    /// <summary>
    /// Verifies the default constructor can be created for service registration.
    /// </summary>
    [Fact]
    public void Constructor_UsesDefaultArpRunnerWhenRunnerIsOmitted()
    {
        var service = new NetworkDeviceDiscoveryService();

        Assert.NotNull(service);
    }

    private sealed class FakeHostnameResolver : IDeviceHostnameResolver
    {
        private readonly IReadOnlyDictionary<string, string> hostnames;

        public FakeHostnameResolver(IReadOnlyDictionary<string, string>? hostnames = null)
        {
            this.hostnames = hostnames ?? new Dictionary<string, string>();
        }

        public Task<string?> ResolveHostnameAsync(string ipAddress, CancellationToken cancellationToken)
        {
            return Task.FromResult(hostnames.TryGetValue(ipAddress, out var hostname) ? hostname : null);
        }
    }

    private sealed class TrackingHostnameResolver : IDeviceHostnameResolver
    {
        private int activeLookups;
        private int maximumConcurrentLookups;
        private int lookupCount;

        public int MaximumConcurrentLookups => maximumConcurrentLookups;

        public int LookupCount => lookupCount;

        public async Task<string?> ResolveHostnameAsync(string ipAddress, CancellationToken cancellationToken)
        {
            var active = Interlocked.Increment(ref activeLookups);
            Interlocked.Increment(ref lookupCount);
            UpdateMaximum(active);
            try
            {
                await Task.Delay(10, cancellationToken);
                return null;
            }
            finally
            {
                Interlocked.Decrement(ref activeLookups);
            }
        }

        private void UpdateMaximum(int candidate)
        {
            while (true)
            {
                var current = maximumConcurrentLookups;
                if (candidate <= current || Interlocked.CompareExchange(ref maximumConcurrentLookups, candidate, current) == current)
                {
                    return;
                }
            }
        }
    }

    private sealed class FakeSubnetProbeRunner : ISubnetProbeRunner
    {
        public bool WasCalled { get; private set; }

        public Task ProbeAsync(CancellationToken cancellationToken)
        {
            WasCalled = true;
            return Task.CompletedTask;
        }
    }

    private sealed class FakeNeighborTableRunner : INeighborTableRunner
    {
        private readonly string output;

        public FakeNeighborTableRunner(string output)
        {
            this.output = output;
        }

        public Task<string> RunAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(output);
        }
    }

    private sealed class FakeArpTableRunner : IArpTableRunner
    {
        private readonly string output;

        public FakeArpTableRunner(string output)
        {
            this.output = output;
        }

        public Task<string> RunAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(output);
        }
    }
}
