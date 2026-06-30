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
            "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic",
            "  not-a-device-line");

        var devices = service.ParseArpOutput(output, DateTimeOffset.UnixEpoch);

        var device = Assert.Single(devices);
        Assert.Equal("192.168.1.1", device.IpAddress);
        Assert.Equal("AA:BB:CC:DD:EE:FF", device.MacAddress);
        Assert.Equal("Unknown", device.DeviceTypeGuess);
        Assert.Equal(TrustStatus.Unknown, device.TrustStatus);
        Assert.Equal(RiskStatus.Normal, device.RiskStatus);
        Assert.Equal(DateTimeOffset.UnixEpoch, device.LastConfirmedUtc);
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

