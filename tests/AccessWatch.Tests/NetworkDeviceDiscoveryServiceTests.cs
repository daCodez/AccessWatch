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
        var service = new NetworkDeviceDiscoveryService(new FakeArpTableRunner(string.Empty));
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
    /// Verifies discovery delegates to the ARP runner and sorts devices consistently.
    /// </summary>
    [Fact]
    public async Task DiscoverAsync_UsesRunnerAndSortsDevices()
    {
        var output = string.Join(Environment.NewLine,
            "  192.168.1.20          00-11-22-33-44-55     dynamic",
            "  192.168.1.10          66-77-88-99-aa-bb     dynamic");
        var service = new NetworkDeviceDiscoveryService(new FakeArpTableRunner(output));

        var devices = await service.DiscoverAsync(CancellationToken.None);

        Assert.Collection(
            devices,
            first => Assert.Equal("192.168.1.10", first.IpAddress),
            second => Assert.Equal("192.168.1.20", second.IpAddress));
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
