using AccessWatch.Core;
using AccessWatch.Detection;
using AppIdentity = AccessWatch.Core.ApplicationIdentity;

namespace AccessWatch.Tests;

/// <summary>
/// Tests parsing behavior for Windows listening port scans.
/// </summary>
public sealed class ListeningPortScannerTests
{
    /// <summary>
    /// Verifies any-address listeners are treated as network reachable.
    /// </summary>
    [Fact]
    public void ParseNetstatOutput_ClassifiesAnyAddressAsNetworkReachable()
    {
        var scanner = new ListeningPortScanner(new FakeIdentityResolver(), new FakeNetstatRunner(""));
        const string output = "  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       100";

        var ports = scanner.ParseNetstatOutput(output, DateTimeOffset.UnixEpoch);

        var port = Assert.Single(ports);
        Assert.Equal(3389, port.PortNumber);
        Assert.Equal(PortReachability.NetworkReachable, port.Reachability);
        Assert.Equal("Fake process", port.Application?.DisplayName);
    }

    /// <summary>
    /// Verifies loopback and malformed lines are handled without false network-reachable events.
    /// </summary>
    [Fact]
    public void ParseNetstatOutput_ClassifiesLoopbackAndSkipsInvalidLines()
    {
        var scanner = new ListeningPortScanner(new FakeIdentityResolver(), new FakeNetstatRunner(""));
        var output = string.Join(Environment.NewLine,
            "  TCP    127.0.0.1:8080         0.0.0.0:0              LISTENING       101",
            "  UDP    0.0.0.0:5353           *:*                                    102",
            "  TCP    bad-endpoint           0.0.0.0:0              LISTENING       103");

        var ports = scanner.ParseNetstatOutput(output, DateTimeOffset.UnixEpoch);

        var port = Assert.Single(ports);
        Assert.Equal(8080, port.PortNumber);
        Assert.Equal(PortReachability.LocalOnly, port.Reachability);
    }

    /// <summary>
    /// Verifies non-IP bind addresses are retained with unknown reachability.
    /// </summary>
    [Fact]
    public void ParseNetstatOutput_ClassifiesHostNamesAsUnknownReachability()
    {
        var scanner = new ListeningPortScanner(new FakeIdentityResolver(), new FakeNetstatRunner(""));
        const string output = "  TCP    hostname:7000          0.0.0.0:0              LISTENING       100";

        var ports = scanner.ParseNetstatOutput(output, DateTimeOffset.UnixEpoch);

        var port = Assert.Single(ports);
        Assert.Equal("hostname", port.LocalAddress);
        Assert.Equal(PortReachability.Unknown, port.Reachability);
    }

    /// <summary>
    /// Verifies concrete LAN addresses are treated as network reachable.
    /// </summary>
    [Fact]
    public void ParseNetstatOutput_ClassifiesConcreteIpAsNetworkReachable()
    {
        var scanner = new ListeningPortScanner(new FakeIdentityResolver(), new FakeNetstatRunner(""));
        const string output = "  TCP    192.168.1.10:7000     0.0.0.0:0              LISTENING       100";

        var ports = scanner.ParseNetstatOutput(output, DateTimeOffset.UnixEpoch);

        var port = Assert.Single(ports);
        Assert.Equal(PortReachability.NetworkReachable, port.Reachability);
    }

    /// <summary>
    /// Verifies ScanAsync sorts netstat observations consistently.
    /// </summary>
    [Fact]
    public async Task ScanAsync_ReturnsSortedPorts()
    {
        var output = string.Join(Environment.NewLine,
            "  TCP    0.0.0.0:9000           0.0.0.0:0              LISTENING       100",
            "  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       100");
        var scanner = new ListeningPortScanner(new FakeIdentityResolver(), new FakeNetstatRunner(output));

        var ports = await scanner.ScanAsync(CancellationToken.None);

        Assert.Collection(
            ports,
            first => Assert.Equal(8000, first.PortNumber),
            second => Assert.Equal(9000, second.PortNumber));
    }

    /// <summary>
    /// Verifies the default scanner constructor can be created.
    /// </summary>
    [Fact]
    public void Constructor_UsesDefaultNetstatRunnerWhenRunnerIsOmitted()
    {
        var scanner = new ListeningPortScanner(new FakeIdentityResolver());

        Assert.NotNull(scanner);
    }

    private sealed class FakeIdentityResolver : IAppIdentityResolver
    {
        public AppIdentity Resolve(int processId)
        {
            return new AppIdentity
            {
                DisplayName = "Fake process",
                ProcessName = "fake",
                SignatureStatus = SignatureStatus.TrustedSigned
            };
        }
    }

    private sealed class FakeNetstatRunner : INetstatRunner
    {
        private readonly string output;

        public FakeNetstatRunner(string output)
        {
            this.output = output;
        }

        public Task<string> RunAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(output);
        }
    }
}
