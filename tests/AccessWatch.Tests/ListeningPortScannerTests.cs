using AccessWatch.Core;
using AccessWatch.Detection;

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
        var scanner = new ListeningPortScanner(new FakeIdentityResolver());
        const string output = "  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       100";

        var ports = scanner.ParseNetstatOutput(output, DateTimeOffset.UnixEpoch);

        var port = Assert.Single(ports);
        Assert.Equal(3389, port.PortNumber);
        Assert.Equal(PortReachability.NetworkReachable, port.Reachability);
        Assert.Equal("Fake process", port.Application?.DisplayName);
    }

    private sealed class FakeIdentityResolver : IAppIdentityResolver
    {
        public ApplicationIdentity Resolve(int processId)
        {
            return new ApplicationIdentity
            {
                DisplayName = "Fake process",
                ProcessName = "fake",
                SignatureStatus = SignatureStatus.TrustedSigned
            };
        }
    }
}
