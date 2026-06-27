using AccessWatch.Core;
using AccessWatch.Rules;

namespace AccessWatch.Tests;

/// <summary>
/// Tests the MVP port risk scoring behavior.
/// </summary>
public sealed class RiskScoringServiceTests
{
    /// <summary>
    /// Verifies network-reachable remote access ports interrupt as high risk.
    /// </summary>
    [Fact]
    public void ScoreNewListeningPort_ReturnsHighRisk_ForNetworkReachableRemoteAccessPort()
    {
        var service = new RiskScoringService();
        var port = new ListeningPort
        {
            PortNumber = 3389,
            LocalAddress = "0.0.0.0",
            Reachability = PortReachability.NetworkReachable,
            Application = new ApplicationIdentity
            {
                DisplayName = "Remote Desktop",
                ProcessName = "svchost",
                SignatureStatus = SignatureStatus.TrustedSigned
            }
        };

        var assessment = service.ScoreNewListeningPort(port, new AccessWatchSettings());

        Assert.Equal(RiskLevel.High, assessment.RiskLevel);
        Assert.Equal(RiskStatus.HighRisk, assessment.RiskStatus);
        Assert.Equal(NotificationAction.AskBeforeAllow, assessment.Action);
    }

    /// <summary>
    /// Verifies unsigned network-reachable apps interrupt as high risk.
    /// </summary>
    [Fact]
    public void ScoreNewListeningPort_ReturnsHighRisk_ForUnsignedNetworkReachableApp()
    {
        var service = new RiskScoringService();
        var port = new ListeningPort
        {
            PortNumber = 49152,
            LocalAddress = "192.168.1.10",
            Reachability = PortReachability.NetworkReachable,
            Application = new ApplicationIdentity
            {
                DisplayName = "Unknown tool",
                ProcessName = "tool",
                SignatureStatus = SignatureStatus.Unsigned
            }
        };

        var assessment = service.ScoreNewListeningPort(port, new AccessWatchSettings());

        Assert.Equal(RiskLevel.High, assessment.RiskLevel);
        Assert.Contains("Unknown or unsigned apps", assessment.WhyItMatters);
    }

    /// <summary>
    /// Verifies trusted local-only listeners stay silent.
    /// </summary>
    [Fact]
    public void ScoreNewListeningPort_SilentlyLogsTrustedLocalOnlyApp()
    {
        var service = new RiskScoringService();
        var port = new ListeningPort
        {
            PortNumber = 12345,
            LocalAddress = "127.0.0.1",
            Reachability = PortReachability.LocalOnly,
            Application = new ApplicationIdentity
            {
                DisplayName = "Trusted helper",
                ProcessName = "helper",
                SignatureStatus = SignatureStatus.TrustedSigned,
                TrustStatus = TrustStatus.Trusted
            }
        };

        var assessment = service.ScoreNewListeningPort(port, new AccessWatchSettings());

        Assert.Equal(RiskLevel.Low, assessment.RiskLevel);
        Assert.Equal(NotificationAction.SilentLog, assessment.Action);
        Assert.Equal("No action needed.", assessment.SuggestedAction);
    }
}
