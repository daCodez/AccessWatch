using AccessWatch.Core;
using AccessWatch.Rules;
using ApplicationIdentity = AccessWatch.Core.ApplicationIdentity;

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

    /// <summary>
    /// Verifies Visual Studio-style local development ports stay low noise.
    /// </summary>
    [Fact]
    public void ScoreNewListeningPort_SilentlyLogsVisualStudioLocalDevServer()
    {
        var service = new RiskScoringService();
        var port = new ListeningPort
        {
            PortNumber = 5173,
            LocalAddress = "127.0.0.1",
            Reachability = PortReachability.LocalOnly,
            Application = new ApplicationIdentity
            {
                DisplayName = "Visual Studio",
                ProcessName = "devenv",
                SignatureStatus = SignatureStatus.TrustedSigned,
                Publisher = "Microsoft"
            }
        };

        var assessment = service.ScoreNewListeningPort(port, new AccessWatchSettings());

        Assert.Equal(RiskLevel.Low, assessment.RiskLevel);
        Assert.Equal(NotificationAction.SilentLog, assessment.Action);
    }

    /// <summary>
    /// Verifies an unknown unsigned public listener asks before future enforcement.
    /// </summary>
    [Fact]
    public void ScoreNewListeningPort_AsksBeforeAllowForUnknownUnsignedPublicListener()
    {
        var service = new RiskScoringService();
        var port = new ListeningPort
        {
            PortNumber = 4444,
            LocalAddress = "0.0.0.0",
            Reachability = PortReachability.NetworkReachable,
            Application = new ApplicationIdentity
            {
                DisplayName = "Unknown app",
                ProcessName = "unknown",
                SignatureStatus = SignatureStatus.Unsigned
            }
        };

        var assessment = service.ScoreNewListeningPort(port, new AccessWatchSettings());

        Assert.Equal(RiskLevel.High, assessment.RiskLevel);
        Assert.Equal(NotificationAction.AskBeforeAllow, assessment.Action);
    }

    /// <summary>
    /// Verifies Plex receives a soft first-time notification before it is trusted.
    /// </summary>
    [Fact]
    public void ScoreNewListeningPort_SoftNotifiesForPlexBeforeTrust()
    {
        var service = new RiskScoringService();
        var port = new ListeningPort
        {
            PortNumber = 32400,
            LocalAddress = "0.0.0.0",
            Reachability = PortReachability.NetworkReachable,
            Application = new ApplicationIdentity
            {
                DisplayName = "Plex Media Server",
                ProcessName = "Plex Media Server",
                SignatureStatus = SignatureStatus.TrustedSigned
            }
        };

        var assessment = service.ScoreNewListeningPort(port, new AccessWatchSettings());

        Assert.Equal(RiskLevel.Medium, assessment.RiskLevel);
        Assert.Equal(NotificationAction.SoftNotify, assessment.Action);
    }

    /// <summary>
    /// Verifies watched applications stay visible without repeatedly high-risk interrupting the user.
    /// </summary>
    [Fact]
    public void ScoreNewListeningPort_DowngradesWatchedNetworkReachableAppToWatchLevel()
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
                SignatureStatus = SignatureStatus.TrustedSigned,
                TrustStatus = TrustStatus.KnownWatched
            }
        };

        var assessment = service.ScoreNewListeningPort(port, new AccessWatchSettings());

        Assert.Equal(RiskLevel.Medium, assessment.RiskLevel);
        Assert.Equal(RiskStatus.Watched, assessment.RiskStatus);
        Assert.Equal(NotificationAction.SoftNotify, assessment.Action);
        Assert.Contains("watched application", assessment.Summary);
        Assert.Contains("asked AccessWatch to watch", assessment.WhyItMatters);
    }
    /// <summary>
    /// Verifies trusted Plex ports are silent after the app is trusted.
    /// </summary>
    [Fact]
    public void ScoreNewListeningPort_SilentlyLogsTrustedPlexPort()
    {
        var service = new RiskScoringService();
        var port = new ListeningPort
        {
            PortNumber = 32400,
            LocalAddress = "0.0.0.0",
            Reachability = PortReachability.NetworkReachable,
            Application = new ApplicationIdentity
            {
                DisplayName = "Plex Media Server",
                ProcessName = "Plex Media Server",
                SignatureStatus = SignatureStatus.TrustedSigned,
                TrustStatus = TrustStatus.Trusted
            }
        };

        var assessment = service.ScoreNewListeningPort(port, new AccessWatchSettings());

        Assert.Equal(RiskLevel.Low, assessment.RiskLevel);
        Assert.Equal(NotificationAction.SilentLog, assessment.Action);
    }

    /// <summary>
    /// Verifies signed network-reachable non-sensitive ports are medium risk.
    /// </summary>
    [Fact]
    public void ScoreNewListeningPort_ReturnsMediumRisk_ForSignedNetworkReachableApp()
    {
        var service = new RiskScoringService();
        var port = new ListeningPort
        {
            PortNumber = 8443,
            LocalAddress = "192.168.1.10",
            Reachability = PortReachability.NetworkReachable,
            Application = new ApplicationIdentity
            {
                DisplayName = "Signed service",
                ProcessName = "signed",
                SignatureStatus = SignatureStatus.TrustedSigned
            }
        };

        var assessment = service.ScoreNewListeningPort(port, new AccessWatchSettings());

        Assert.Equal(RiskLevel.Medium, assessment.RiskLevel);
        Assert.Equal(NotificationAction.SoftNotify, assessment.Action);
    }

    /// <summary>
    /// Verifies non-network-reachable unknown ports remain low risk.
    /// </summary>
    [Fact]
    public void ScoreNewListeningPort_ReturnsLowRisk_ForUnknownReachability()
    {
        var service = new RiskScoringService();
        var port = new ListeningPort
        {
            PortNumber = 12345,
            LocalAddress = "mystery",
            Reachability = PortReachability.Unknown
        };

        var assessment = service.ScoreNewListeningPort(port, new AccessWatchSettings());

        Assert.Equal(RiskLevel.Low, assessment.RiskLevel);
        Assert.Equal(RiskStatus.Normal, assessment.RiskStatus);
    }

    /// <summary>
    /// Verifies protection mode overrides medium-risk notification behavior.
    /// </summary>
    [Theory]
    [InlineData(ProtectionMode.Quiet, RiskLevel.Medium, NotificationAction.SilentLog)]
    [InlineData(ProtectionMode.Balanced, RiskLevel.Medium, NotificationAction.SoftNotify)]
    [InlineData(ProtectionMode.Strict, RiskLevel.Medium, NotificationAction.AskBeforeAllow)]
    [InlineData(ProtectionMode.Lockdown, RiskLevel.Critical, NotificationAction.AutoBlock)]
    [InlineData(ProtectionMode.Balanced, RiskLevel.Low, NotificationAction.SilentLog)]
    [InlineData(ProtectionMode.Balanced, RiskLevel.High, NotificationAction.AskBeforeAllow)]
    public void NotificationActionPolicy_ChoosesExpectedAction(ProtectionMode mode, RiskLevel riskLevel, NotificationAction expected)
    {
        var policy = new NotificationActionPolicy();

        var action = policy.Choose(riskLevel, mode);

        Assert.Equal(expected, action);
    }

    /// <summary>
    /// Verifies the policy safely logs unknown future risk values.
    /// </summary>
    [Fact]
    public void NotificationActionPolicy_SilentlyLogsUnknownRiskLevel()
    {
        var policy = new NotificationActionPolicy();

        var action = policy.Choose((RiskLevel)999, ProtectionMode.Balanced);

        Assert.Equal(NotificationAction.SilentLog, action);
    }

    /// <summary>
    /// Verifies all high-risk port labels are included in summaries.
    /// </summary>
    /// <param name="portNumber">High-risk port number.</param>
    /// <param name="expectedLabel">Expected summary label.</param>
    [Theory]
    [InlineData(445, "SMB file sharing")]
    [InlineData(139, "NetBIOS")]
    [InlineData(5985, "WinRM")]
    [InlineData(5986, "WinRM HTTPS")]
    [InlineData(22, "SSH")]
    [InlineData(5900, "VNC")]
    public void ScoreNewListeningPort_LabelsKnownHighRiskPorts(int portNumber, string expectedLabel)
    {
        var service = new RiskScoringService();
        var port = new ListeningPort
        {
            PortNumber = portNumber,
            LocalAddress = "0.0.0.0",
            Reachability = PortReachability.NetworkReachable,
            Application = new ApplicationIdentity
            {
                DisplayName = "System service",
                ProcessName = "service",
                SignatureStatus = SignatureStatus.TrustedSigned
            }
        };

        var assessment = service.ScoreNewListeningPort(port, new AccessWatchSettings());

        Assert.Contains(expectedLabel, assessment.Summary);
    }
}
