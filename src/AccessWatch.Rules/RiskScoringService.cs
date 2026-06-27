using AccessWatch.Core;

namespace AccessWatch.Rules;

/// <summary>
/// Scores AccessWatch events with low-noise defaults.
/// </summary>
public sealed class RiskScoringService : IRiskScoringService
{
    private static readonly HashSet<int> HighRiskPorts = [3389, 445, 139, 5985, 5986, 22, 5900];

    /// <inheritdoc />
    public PortRiskAssessment ScoreNewListeningPort(ListeningPort port, AccessWatchSettings settings)
    {
        var application = port.Application;
        var isHighRiskPort = HighRiskPorts.Contains(port.PortNumber);
        var isUnsignedOrUnknown = application is null
            || application.SignatureStatus is SignatureStatus.Unsigned or SignatureStatus.InvalidSignature or SignatureStatus.Unknown;
        var isTrustedLocal = application?.TrustStatus == TrustStatus.Trusted && port.Reachability == PortReachability.LocalOnly;

        if (isTrustedLocal)
        {
            return Assessment(
                RiskLevel.Low,
                RiskStatus.Normal,
                settings,
                $"{ApplicationName(application)} opened a local-only port.",
                "The service is only listening on this computer.",
                "No action needed.");
        }

        // Network-reachable remote access ports are interruption-worthy because they can expose control surfaces to LAN peers.
        if (port.Reachability == PortReachability.NetworkReachable && isHighRiskPort)
        {
            return Assessment(
                RiskLevel.High,
                RiskStatus.HighRisk,
                settings,
                $"{ApplicationName(application)} opened {DescribePort(port.PortNumber)} on port {port.PortNumber}.",
                "This port is commonly used for remote access or Windows file sharing.",
                "Review whether this service should be reachable from your network.");
        }

        if (port.Reachability == PortReachability.NetworkReachable && isUnsignedOrUnknown)
        {
            return Assessment(
                RiskLevel.High,
                RiskStatus.HighRisk,
                settings,
                $"{ApplicationName(application)} opened a network-reachable port.",
                "Unknown or unsigned apps listening on the network deserve review.",
                "Confirm the app is expected before trusting it.");
        }

        if (port.Reachability == PortReachability.NetworkReachable)
        {
            return Assessment(
                RiskLevel.Medium,
                RiskStatus.Watched,
                settings,
                $"{ApplicationName(application)} opened a network-reachable port.",
                "Other devices on your network may be able to connect to this service.",
                "No action needed if you recognize the app.");
        }

        return Assessment(
            RiskLevel.Low,
            RiskStatus.Normal,
            settings,
            $"{ApplicationName(application)} opened a local-only port.",
            "The listener does not appear reachable from other devices.",
            "No action needed.");
    }

    private static PortRiskAssessment Assessment(
        RiskLevel riskLevel,
        RiskStatus riskStatus,
        AccessWatchSettings settings,
        string summary,
        string whyItMatters,
        string suggestedAction)
    {
        return new PortRiskAssessment(riskLevel, riskStatus, ChooseAction(riskLevel, settings.ProtectionMode), summary, whyItMatters, suggestedAction);
    }

    private static NotificationAction ChooseAction(RiskLevel riskLevel, ProtectionMode mode)
    {
        return mode switch
        {
            ProtectionMode.Quiet when riskLevel == RiskLevel.Medium => NotificationAction.SilentLog,
            ProtectionMode.Strict when riskLevel == RiskLevel.Medium => NotificationAction.AskBeforeAllow,
            ProtectionMode.Lockdown when riskLevel == RiskLevel.Critical => NotificationAction.AutoBlock,
            _ => riskLevel switch
            {
                RiskLevel.Low => NotificationAction.SilentLog,
                RiskLevel.Medium => NotificationAction.SoftNotify,
                RiskLevel.High => NotificationAction.AskBeforeAllow,
                RiskLevel.Critical => NotificationAction.AutoBlock,
                _ => NotificationAction.SilentLog
            }
        };
    }

    private static string ApplicationName(ApplicationIdentity? application)
    {
        return application?.DisplayName ?? "An unknown application";
    }

    private static string DescribePort(int portNumber)
    {
        return portNumber switch
        {
            3389 => "Remote Desktop",
            445 => "SMB file sharing",
            139 => "NetBIOS",
            5985 => "WinRM",
            5986 => "WinRM HTTPS",
            22 => "SSH",
            5900 => "VNC",
            _ => "a service"
        };
    }
}
