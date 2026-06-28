using AccessWatch.Core;

namespace AccessWatch.Rules;

/// <summary>
/// Scores AccessWatch events with low-noise defaults.
/// </summary>
public sealed class RiskScoringService : IRiskScoringService
{
    private static readonly IReadOnlyDictionary<int, string> HighRiskPorts = new Dictionary<int, string>
    {
        [3389] = "Remote Desktop",
        [445] = "SMB file sharing",
        [139] = "NetBIOS",
        [5985] = "WinRM",
        [5986] = "WinRM HTTPS",
        [22] = "SSH",
        [5900] = "VNC"
    };
    private readonly NotificationActionPolicy actionPolicy;

    /// <summary>
    /// Initializes a new risk scoring service.
    /// </summary>
    /// <param name="actionPolicy">Notification action policy.</param>
    public RiskScoringService(NotificationActionPolicy? actionPolicy = null)
    {
        this.actionPolicy = actionPolicy ?? new NotificationActionPolicy();
    }

    /// <inheritdoc />
    public PortRiskAssessment ScoreNewListeningPort(ListeningPort port, AccessWatchSettings settings)
    {
        var application = port.Application;
        var isHighRiskPort = HighRiskPorts.TryGetValue(port.PortNumber, out var highRiskPortName);
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

        if (application?.TrustStatus == TrustStatus.Trusted && port.Reachability == PortReachability.NetworkReachable && !isHighRiskPort)
        {
            return Assessment(
                RiskLevel.Low,
                RiskStatus.Normal,
                settings,
                $"{ApplicationName(application)} opened a trusted network-reachable port.",
                "The app is trusted and this is not a known high-risk remote access port.",
                "No action needed.");
        }

        // Network-reachable remote access ports are interruption-worthy because they can expose control surfaces to LAN peers.
        if (port.Reachability == PortReachability.NetworkReachable && isHighRiskPort)
        {
            return Assessment(
                RiskLevel.High,
                RiskStatus.HighRisk,
                settings,
                $"{ApplicationName(application)} opened {highRiskPortName} on port {port.PortNumber}.",
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

    private PortRiskAssessment Assessment(
        RiskLevel riskLevel,
        RiskStatus riskStatus,
        AccessWatchSettings settings,
        string summary,
        string whyItMatters,
        string suggestedAction)
    {
        return new PortRiskAssessment(riskLevel, riskStatus, actionPolicy.Choose(riskLevel, settings.ProtectionMode), summary, whyItMatters, suggestedAction);
    }

    private static string ApplicationName(ApplicationIdentity? application)
    {
        return application?.DisplayName ?? "An unknown application";
    }
}

/// <summary>
/// Chooses the MVP notification action for a risk level and protection mode.
/// </summary>
public sealed class NotificationActionPolicy
{
    /// <summary>
    /// Chooses a notification action.
    /// </summary>
    /// <param name="riskLevel">Event risk level.</param>
    /// <param name="mode">Current protection mode.</param>
    /// <returns>The notification or enforcement-ready action.</returns>
    public NotificationAction Choose(RiskLevel riskLevel, ProtectionMode mode)
    {
        if (mode == ProtectionMode.Quiet && riskLevel == RiskLevel.Medium)
        {
            return NotificationAction.SilentLog;
        }

        if (mode == ProtectionMode.Strict && riskLevel == RiskLevel.Medium)
        {
            return NotificationAction.AskBeforeAllow;
        }

        return riskLevel switch
        {
            RiskLevel.Low => NotificationAction.SilentLog,
            RiskLevel.Medium => NotificationAction.SoftNotify,
            RiskLevel.High => NotificationAction.AskBeforeAllow,
            RiskLevel.Critical => NotificationAction.AutoBlock,
            _ => NotificationAction.SilentLog
        };
    }
}
