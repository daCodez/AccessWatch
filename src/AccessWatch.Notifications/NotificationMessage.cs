using AccessWatch.Core;

namespace AccessWatch.Notifications;

/// <summary>
/// Represents a tray notification request.
/// </summary>
public sealed record NotificationMessage(
    string Title,
    string Body,
    RiskLevel RiskLevel,
    NotificationAction Action,
    string SuggestedAction);

/// <summary>
/// Converts risk assessments into plain-language toast alerts.
/// </summary>
public sealed class NotificationMessageFactory
{
    /// <summary>
    /// Creates a notification message from a port risk assessment.
    /// </summary>
    /// <param name="assessment">The risk assessment to describe.</param>
    /// <returns>A notification message.</returns>
    public NotificationMessage Create(PortRiskAssessment assessment)
    {
        return new NotificationMessage(
            TitleFor(assessment),
            BodyFor(assessment),
            assessment.RiskLevel,
            assessment.Action,
            assessment.SuggestedAction);
    }

    private static string TitleFor(PortRiskAssessment assessment) =>
        assessment.RiskLevel >= RiskLevel.High ? "AccessWatch warning" : "AccessWatch notice";

    private static string BodyFor(PortRiskAssessment assessment)
    {
        var evidence = string.Concat(assessment.Summary, " ", assessment.WhyItMatters).ToLowerInvariant();
        var action = PlainAction(assessment);

        if (evidence.Contains("camera", StringComparison.Ordinal))
        {
            return $"Someone is trying to use your camera. {action}";
        }

        if (evidence.Contains("microphone", StringComparison.Ordinal))
        {
            return $"Someone is trying to use your microphone. {action}";
        }

        if (evidence.Contains("joined the network", StringComparison.Ordinal) || evidence.Contains("new device", StringComparison.Ordinal))
        {
            return $"A new device joined your network. {action}";
        }

        if (evidence.Contains("network-reachable", StringComparison.Ordinal) || evidence.Contains("opened a port", StringComparison.Ordinal) || evidence.Contains("remote", StringComparison.Ordinal) || evidence.Contains("listener", StringComparison.Ordinal))
        {
            return $"Someone is trying to connect to your PC. {action}";
        }

        return $"AccessWatch noticed something unusual. {action}";
    }

    private static string PlainAction(PortRiskAssessment assessment) =>
        assessment.Action switch
        {
            NotificationAction.AskBeforeAllow => "Open AccessWatch to block, allow, or watch it.",
            NotificationAction.AutoBlock => "AccessWatch is prepared to block it.",
            NotificationAction.SoftNotify => "Open AccessWatch if you do not recognize it.",
            _ => "No action is needed right now."
        };
}