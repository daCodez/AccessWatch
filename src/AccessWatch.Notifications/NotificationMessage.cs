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
/// Converts risk assessments into user-friendly notification messages.
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
            "AccessWatch",
            $"{assessment.Summary} {assessment.WhyItMatters}",
            assessment.RiskLevel,
            assessment.Action,
            assessment.SuggestedAction);
    }
}
