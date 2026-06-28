using AccessWatch.Core;
using ApplicationIdentity = AccessWatch.Core.ApplicationIdentity;

namespace AccessWatch.Tests;

/// <summary>
/// Tests core model defaults and record values.
/// </summary>
public sealed class CoreModelTests
{
    /// <summary>
    /// Verifies model defaults are safe for unknown observations.
    /// </summary>
    [Fact]
    public void CoreModels_HaveSafeDefaults()
    {
        var application = new ApplicationIdentity();
        var port = new ListeningPort();
        var networkEvent = new NetworkEvent();
        var settings = new AccessWatchSettings();

        Assert.Equal("Unknown application", application.DisplayName);
        Assert.Equal("unknown", application.ProcessName);
        Assert.Equal(SignatureStatus.Unknown, application.SignatureStatus);
        Assert.Equal(TrustStatus.Unknown, application.TrustStatus);
        Assert.Equal("TCP", port.Protocol);
        Assert.Equal(PortReachability.Unknown, port.Reachability);
        Assert.Equal(RiskStatus.Normal, port.RiskStatus);
        Assert.Equal("TCP", networkEvent.Protocol);
        Assert.Equal("Inbound", networkEvent.Direction);
        Assert.Equal("{}", networkEvent.DetailsJson);
        Assert.Equal(ProtectionMode.Balanced, settings.ProtectionMode);
        Assert.Equal(AiMode.ManualChatGptCopy, settings.AiMode);
    }

    /// <summary>
    /// Verifies record constructor values are preserved.
    /// </summary>
    [Fact]
    public void CoreRecords_PreserveConstructorValues()
    {
        var assessment = new PortRiskAssessment(RiskLevel.Critical, RiskStatus.Critical, NotificationAction.AutoBlock, "Summary", "Why", "Act");
        var confidence = new TrustConfidence(0.42, "Reason");

        Assert.Equal(RiskLevel.Critical, assessment.RiskLevel);
        Assert.Equal(RiskStatus.Critical, assessment.RiskStatus);
        Assert.Equal(NotificationAction.AutoBlock, assessment.Action);
        Assert.Equal("Summary", assessment.Summary);
        Assert.Equal("Why", assessment.WhyItMatters);
        Assert.Equal("Act", assessment.SuggestedAction);
        Assert.Equal(0.42, confidence.Score);
        Assert.Equal("Reason", confidence.Reason);
    }
}
