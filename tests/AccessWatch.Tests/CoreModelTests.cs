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

    /// <summary>
    /// Verifies device address classification excludes broadcast, multicast, and non-host rows.
    /// </summary>
    [Theory]
    [InlineData("192.168.1.25", "02:AC:CE:55:20:25", true)]
    [InlineData("192.168.1.25", null, true)]
    [InlineData("172.31.191.255", "FF:FF:FF:FF:FF:FF", false)]
    [InlineData("224.0.0.251", "01:00:5E:00:00:FB", false)]
    [InlineData("239.255.255.250", "01:00:5E:7F:FF:FA", false)]
    [InlineData("10.0.0.255", "00:11:22:33:44:55", false)]
    [InlineData("0.0.0.0", "00:11:22:33:44:55", false)]
    [InlineData("127.0.0.1", "00:11:22:33:44:55", false)]
    [InlineData("fe80::1", "00:11:22:33:44:55", false)]
    [InlineData("999.999.999.999", "00:11:22:33:44:55", false)]
    public void DeviceAddressClassifier_IdentifiesUsableDeviceAddresses(string ipAddress, string? macAddress, bool expected)
    {
        Assert.Equal(expected, DeviceAddressClassifier.IsUsableDeviceAddress(ipAddress, macAddress));
    }
}
