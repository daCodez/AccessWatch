using System.Text.Json;
using AccessWatch.AI;
using AccessWatch.Core;

namespace AccessWatch.Tests;

/// <summary>
/// Tests redacted manual AI handoff payload creation.
/// </summary>
public sealed class AiHandoffServiceTests
{
    /// <summary>
    /// Verifies new listening port events are mapped to a safe incident summary.
    /// </summary>
    [Fact]
    public void CreateRedactedIncidentSummary_MapsNewListeningPort()
    {
        var service = new ManualAiHandoffService();
        var networkEvent = new NetworkEvent
        {
            EventType = "NewListeningPort",
            RiskLevel = RiskLevel.High,
            SourceDeviceId = 5,
            DestinationPort = 3389
        };

        var json = service.CreateRedactedIncidentSummary(networkEvent, 8, TimeSpan.FromSeconds(90));

        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal("PossibleRemoteAccessAttempt", root.GetProperty("incidentType").GetString());
        Assert.Equal("High", root.GetProperty("riskLevel").GetString());
        Assert.True(root.GetProperty("sourceDeviceKnown").GetBoolean());
        Assert.Equal("Remote Desktop", root.GetProperty("targetService").GetString());
        Assert.Equal(3389, root.GetProperty("targetPort").GetInt32());
        Assert.True(root.GetProperty("newListeningPortDetected").GetBoolean());
        Assert.Equal(8, root.GetProperty("eventCount").GetInt32());
        Assert.Equal(90, root.GetProperty("timeWindowSeconds").GetInt32());
    }

    /// <summary>
    /// Verifies non-port events and unknown target services remain redacted and generic.
    /// </summary>
    [Fact]
    public void CreateRedactedIncidentSummary_MapsUnknownEvent()
    {
        var service = new ManualAiHandoffService();
        var networkEvent = new NetworkEvent
        {
            EventType = "OtherEvent",
            RiskLevel = RiskLevel.Low,
            DestinationPort = 12345
        };

        var json = service.CreateRedactedIncidentSummary(networkEvent, 1, TimeSpan.FromSeconds(5));

        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal("OtherEvent", root.GetProperty("incidentType").GetString());
        Assert.False(root.GetProperty("sourceDeviceKnown").GetBoolean());
        Assert.Equal("Unknown", root.GetProperty("targetService").GetString());
        Assert.False(root.GetProperty("newListeningPortDetected").GetBoolean());
    }

    /// <summary>
    /// Verifies grouped incidents are converted to redacted AI review packets.
    /// </summary>
    [Fact]
    public void CreateRedactedIncidentSummary_RedactsGroupedIncidentIdentifiers()
    {
        var service = new ManualAiHandoffService();
        var incident = new Incident
        {
            Title = "Camera activated",
            Summary = "Visual Studio used camera near 192.168.1.25 from AA:BB:CC:DD:EE:FF.",
            MainDeviceId = 12,
            MainApplicationId = 34,
            RiskLevel = RiskLevel.High,
            Status = IncidentStatus.Open,
            EventCount = 3
        };

        var json = service.CreateRedactedIncidentSummary(incident);

        Assert.DoesNotContain("192.168.1.25", json);
        Assert.DoesNotContain("AA:BB:CC:DD:EE:FF", json);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal("GroupedAccessWatchIncident", root.GetProperty("incidentType").GetString());
        Assert.Equal("Camera activated", root.GetProperty("title").GetString());
        Assert.Equal("High", root.GetProperty("riskLevel").GetString());
        Assert.Equal("Open", root.GetProperty("status").GetString());
        Assert.Equal(3, root.GetProperty("eventCount").GetInt32());
        Assert.True(root.GetProperty("hasPrimaryDevice").GetBoolean());
        Assert.True(root.GetProperty("hasPrimaryApplication").GetBoolean());
        Assert.Contains("[ip-address]", root.GetProperty("summary").GetString());
        Assert.Contains("[mac-address]", root.GetProperty("summary").GetString());
        Assert.Contains("what the user should verify", root.GetProperty("suggestedReview").GetString());
    }

    /// <summary>
    /// Verifies grouped incident handoff packets use safe fallback text.
    /// </summary>
    [Fact]
    public void CreateRedactedIncidentSummary_UsesGroupedIncidentFallbackText()
    {
        var service = new ManualAiHandoffService();
        var incident = new Incident
        {
            Title = "  ",
            Summary = "",
            RiskLevel = RiskLevel.Low,
            Status = IncidentStatus.Open
        };

        var json = service.CreateRedactedIncidentSummary(incident);

        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal("Untitled incident", root.GetProperty("title").GetString());
        Assert.Equal("No incident summary recorded yet.", root.GetProperty("summary").GetString());
        Assert.False(root.GetProperty("hasPrimaryDevice").GetBoolean());
        Assert.False(root.GetProperty("hasPrimaryApplication").GetBoolean());
    }

    /// <summary>
    /// Verifies known remote-access ports map to redacted service names.
    /// </summary>
    /// <param name="port">Target port.</param>
    /// <param name="serviceName">Expected service name.</param>
    [Theory]
    [InlineData(445, "SMB")]
    [InlineData(139, "NetBIOS")]
    [InlineData(5985, "WinRM")]
    [InlineData(5986, "WinRM HTTPS")]
    [InlineData(22, "SSH")]
    [InlineData(5900, "VNC")]
    public void CreateRedactedIncidentSummary_MapsKnownPorts(int port, string serviceName)
    {
        var service = new ManualAiHandoffService();
        var networkEvent = new NetworkEvent
        {
            EventType = "NewListeningPort",
            RiskLevel = RiskLevel.High,
            DestinationPort = port
        };

        var json = service.CreateRedactedIncidentSummary(networkEvent, 1, TimeSpan.FromSeconds(1));

        using var document = JsonDocument.Parse(json);
        Assert.Equal(serviceName, document.RootElement.GetProperty("targetService").GetString());
    }
}
