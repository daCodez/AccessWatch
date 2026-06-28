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
