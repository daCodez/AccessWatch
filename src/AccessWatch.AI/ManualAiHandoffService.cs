using System.Text.Json;
using AccessWatch.Core;

namespace AccessWatch.AI;

/// <summary>
/// Creates redacted manual ChatGPT handoff payloads.
/// </summary>
public sealed class ManualAiHandoffService : IAiHandoffService
{
    /// <inheritdoc />
    public string CreateRedactedIncidentSummary(NetworkEvent networkEvent, int eventCount, TimeSpan timeWindow)
    {
        var payload = new
        {
            incidentType = networkEvent.EventType == "NewListeningPort"
                ? "PossibleRemoteAccessAttempt"
                : networkEvent.EventType,
            riskLevel = networkEvent.RiskLevel.ToString(),
            sourceDeviceKnown = networkEvent.SourceDeviceId is not null,
            targetService = DescribePort(networkEvent.DestinationPort),
            targetPort = networkEvent.DestinationPort,
            newListeningPortDetected = networkEvent.EventType == "NewListeningPort",
            eventCount,
            timeWindowSeconds = (int)timeWindow.TotalSeconds
        };

        return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
    }

    private static string DescribePort(int? portNumber)
    {
        return portNumber switch
        {
            3389 => "Remote Desktop",
            445 => "SMB",
            139 => "NetBIOS",
            5985 => "WinRM",
            5986 => "WinRM HTTPS",
            22 => "SSH",
            5900 => "VNC",
            _ => "Unknown"
        };
    }
}
