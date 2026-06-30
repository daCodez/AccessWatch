using System.Text.Json;
using System.Text.RegularExpressions;
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

    /// <inheritdoc />
    public string CreateRedactedIncidentSummary(Incident incident)
    {
        var payload = new
        {
            incidentType = "GroupedAccessWatchIncident",
            title = FirstUseful(incident.Title, "Untitled incident"),
            riskLevel = incident.RiskLevel.ToString(),
            status = incident.Status.ToString(),
            eventCount = incident.EventCount,
            hasPrimaryDevice = incident.MainDeviceId is not null,
            hasPrimaryApplication = incident.MainApplicationId is not null,
            summary = RedactSensitiveText(FirstUseful(incident.Summary, "No incident summary recorded yet.")),
            suggestedReview = "Explain whether this looks expected, what evidence is missing, and what the user should verify before trusting or blocking it."
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

    private static string FirstUseful(string? value, string fallback)
    {
        return string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
    }

    private static string RedactSensitiveText(string value)
    {
        var withoutMac = Regex.Replace(
            value,
            @"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b",
            "[mac-address]");
        return Regex.Replace(
            withoutMac,
            @"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "[ip-address]");
    }
}
