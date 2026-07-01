using System.Text.Json;
using AccessWatch.Core;

namespace AccessWatch.Service;

internal static class IncidentFactory
{
    public static Incident? CreateReviewIncident(NetworkEvent networkEvent, DateTimeOffset now)
    {
        if (!networkEvent.WasUserNotified && networkEvent.RiskLevel < RiskLevel.Medium)
        {
            return null;
        }

        var createdUtc = networkEvent.CreatedUtc == default ? now : networkEvent.CreatedUtc;
        return new Incident
        {
            Title = BuildTitle(networkEvent),
            Summary = BuildSummary(networkEvent),
            MainDeviceId = networkEvent.SourceDeviceId,
            MainApplicationId = networkEvent.ApplicationId,
            RiskLevel = networkEvent.RiskLevel,
            Status = IncidentStatus.Open,
            EventCount = 1,
            StartedUtc = createdUtc,
            LastUpdatedUtc = now
        };
    }

    private static string BuildTitle(NetworkEvent networkEvent)
    {
        var app = ReadDetail(networkEvent.DetailsJson, "app");
        var deviceName = ReadDetail(networkEvent.DetailsJson, "deviceName");
        return networkEvent.EventType switch
        {
            "CameraActivated" => BuildActorTitle("Camera access", app, deviceName),
            "MicrophoneActivated" => BuildActorTitle("Microphone access", app, deviceName),
            "NewDeviceObserved" => string.IsNullOrWhiteSpace(deviceName) ? "New device observed" : $"New device observed: {deviceName}",
            "ListeningPortApplicationChanged" => BuildActorTitle("Port ownership changed", app, deviceName),
            "NewListeningPort" => BuildActorTitle("Network port opened", app, deviceName),
            _ => string.IsNullOrWhiteSpace(networkEvent.Summary) ? networkEvent.EventType : networkEvent.Summary
        };
    }

    private static string BuildActorTitle(string prefix, string app, string deviceName)
    {
        if (!string.IsNullOrWhiteSpace(app) && !string.IsNullOrWhiteSpace(deviceName))
        {
            return $"{prefix}: {app} on {deviceName}";
        }

        if (!string.IsNullOrWhiteSpace(app))
        {
            return $"{prefix}: {app}";
        }

        return string.IsNullOrWhiteSpace(deviceName) ? prefix : $"{prefix}: {deviceName}";
    }

    private static string BuildSummary(NetworkEvent networkEvent)
    {
        var whatHappened = ReadDetail(networkEvent.DetailsJson, "whatHappened");
        var why = ReadDetail(networkEvent.DetailsJson, "whyItMatters");
        var action = ReadDetail(networkEvent.DetailsJson, "suggestedAction");
        var summary = string.IsNullOrWhiteSpace(whatHappened) ? networkEvent.Summary : whatHappened;

        if (!string.IsNullOrWhiteSpace(why))
        {
            summary = $"{summary} Why: {why}";
        }

        if (!string.IsNullOrWhiteSpace(action))
        {
            summary = $"{summary} Action: {action}";
        }

        return summary;
    }

    private static string ReadDetail(string detailsJson, string propertyName)
    {
        if (string.IsNullOrWhiteSpace(detailsJson))
        {
            return string.Empty;
        }

        try
        {
            using var document = JsonDocument.Parse(detailsJson);
            if (!document.RootElement.TryGetProperty(propertyName, out var value) || value.ValueKind != JsonValueKind.String)
            {
                return string.Empty;
            }

            return value.GetString()!;
        }
        catch (JsonException)
        {
            return string.Empty;
        }
    }
}