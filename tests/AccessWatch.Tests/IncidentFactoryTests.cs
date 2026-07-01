using AccessWatch.Core;
using AccessWatch.Service;

namespace AccessWatch.Tests;

/// <summary>
/// Tests conversion from review-worthy events into dashboard incidents.
/// </summary>
public sealed class IncidentFactoryTests
{
    /// <summary>
    /// Verifies silent low-risk events remain event history instead of becoming incidents.
    /// </summary>
    [Fact]
    public void CreateReviewIncident_SkipsSilentLowRiskEvents()
    {
        var incident = IncidentFactory.CreateReviewIncident(new NetworkEvent { RiskLevel = RiskLevel.Low }, DateTimeOffset.UtcNow);

        Assert.Null(incident);
    }

    /// <summary>
    /// Verifies incident timestamps fall back to the current time when an event has no persisted timestamp yet.
    /// </summary>
    [Fact]
    public void CreateReviewIncident_UsesCurrentTimeWhenEventTimestampIsMissing()
    {
        var now = new DateTimeOffset(2026, 7, 1, 12, 0, 0, TimeSpan.Zero);

        var incident = IncidentFactory.CreateReviewIncident(
            new NetworkEvent
            {
                EventType = "UnknownEvent",
                Summary = "Something unusual happened.",
                RiskLevel = RiskLevel.Medium,
                WasUserNotified = true
            },
            now);

        Assert.NotNull(incident);
        Assert.Equal("Something unusual happened.", incident.Title);
        Assert.Equal("Something unusual happened.", incident.Summary);
        Assert.Equal(now, incident.StartedUtc);
        Assert.Equal(now, incident.LastUpdatedUtc);
    }

    /// <summary>
    /// Verifies title fallbacks when event details include only part of the app/device context.
    /// </summary>
    [Theory]
    [InlineData("NewListeningPort", "{\"app\":\"Only App\"}", "Network port opened: Only App")]
    [InlineData("NewListeningPort", "{\"deviceName\":\"only-device\"}", "Network port opened: only-device")]
    [InlineData("NewListeningPort", "{}", "Network port opened")]
    [InlineData("NewDeviceObserved", "{}", "New device observed")]
    [InlineData("UnmappedEvent", "{}", "UnmappedEvent")]
    public void CreateReviewIncident_UsesTitleFallbacks(string eventType, string detailsJson, string expectedTitle)
    {
        var incident = IncidentFactory.CreateReviewIncident(
            new NetworkEvent
            {
                EventType = eventType,
                DetailsJson = detailsJson,
                RiskLevel = RiskLevel.High,
                WasUserNotified = true,
                CreatedUtc = DateTimeOffset.UtcNow
            },
            DateTimeOffset.UtcNow);

        Assert.NotNull(incident);
        Assert.Equal(expectedTitle, incident.Title);
    }

    /// <summary>
    /// Verifies malformed or non-string details safely fall back to the raw event summary.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("{\"whatHappened\":42,\"whyItMatters\":false,\"suggestedAction\":{}}")]
    public void CreateReviewIncident_UsesSummaryWhenDetailsAreMissingOrInvalid(string detailsJson)
    {
        var incident = IncidentFactory.CreateReviewIncident(
            new NetworkEvent
            {
                EventType = "UnmappedEvent",
                Summary = "Fallback summary.",
                DetailsJson = detailsJson,
                RiskLevel = RiskLevel.High,
                WasUserNotified = true,
                CreatedUtc = DateTimeOffset.UtcNow
            },
            DateTimeOffset.UtcNow);

        Assert.NotNull(incident);
        Assert.Equal("Fallback summary.", incident.Title);
        Assert.Equal("Fallback summary.", incident.Summary);
    }
}