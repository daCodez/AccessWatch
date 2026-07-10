using System.Net;
using AccessWatch.AI;
using AccessWatch.Core;

namespace AccessWatch.Tests;

/// <summary>
/// Verifies support bridge AI behavior.
/// </summary>
public sealed class SupportBridgeInvestigationBridgeTests
{
    /// <summary>
    /// Verifies the bridge posts redacted investigation requests to the configured localhost endpoint.
    /// </summary>
    [Fact]
    public async Task ReviewIncidentAsync_WithLocalJsonResponse_ReturnsAiResult()
    {
        var handler = new RecordingHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""
                {
                  "provider": "Support Bridge",
                  "summary": "Local-only listener looks expected.",
                  "recommendedAction": "Watch until the process identity is confirmed.",
                  "confidence": "Medium"
                }
                """)
        });
        var bridge = new SupportBridgeInvestigationBridge(new HttpClient(handler));
        var settings = new AccessWatchSettings { SupportBridgeEndpoint = "http://localhost:7331/accesswatch/investigations" };

        var result = await bridge.ReviewIncidentAsync(CreateRequest(), settings, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Equal("Support Bridge", result.Provider);
        Assert.Equal("Local-only listener looks expected.", result.Summary);
        Assert.Equal("Watch until the process identity is confirmed.", result.RecommendedAction);
        Assert.Equal("Medium", result.Confidence);
        Assert.Equal(HttpMethod.Post, handler.Request?.Method);
        Assert.Equal(settings.SupportBridgeEndpoint, handler.Request?.RequestUri?.ToString());
    }

    /// <summary>
    /// Verifies the bridge refuses non-local endpoints for this private-network release.
    /// </summary>
    [Fact]
    public async Task ReviewIncidentAsync_WithRemoteEndpoint_ReturnsUnavailableWithoutSending()
    {
        var handler = new RecordingHandler(new HttpResponseMessage(HttpStatusCode.OK));
        var bridge = new SupportBridgeInvestigationBridge(new HttpClient(handler));
        var settings = new AccessWatchSettings { SupportBridgeEndpoint = "https://example.com/accesswatch" };

        var result = await bridge.ReviewIncidentAsync(CreateRequest(), settings, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Contains("must be localhost", result.Summary);
        Assert.Null(handler.Request);
    }

    /// <summary>
    /// Verifies redirects are rejected so a local bridge cannot forward an investigation elsewhere.
    /// </summary>
    [Fact]
    public async Task ReviewIncidentAsync_WithRedirectResponse_ReturnsUnavailableWithoutFollowingRedirect()
    {
        var handler = new RecordingHandler(new HttpResponseMessage(HttpStatusCode.TemporaryRedirect)
        {
            Headers = { Location = new Uri("https://example.com/investigations") }
        });
        var bridge = new SupportBridgeInvestigationBridge(new HttpClient(handler));

        var result = await bridge.ReviewIncidentAsync(CreateRequest(), new AccessWatchSettings(), CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Contains("307", result.Summary);
        Assert.Equal("http://localhost:8123/accesswatch/investigations", handler.Request?.RequestUri?.ToString());
    }

    /// <summary>
    /// Verifies invalid bridge URLs are reported as operator-friendly unavailable results.
    /// </summary>
    [Fact]
    public async Task ReviewIncidentAsync_WithInvalidEndpoint_ReturnsUnavailable()
    {
        var bridge = new SupportBridgeInvestigationBridge();
        var settings = new AccessWatchSettings { SupportBridgeEndpoint = "not a url" };

        var result = await bridge.ReviewIncidentAsync(CreateRequest(), settings, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Contains("not a valid URL", result.Summary);
    }

    /// <summary>
    /// Verifies bridge HTTP errors are converted into safe unavailable results.
    /// </summary>
    [Fact]
    public async Task ReviewIncidentAsync_WithGatewayError_ReturnsUnavailable()
    {
        var bridge = new SupportBridgeInvestigationBridge(new HttpClient(new RecordingHandler(new HttpResponseMessage(HttpStatusCode.BadGateway)
        {
            ReasonPhrase = "No agent"
        })));

        var result = await bridge.ReviewIncidentAsync(CreateRequest(), new AccessWatchSettings(), CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Contains("502", result.Summary);
        Assert.Contains("No agent", result.Summary);
    }

    /// <summary>
    /// Verifies plain-text gateway replies still appear in the in-app review surface.
    /// </summary>
    [Fact]
    public async Task ReviewIncidentAsync_WithPlainTextResponse_ReturnsTextSummary()
    {
        var bridge = new SupportBridgeInvestigationBridge(new HttpClient(new RecordingHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("This looks like a localhost-only development server.")
        })));

        var result = await bridge.ReviewIncidentAsync(CreateRequest(), new AccessWatchSettings(), CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Equal("This looks like a localhost-only development server.", result.Summary);
        Assert.Equal("Review the evidence in AccessWatch before trusting or blocking.", result.RecommendedAction);
        Assert.Equal("Not provided", result.Confidence);
    }

    /// <summary>
    /// Verifies empty gateway replies are treated as unavailable instead of trusted analysis.
    /// </summary>
    [Fact]
    public async Task ReviewIncidentAsync_WithEmptyResponse_ReturnsUnavailable()
    {
        var bridge = new SupportBridgeInvestigationBridge(new HttpClient(new RecordingHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(" ")
        })));

        var result = await bridge.ReviewIncidentAsync(CreateRequest(), new AccessWatchSettings(), CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Contains("empty review", result.Summary);
    }

    /// <summary>
    /// Verifies oversized bridge replies are rejected before they can fill the review surface.
    /// </summary>
    [Fact]
    public async Task ReviewIncidentAsync_WithOversizedResponse_ReturnsUnavailable()
    {
        var oversizedReview = new string('x', 128 * 1024 + 1);
        var bridge = new SupportBridgeInvestigationBridge(new HttpClient(new RecordingHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(oversizedReview)
        })));

        var result = await bridge.ReviewIncidentAsync(CreateRequest(), new AccessWatchSettings(), CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Contains("too large", result.Summary);
    }

    /// <summary>
    /// Verifies network failures are presented safely inside AccessWatch.
    /// </summary>
    [Fact]
    public async Task ReviewIncidentAsync_WithNetworkFailure_ReturnsUnavailable()
    {
        var bridge = new SupportBridgeInvestigationBridge(new HttpClient(new ThrowingHandler(new HttpRequestException("connection refused"))));

        var result = await bridge.ReviewIncidentAsync(CreateRequest(), new AccessWatchSettings(), CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Contains("not reachable", result.Summary);
        Assert.Contains("connection refused", result.Summary);
    }

    /// <summary>
    /// Verifies bridge timeouts are presented safely inside AccessWatch.
    /// </summary>
    [Fact]
    public async Task ReviewIncidentAsync_WithTimeout_ReturnsUnavailable()
    {
        var bridge = new SupportBridgeInvestigationBridge(new HttpClient(new ThrowingHandler(new OperationCanceledException())));

        var result = await bridge.ReviewIncidentAsync(CreateRequest(), new AccessWatchSettings(), CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Contains("timed out", result.Summary);
    }

    /// <summary>
    /// Verifies caller-requested cancellation remains observable by the caller.
    /// </summary>
    [Fact]
    public async Task ReviewIncidentAsync_WithCallerCancellation_Throws()
    {
        using var source = new CancellationTokenSource();
        await source.CancelAsync();
        var bridge = new SupportBridgeInvestigationBridge(new HttpClient(new ThrowingHandler(new OperationCanceledException())));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => bridge.ReviewIncidentAsync(CreateRequest(), new AccessWatchSettings(), source.Token));
    }

    private static AiInvestigationRequest CreateRequest() =>
        new(
            "AccessWatch",
            "Incident",
            "TCP listener opened",
            "High",
            "Open",
            "{\"riskLevel\":\"High\"}",
            "Explain what to verify before trusting this incident.");

    private sealed class RecordingHandler(HttpResponseMessage response) : HttpMessageHandler
    {
        public HttpRequestMessage? Request { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Request = request;
            return Task.FromResult(response);
        }
    }

    private sealed class ThrowingHandler(Exception exception) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromException<HttpResponseMessage>(exception);
    }
}