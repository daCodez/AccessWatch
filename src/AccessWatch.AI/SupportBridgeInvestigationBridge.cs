using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Json;
using System.Text.Json;
using AccessWatch.Core;

namespace AccessWatch.AI;

/// <summary>
/// Sends redacted AccessWatch investigation requests to a local support bridge gateway.
/// </summary>
[ExcludeFromCodeCoverage]
public sealed class SupportBridgeInvestigationBridge : IAiInvestigationBridge
{
    private const string ProviderName = "Support Bridge";
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly HttpClient httpClient;

    /// <summary>
    /// Initializes a new support bridge gateway.
    /// </summary>
    /// <param name="httpClient">HTTP client used for local gateway calls.</param>
    public SupportBridgeInvestigationBridge(HttpClient? httpClient = null)
    {
        this.httpClient = httpClient ?? CreateLocalBridgeClient();
    }

    private static HttpClient CreateLocalBridgeClient()
    {
        return new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromSeconds(20)
        };
    }

    /// <inheritdoc />
    public async Task<AiInvestigationResult> ReviewIncidentAsync(
        AiInvestigationRequest request,
        AccessWatchSettings settings,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(settings.SupportBridgeEndpoint, UriKind.Absolute, out var endpoint))
        {
            return AiInvestigationResult.Unavailable(ProviderName, "Support bridge endpoint is not a valid URL.");
        }

        if (!IsLocalEndpoint(endpoint))
        {
            return AiInvestigationResult.Unavailable(ProviderName, "Support bridge endpoint must be localhost or loopback for this release.");
        }

        try
        {
            using var response = await httpClient.PostAsJsonAsync(endpoint, request, SerializerOptions, cancellationToken).ConfigureAwait(false);
            var responseText = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return AiInvestigationResult.Unavailable(ProviderName, $"Support bridge returned {(int)response.StatusCode} {response.ReasonPhrase}.");
            }

            return ParseResponse(responseText);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return AiInvestigationResult.Unavailable(ProviderName, "Support bridge timed out before returning a review.");
        }
        catch (HttpRequestException ex)
        {
            return AiInvestigationResult.Unavailable(ProviderName, $"Support bridge is not reachable: {ex.Message}");
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return AiInvestigationResult.Unavailable(ProviderName, "Support bridge timed out before returning a review.");
        }
    }

    private static AiInvestigationResult ParseResponse(string responseText)
    {
        if (string.IsNullOrWhiteSpace(responseText))
        {
            return AiInvestigationResult.Unavailable(ProviderName, "Support bridge returned an empty review.");
        }

        try
        {
            using var document = JsonDocument.Parse(responseText);
            var root = document.RootElement;
            var summary = ReadString(root, "summary", "analysis", "message", "text");
            if (string.IsNullOrWhiteSpace(summary))
            {
                summary = responseText.Trim();
            }

            return new AiInvestigationResult(
                true,
                ReadString(root, "provider") ?? ProviderName,
                summary,
                ReadString(root, "recommendedAction", "recommendation", "action") ?? "Review the evidence in AccessWatch before trusting or blocking.",
                ReadString(root, "confidence") ?? "Not provided",
                responseText);
        }
        catch (JsonException)
        {
            return new AiInvestigationResult(
                true,
                ProviderName,
                responseText.Trim(),
                "Review the evidence in AccessWatch before trusting or blocking.",
                "Not provided",
                responseText);
        }
    }

    private static string? ReadString(JsonElement root, params string[] names)
    {
        foreach (var name in names)
        {
            if (root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String)
            {
                return value.GetString();
            }
        }

        return null;
    }

    private static bool IsLocalEndpoint(Uri endpoint) =>
        endpoint.IsLoopback || string.Equals(endpoint.Host, "localhost", StringComparison.OrdinalIgnoreCase);
}