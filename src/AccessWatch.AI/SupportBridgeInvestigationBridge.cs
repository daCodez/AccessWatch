using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Json;
using System.Text;
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
    private const int MaxResponseCharacters = 128 * 1024;
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
            using var message = new HttpRequestMessage(HttpMethod.Post, endpoint)
            {
                Content = JsonContent.Create(request, options: SerializerOptions)
            };
            using var response = await httpClient.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return AiInvestigationResult.Unavailable(ProviderName, $"Support bridge returned {(int)response.StatusCode} {response.ReasonPhrase}.");
            }

            if (response.Content.Headers.ContentLength is > MaxResponseCharacters)
            {
                return AiInvestigationResult.Unavailable(ProviderName, "Support bridge returned a review that is too large to display safely.");
            }

            var responseText = await ReadBoundedResponseAsync(response.Content, cancellationToken).ConfigureAwait(false);
            return ParseResponse(responseText);
        }
        catch (SupportBridgeResponseTooLargeException)
        {
            return AiInvestigationResult.Unavailable(ProviderName, "Support bridge returned a review that is too large to display safely.");
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

    private static async Task<string> ReadBoundedResponseAsync(HttpContent content, CancellationToken cancellationToken)
    {
        await using var responseStream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var reader = new StreamReader(responseStream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 4096, leaveOpen: false);
        var builder = new StringBuilder();
        var buffer = new char[4096];

        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return builder.ToString();
            }

            if (builder.Length > MaxResponseCharacters - read)
            {
                throw new SupportBridgeResponseTooLargeException();
            }

            builder.Append(buffer, 0, read);
        }
    }

    private sealed class SupportBridgeResponseTooLargeException : Exception;

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