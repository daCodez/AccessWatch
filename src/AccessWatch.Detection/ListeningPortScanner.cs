using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using AccessWatch.Core;

namespace AccessWatch.Detection;

/// <summary>
/// Scans Windows listening TCP ports using netstat ownership data.
/// </summary>
public sealed class ListeningPortScanner : IListeningPortScanner
{
    private readonly IAppIdentityResolver identityResolver;
    private readonly INetstatRunner netstatRunner;

    /// <summary>
    /// Initializes a new listening port scanner.
    /// </summary>
    /// <param name="identityResolver">Resolver used for owning process metadata.</param>
    /// <param name="netstatRunner">Runner used to collect netstat output.</param>
    public ListeningPortScanner(IAppIdentityResolver identityResolver, INetstatRunner? netstatRunner = null)
    {
        this.identityResolver = identityResolver;
        this.netstatRunner = netstatRunner ?? new NetstatRunner();
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<ListeningPort>> ScanAsync(CancellationToken cancellationToken)
    {
        var output = await netstatRunner.RunAsync(cancellationToken);
        var now = DateTimeOffset.UtcNow;
        return ParseNetstatOutput(output, now)
            .OrderBy(port => port.PortNumber)
            .ThenBy(port => port.LocalAddress, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <summary>
    /// Parses netstat output into listening port observations.
    /// </summary>
    /// <param name="output">Raw netstat output.</param>
    /// <param name="observedAtUtc">Observation time.</param>
    /// <returns>Parsed listening ports.</returns>
    public IReadOnlyList<ListeningPort> ParseNetstatOutput(string output, DateTimeOffset observedAtUtc)
    {
        var ports = new List<ListeningPort>();

        foreach (var rawLine in output.AsSpan().EnumerateLines())
        {
            var line = rawLine.Trim();
            if (!TryReadNetstatLine(line, out var localAddress, out var portNumber, out var processId))
            {
                continue;
            }

            ports.Add(new ListeningPort
            {
                PortNumber = portNumber,
                Protocol = "TCP",
                LocalAddress = localAddress,
                Reachability = ClassifyReachability(localAddress),
                OwningProcessId = processId,
                Application = identityResolver.Resolve(processId),
                FirstSeenUtc = observedAtUtc,
                LastSeenUtc = observedAtUtc
            });
        }

        return ports;
    }

    private static bool TryReadNetstatLine(ReadOnlySpan<char> line, out string localAddress, out int portNumber, out int processId)
    {
        localAddress = string.Empty;
        portNumber = 0;
        processId = 0;
        if (!TryReadToken(ref line, out var protocol) || !protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!TryReadToken(ref line, out var localEndpoint) ||
            !TryReadToken(ref line, out _) ||
            !TryReadToken(ref line, out var state) ||
            !state.Equals("LISTENING", StringComparison.OrdinalIgnoreCase) ||
            !TryReadToken(ref line, out var pid) ||
            !TrySplitEndpoint(localEndpoint, out localAddress, out portNumber))
        {
            return false;
        }

        return int.TryParse(pid, NumberStyles.None, CultureInfo.InvariantCulture, out processId);
    }

    private static bool TryReadToken(ref ReadOnlySpan<char> value, out ReadOnlySpan<char> token)
    {
        value = value.TrimStart();
        if (value.IsEmpty)
        {
            token = default;
            return false;
        }

        var tokenLength = 0;
        while (tokenLength < value.Length && !char.IsWhiteSpace(value[tokenLength]))
        {
            tokenLength++;
        }

        token = value[..tokenLength];
        value = value[tokenLength..];
        return true;
    }

    private static bool TrySplitEndpoint(ReadOnlySpan<char> endpoint, out string address, out int port)
    {
        address = string.Empty;
        port = 0;
        var lastColon = endpoint.LastIndexOf(':');
        if (lastColon <= 0 || lastColon == endpoint.Length - 1)
        {
            return false;
        }

        var addressSpan = endpoint[..lastColon];
        if (addressSpan is ['[', .., ']'])
        {
            addressSpan = addressSpan[1..^1];
        }

        address = addressSpan.ToString();
        return int.TryParse(endpoint[(lastColon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out port);
    }

    private static PortReachability ClassifyReachability(string localAddress)
    {
        // Binding to any-address means LAN peers can usually reach the service, so it deserves more attention.
        if (localAddress is "0.0.0.0" or "::" or "[::]")
        {
            return PortReachability.NetworkReachable;
        }

        if (IPAddress.TryParse(localAddress, out var ipAddress))
        {
            return IPAddress.IsLoopback(ipAddress) ? PortReachability.LocalOnly : PortReachability.NetworkReachable;
        }

        return PortReachability.Unknown;
    }
}

/// <summary>
/// Runs netstat and returns its output.
/// </summary>
public interface INetstatRunner
{
    /// <summary>
    /// Runs netstat for listening TCP port ownership data.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Raw netstat output.</returns>
    Task<string> RunAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Windows process-backed netstat runner.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Thin Windows process boundary; parser and scanner orchestration are covered with deterministic runner fakes.")]
public sealed class NetstatRunner : INetstatRunner
{
    /// <inheritdoc />
    public async Task<string> RunAsync(CancellationToken cancellationToken)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "netstat.exe",
            Arguments = "-ano -p tcp",
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        }) ?? throw new InvalidOperationException("Unable to start netstat.exe.");

        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        if (process.ExitCode != 0)
        {
            var error = await errorTask;
            throw new InvalidOperationException($"netstat.exe failed with exit code {process.ExitCode}: {error}");
        }

        return await outputTask;
    }
}
