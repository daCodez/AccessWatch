using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text.RegularExpressions;
using AccessWatch.Core;

namespace AccessWatch.Detection;

/// <summary>
/// Scans Windows listening TCP ports using netstat ownership data.
/// </summary>
public sealed class ListeningPortScanner : IListeningPortScanner
{
    private static readonly Regex NetstatTcpLine = new(
        @"^\s*TCP\s+(?<local>\S+)\s+\S+\s+(?<state>LISTENING)\s+(?<pid>\d+)\s*$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

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

        foreach (var line in output.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var match = NetstatTcpLine.Match(line);
            if (!match.Success || !line.Contains("LISTENING", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!TrySplitEndpoint(match.Groups["local"].Value, out var localAddress, out var portNumber))
            {
                continue;
            }

            var processId = int.Parse(match.Groups["pid"].Value);
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

    private static bool TrySplitEndpoint(string endpoint, out string address, out int port)
    {
        address = string.Empty;
        port = 0;
        var lastColon = endpoint.LastIndexOf(':');
        if (lastColon <= 0 || lastColon == endpoint.Length - 1)
        {
            return false;
        }

        address = endpoint[..lastColon].Trim('[', ']');
        return int.TryParse(endpoint[(lastColon + 1)..], out port);
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
