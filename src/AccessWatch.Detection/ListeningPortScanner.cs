using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;
using AccessWatch.Core;

namespace AccessWatch.Detection;

/// <summary>
/// Scans Windows listening TCP ports using netstat ownership data.
/// </summary>
public sealed partial class ListeningPortScanner : IListeningPortScanner
{
    private readonly IAppIdentityResolver identityResolver;

    /// <summary>
    /// Initializes a new listening port scanner.
    /// </summary>
    /// <param name="identityResolver">Resolver used for owning process metadata.</param>
    public ListeningPortScanner(IAppIdentityResolver identityResolver)
    {
        this.identityResolver = identityResolver;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<ListeningPort>> ScanAsync(CancellationToken cancellationToken)
    {
        var output = await RunNetstatAsync(cancellationToken);
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
            var match = NetstatTcpLine().Match(line);
            if (!match.Success || !line.Contains("LISTENING", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!TrySplitEndpoint(match.Groups["local"].Value, out var localAddress, out var portNumber))
            {
                continue;
            }

            var processId = int.TryParse(match.Groups["pid"].Value, out var pid) ? pid : (int?)null;
            ports.Add(new ListeningPort
            {
                PortNumber = portNumber,
                Protocol = "TCP",
                LocalAddress = localAddress,
                Reachability = ClassifyReachability(localAddress),
                OwningProcessId = processId,
                Application = processId is null ? null : identityResolver.Resolve(processId.Value),
                FirstSeenUtc = observedAtUtc,
                LastSeenUtc = observedAtUtc
            });
        }

        return ports;
    }

    private static async Task<string> RunNetstatAsync(CancellationToken cancellationToken)
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

    [GeneratedRegex(@"^\s*TCP\s+(?<local>\S+)\s+\S+\s+(?<state>LISTENING)\s+(?<pid>\d+)\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex NetstatTcpLine();
}
