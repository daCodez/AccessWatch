using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;
using AccessWatch.Core;

namespace AccessWatch.Detection;

/// <summary>
/// Discovers local-network devices from the Windows ARP cache.
/// </summary>
public sealed class NetworkDeviceDiscoveryService : INetworkDeviceDiscoveryService
{
    private static readonly Regex ArpLine = new(
        @"^\s*(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<mac>[0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s+\S+\s*$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly IArpTableRunner arpTableRunner;

    /// <summary>
    /// Initializes a new device discovery service using the default ARP runner.
    /// </summary>
    public NetworkDeviceDiscoveryService()
        : this(new ArpTableRunner())
    {
    }

    /// <summary>
    /// Initializes a new device discovery service with a supplied ARP runner.
    /// </summary>
    /// <param name="arpTableRunner">Runner used to collect ARP output.</param>
    public NetworkDeviceDiscoveryService(IArpTableRunner arpTableRunner)
    {
        this.arpTableRunner = arpTableRunner;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<NetworkDevice>> DiscoverAsync(CancellationToken cancellationToken)
    {
        var output = await arpTableRunner.RunAsync(cancellationToken);
        return ParseArpOutput(output, DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Parses ARP output into local-network device observations.
    /// </summary>
    /// <param name="output">Raw ARP output.</param>
    /// <param name="observedAtUtc">Observation time.</param>
    /// <returns>Parsed device observations.</returns>
    public IReadOnlyList<NetworkDevice> ParseArpOutput(string output, DateTimeOffset observedAtUtc)
    {
        var devices = new List<NetworkDevice>();
        foreach (var line in output.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var match = ArpLine.Match(line);
            if (!match.Success)
            {
                continue;
            }

            devices.Add(new NetworkDevice
            {
                IpAddress = match.Groups["ip"].Value,
                MacAddress = match.Groups["mac"].Value.Replace('-', ':').ToUpperInvariant(),
                DeviceTypeGuess = "Unknown",
                TrustStatus = TrustStatus.Unknown,
                RiskStatus = RiskStatus.Normal,
                FirstSeenUtc = observedAtUtc,
                LastSeenUtc = observedAtUtc,
                LastConfirmedUtc = observedAtUtc
            });
        }

        return devices
            .OrderBy(device => device.IpAddress, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}

/// <summary>
/// Runs an ARP table command and returns its output.
/// </summary>
public interface IArpTableRunner
{
    /// <summary>
    /// Runs the local ARP table command.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Raw ARP table output.</returns>
    Task<string> RunAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Windows process-backed ARP table runner.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Thin Windows process boundary; parser behavior is covered with deterministic runner fakes.")]
public sealed class ArpTableRunner : IArpTableRunner
{
    /// <inheritdoc />
    public async Task<string> RunAsync(CancellationToken cancellationToken)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "arp.exe",
            Arguments = "-a",
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        }) ?? throw new InvalidOperationException("Unable to start arp.exe.");

        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        if (process.ExitCode != 0)
        {
            var error = await errorTask;
            throw new InvalidOperationException($"arp.exe failed with exit code {process.ExitCode}: {error}");
        }

        return await outputTask;
    }
}
