using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using AccessWatch.Core;

namespace AccessWatch.Detection;

/// <summary>
/// Discovers local-network devices from Windows network tables.
/// </summary>
public sealed class NetworkDeviceDiscoveryService : INetworkDeviceDiscoveryService
{
    private const string NeighborTableNote = "Seen in Windows neighbor table; useful for phones, Phone Link devices, and quiet Wi-Fi devices.";
    private readonly IArpTableRunner arpTableRunner;
    private readonly IDeviceHostnameResolver hostnameResolver;
    private readonly INeighborTableRunner? neighborTableRunner;

    /// <summary>
    /// Initializes a new device discovery service using the default Windows runners.
    /// </summary>
    public NetworkDeviceDiscoveryService()
        : this(new ArpTableRunner(), new DnsDeviceHostnameResolver(), new NetshNeighborTableRunner())
    {
    }

    /// <summary>
    /// Initializes a new device discovery service with a supplied ARP runner.
    /// </summary>
    /// <param name="arpTableRunner">Runner used to collect ARP output.</param>
    public NetworkDeviceDiscoveryService(IArpTableRunner arpTableRunner)
        : this(arpTableRunner, new DnsDeviceHostnameResolver())
    {
    }

    /// <summary>
    /// Initializes a new device discovery service with supplied ARP and hostname resolvers.
    /// </summary>
    /// <param name="arpTableRunner">Runner used to collect ARP output.</param>
    /// <param name="hostnameResolver">Resolver used to label devices by hostname.</param>
    public NetworkDeviceDiscoveryService(IArpTableRunner arpTableRunner, IDeviceHostnameResolver hostnameResolver)
        : this(arpTableRunner, hostnameResolver, null)
    {
    }

    /// <summary>
    /// Initializes a new device discovery service with supplied ARP, hostname, and neighbor table readers.
    /// </summary>
    /// <param name="arpTableRunner">Runner used to collect ARP output.</param>
    /// <param name="hostnameResolver">Resolver used to label devices by hostname.</param>
    /// <param name="neighborTableRunner">Optional runner used to collect Windows neighbor table output.</param>
    public NetworkDeviceDiscoveryService(
        IArpTableRunner arpTableRunner,
        IDeviceHostnameResolver hostnameResolver,
        INeighborTableRunner? neighborTableRunner)
    {
        this.arpTableRunner = arpTableRunner;
        this.hostnameResolver = hostnameResolver;
        this.neighborTableRunner = neighborTableRunner;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<NetworkDevice>> DiscoverAsync(CancellationToken cancellationToken)
    {
        var observedAtUtc = DateTimeOffset.UtcNow;
        var arpOutput = await arpTableRunner.RunAsync(cancellationToken);
        var devices = ParseArpOutput(arpOutput, observedAtUtc);
        if (neighborTableRunner is not null)
        {
            var neighborOutput = await neighborTableRunner.RunAsync(cancellationToken);
            devices = MergeDeviceObservations(devices, ParseNeighborOutput(neighborOutput, observedAtUtc));
        }

        return await AddHostnamesAsync(devices, cancellationToken);
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
        foreach (var rawLine in output.AsSpan().EnumerateLines())
        {
            if (!TryReadAddressAndMacLine(rawLine.Trim(), out var ipAddress, out var macAddress))
            {
                continue;
            }

            if (!DeviceAddressClassifier.IsUsableDeviceAddress(ipAddress, macAddress))
            {
                continue;
            }

            devices.Add(new NetworkDevice
            {
                IpAddress = ipAddress,
                MacAddress = macAddress,
                DeviceTypeGuess = "Unknown",
                TrustStatus = TrustStatus.Unknown,
                RiskStatus = RiskStatus.Normal,
                FirstSeenUtc = observedAtUtc,
                LastSeenUtc = observedAtUtc,
                LastConfirmedUtc = observedAtUtc
            });
        }

        return SortDevices(devices);
    }

    /// <summary>
    /// Parses Windows neighbor table output into device observations.
    /// </summary>
    /// <param name="output">Raw neighbor table output.</param>
    /// <param name="observedAtUtc">Observation time.</param>
    /// <returns>Parsed device observations.</returns>
    public IReadOnlyList<NetworkDevice> ParseNeighborOutput(string output, DateTimeOffset observedAtUtc)
    {
        var devices = new List<NetworkDevice>();
        foreach (var rawLine in output.AsSpan().EnumerateLines())
        {
            if (!TryReadAddressAndMacLine(rawLine.Trim(), out var ipAddress, out var macAddress))
            {
                continue;
            }

            if (!DeviceAddressClassifier.IsUsableDeviceAddress(ipAddress, macAddress))
            {
                continue;
            }

            devices.Add(new NetworkDevice
            {
                IpAddress = ipAddress,
                MacAddress = macAddress,
                DeviceTypeGuess = "Network neighbor",
                TrustStatus = TrustStatus.Unknown,
                RiskStatus = RiskStatus.Normal,
                Notes = NeighborTableNote,
                FirstSeenUtc = observedAtUtc,
                LastSeenUtc = observedAtUtc,
                LastConfirmedUtc = observedAtUtc
            });
        }

        return SortDevices(devices);
    }

    private static IReadOnlyList<NetworkDevice> MergeDeviceObservations(IReadOnlyList<NetworkDevice> primary, IReadOnlyList<NetworkDevice> secondary)
    {
        if (secondary.Count == 0)
        {
            return primary;
        }

        var devices = new List<NetworkDevice>(primary.Count + secondary.Count);
        devices.AddRange(primary);
        foreach (var candidate in secondary)
        {
            if (devices.Any(device => SameDevice(device, candidate)))
            {
                continue;
            }

            devices.Add(candidate);
        }

        return SortDevices(devices);
    }

    private static bool SameDevice(NetworkDevice left, NetworkDevice right)
    {
        return string.Equals(left.IpAddress, right.IpAddress, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(left.MacAddress, right.MacAddress, StringComparison.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<NetworkDevice> SortDevices(List<NetworkDevice> devices)
    {
        return devices
            .OrderBy(device => device.IpAddress, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static bool TryReadAddressAndMacLine(ReadOnlySpan<char> line, out string ipAddress, out string macAddress)
    {
        ipAddress = string.Empty;
        macAddress = string.Empty;
        if (!TryReadToken(ref line, out var ipAddressToken) ||
            !TryReadToken(ref line, out var macAddressToken) ||
            !TryReadToken(ref line, out _))
        {
            return false;
        }

        if (!LooksLikeIpv4Address(ipAddressToken) || !TryNormalizeMacAddress(macAddressToken, out macAddress))
        {
            return false;
        }

        ipAddress = ipAddressToken.ToString();
        return true;
    }

    private static bool LooksLikeIpv4Address(ReadOnlySpan<char> value)
    {
        var dots = 0;
        foreach (var character in value)
        {
            if (character == '.')
            {
                dots++;
                continue;
            }

            if (!char.IsAsciiDigit(character))
            {
                return false;
            }
        }

        return dots == 3;
    }

    private static bool TryNormalizeMacAddress(ReadOnlySpan<char> value, out string macAddress)
    {
        macAddress = string.Empty;
        if (value.Length != 17)
        {
            return false;
        }

        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if ((index + 1) % 3 == 0)
            {
                if (character != '-')
                {
                    return false;
                }
            }
            else if (!char.IsAsciiHexDigit(character))
            {
                return false;
            }
        }

        macAddress = string.Create(17, value, static (destination, source) =>
        {
            for (var index = 0; index < source.Length; index++)
            {
                destination[index] = source[index] == '-'
                    ? ':'
                    : char.ToUpperInvariant(source[index]);
            }
        });
        return true;
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

    private async Task<IReadOnlyList<NetworkDevice>> AddHostnamesAsync(IReadOnlyList<NetworkDevice> devices, CancellationToken cancellationToken)
    {
        var namedDevices = new List<NetworkDevice>(devices.Count);
        foreach (var device in devices)
        {
            var hostname = await hostnameResolver.ResolveHostnameAsync(device.IpAddress, cancellationToken);
            namedDevices.Add(string.IsNullOrWhiteSpace(hostname) ? device : device with { Hostname = hostname.Trim().TrimEnd('.') });
        }

        return namedDevices;
    }
}

/// <summary>
/// Resolves a device hostname from an IP address.
/// </summary>
public interface IDeviceHostnameResolver
{
    /// <summary>
    /// Resolves a hostname for an IP address.
    /// </summary>
    /// <param name="ipAddress">IP address to resolve.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Hostname when available; otherwise null.</returns>
    Task<string?> ResolveHostnameAsync(string ipAddress, CancellationToken cancellationToken);
}

/// <summary>
/// DNS-backed device hostname resolver.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Thin DNS boundary; hostname enrichment is covered with deterministic resolver fakes.")]
public sealed class DnsDeviceHostnameResolver : IDeviceHostnameResolver
{
    /// <inheritdoc />
    public async Task<string?> ResolveHostnameAsync(string ipAddress, CancellationToken cancellationToken)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(ipAddress, cancellationToken);
            return string.IsNullOrWhiteSpace(entry.HostName) ? null : entry.HostName;
        }
        catch
        {
            return null;
        }
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
/// Runs a Windows neighbor table command and returns its output.
/// </summary>
public interface INeighborTableRunner
{
    /// <summary>
    /// Runs the local neighbor table command.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Raw neighbor table output.</returns>
    Task<string> RunAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Windows process-backed ARP table runner.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Thin Windows process boundary; parser behavior is covered with deterministic runner fakes.")]
public sealed class ArpTableRunner : IArpTableRunner
{
    /// <inheritdoc />
    public Task<string> RunAsync(CancellationToken cancellationToken)
    {
        return WindowsNetworkCommandRunner.RunAsync("arp.exe", "-a", cancellationToken, "ARP");
    }
}

/// <summary>
/// Windows process-backed neighbor table runner.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Thin Windows process boundary; parser behavior is covered with deterministic runner fakes.")]
public sealed class NetshNeighborTableRunner : INeighborTableRunner
{
    /// <inheritdoc />
    public Task<string> RunAsync(CancellationToken cancellationToken)
    {
        return WindowsNetworkCommandRunner.RunAsync("netsh.exe", "interface ip show neighbors", cancellationToken, "neighbor table");
    }
}

[ExcludeFromCodeCoverage(Justification = "Thin Windows process boundary; parser behavior is covered with deterministic runner fakes.")]
internal static class WindowsNetworkCommandRunner
{
    public static async Task<string> RunAsync(string fileName, string arguments, CancellationToken cancellationToken, string label)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        }) ?? throw new InvalidOperationException($"Unable to start {fileName}.");

        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        if (process.ExitCode != 0)
        {
            var error = await errorTask;
            throw new InvalidOperationException($"{label} command failed with exit code {process.ExitCode}: {error}");
        }

        return await outputTask;
    }
}
