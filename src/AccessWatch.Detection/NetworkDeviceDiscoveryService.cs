using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using AccessWatch.Core;

namespace AccessWatch.Detection;

/// <summary>
/// Discovers local-network devices from the Windows ARP cache.
/// </summary>
public sealed class NetworkDeviceDiscoveryService : INetworkDeviceDiscoveryService
{
    private readonly IArpTableRunner arpTableRunner;
    private readonly IDeviceHostnameResolver hostnameResolver;

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
        : this(arpTableRunner, new DnsDeviceHostnameResolver())
    {
    }

    /// <summary>
    /// Initializes a new device discovery service with supplied ARP and hostname resolvers.
    /// </summary>
    /// <param name="arpTableRunner">Runner used to collect ARP output.</param>
    /// <param name="hostnameResolver">Resolver used to label devices by hostname.</param>
    public NetworkDeviceDiscoveryService(IArpTableRunner arpTableRunner, IDeviceHostnameResolver hostnameResolver)
    {
        this.arpTableRunner = arpTableRunner;
        this.hostnameResolver = hostnameResolver;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<NetworkDevice>> DiscoverAsync(CancellationToken cancellationToken)
    {
        var output = await arpTableRunner.RunAsync(cancellationToken);
        var devices = ParseArpOutput(output, DateTimeOffset.UtcNow);
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
            if (!TryReadArpLine(rawLine.Trim(), out var ipAddress, out var macAddress))
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

        return devices
            .OrderBy(device => device.IpAddress, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static bool TryReadArpLine(ReadOnlySpan<char> line, out string ipAddress, out string macAddress)
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
