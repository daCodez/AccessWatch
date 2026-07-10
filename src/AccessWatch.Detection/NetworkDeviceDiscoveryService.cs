using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using AccessWatch.Core;

namespace AccessWatch.Detection;

/// <summary>
/// Discovers local-network devices from Windows network tables.
/// </summary>
public sealed class NetworkDeviceDiscoveryService : INetworkDeviceDiscoveryService
{
    private const string ArpTableNote = "Seen in ARP table; active subnet probing can refresh this entry when quiet devices respond.";
    private const string NeighborTableNote = "Seen in Windows neighbor table; useful for phones, Phone Link devices, and quiet Wi-Fi devices.";
    private const int MaxConcurrentHostnameLookups = 16;
    private readonly IArpTableRunner arpTableRunner;
    private readonly IDeviceHostnameResolver hostnameResolver;
    private readonly INeighborTableRunner? neighborTableRunner;
    private readonly ISubnetProbeRunner? subnetProbeRunner;

    /// <summary>
    /// Initializes a new device discovery service using the default Windows runners.
    /// </summary>
    public NetworkDeviceDiscoveryService()
        : this(new ArpTableRunner(), new DnsDeviceHostnameResolver(), new NetshNeighborTableRunner(), new WindowsSubnetProbeRunner())
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
        : this(arpTableRunner, hostnameResolver, neighborTableRunner, null)
    {
    }

    /// <summary>
    /// Initializes a new device discovery service with supplied ARP, hostname, neighbor table, and active subnet probe readers.
    /// </summary>
    /// <param name="arpTableRunner">Runner used to collect ARP output.</param>
    /// <param name="hostnameResolver">Resolver used to label devices by hostname.</param>
    /// <param name="neighborTableRunner">Optional runner used to collect Windows neighbor table output.</param>
    /// <param name="subnetProbeRunner">Optional runner used to wake quiet local devices before table reads.</param>
    public NetworkDeviceDiscoveryService(
        IArpTableRunner arpTableRunner,
        IDeviceHostnameResolver hostnameResolver,
        INeighborTableRunner? neighborTableRunner,
        ISubnetProbeRunner? subnetProbeRunner)
    {
        this.arpTableRunner = arpTableRunner;
        this.hostnameResolver = hostnameResolver;
        this.neighborTableRunner = neighborTableRunner;
        this.subnetProbeRunner = subnetProbeRunner;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<NetworkDevice>> DiscoverAsync(CancellationToken cancellationToken)
    {
        var observedAtUtc = DateTimeOffset.UtcNow;
        if (subnetProbeRunner is not null)
        {
            await subnetProbeRunner.ProbeAsync(cancellationToken);
        }

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
                DeviceTypeGuess = GuessDeviceType(ipAddress, null, null),
                TrustStatus = TrustStatus.Unknown,
                RiskStatus = RiskStatus.Normal,
                Notes = ArpTableNote,
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
                DeviceTypeGuess = GuessDeviceType(ipAddress, null, "Network neighbor"),
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

        if (!TryNormalizeIpAddress(ipAddressToken, out ipAddress) || !TryNormalizeMacAddress(macAddressToken, out macAddress))
        {
            return false;
        }

        return true;
    }

    private static bool TryNormalizeIpAddress(ReadOnlySpan<char> value, out string ipAddress)
    {
        ipAddress = string.Empty;
        if (!IPAddress.TryParse(value, out var parsedAddress))
        {
            return false;
        }

        ipAddress = parsedAddress.ToString();
        return true;
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

    private static string GuessDeviceType(string ipAddress, string? hostname, string? fallback)
    {
        var normalizedName = hostname?.Trim().ToLowerInvariant() ?? string.Empty;
        if (normalizedName.Contains("iphone", StringComparison.Ordinal) ||
            normalizedName.Contains("android", StringComparison.Ordinal) ||
            normalizedName.Contains("pixel", StringComparison.Ordinal) ||
            normalizedName.Contains("galaxy", StringComparison.Ordinal) ||
            normalizedName.Contains("phone", StringComparison.Ordinal))
        {
            return "Phone";
        }

        if (normalizedName.Contains("ipad", StringComparison.Ordinal) || normalizedName.Contains("tablet", StringComparison.Ordinal))
        {
            return "Tablet";
        }

        if (normalizedName.Contains("printer", StringComparison.Ordinal) || normalizedName.Contains("print", StringComparison.Ordinal))
        {
            return "Printer";
        }

        if (normalizedName.Contains("nas", StringComparison.Ordinal) || normalizedName.Contains("storage", StringComparison.Ordinal))
        {
            return "Network storage";
        }

        if (normalizedName.Contains("router", StringComparison.Ordinal) || normalizedName.Contains("gateway", StringComparison.Ordinal) || ipAddress.EndsWith(".1", StringComparison.Ordinal))
        {
            return "Router / gateway";
        }

        if (normalizedName.Contains("tv", StringComparison.Ordinal) || normalizedName.Contains("roku", StringComparison.Ordinal) || normalizedName.Contains("chromecast", StringComparison.Ordinal))
        {
            return "Media device";
        }

        if (normalizedName.Contains("speaker", StringComparison.Ordinal) || normalizedName.Contains("echo", StringComparison.Ordinal))
        {
            return "Smart speaker";
        }

        return string.IsNullOrWhiteSpace(fallback) ? "Unknown" : fallback;
    }

    private static string MergeDeviceNotes(string? notes, string deviceTypeGuess)
    {
        if (deviceTypeGuess == "Router / gateway")
        {
            var routerNote = "Likely router or default gateway based on address pattern.";
            return string.Concat(notes, " ", routerNote).Trim();
        }

        return string.Concat(notes);
    }
    private async Task<IReadOnlyList<NetworkDevice>> AddHostnamesAsync(IReadOnlyList<NetworkDevice> devices, CancellationToken cancellationToken)
    {
        var namedDevices = new NetworkDevice[devices.Count];
        using var throttle = new SemaphoreSlim(MaxConcurrentHostnameLookups);
        var tasks = new Task[devices.Count];
        for (var index = 0; index < devices.Count; index++)
        {
            tasks[index] = AddHostnameAsync(devices[index], index, namedDevices, throttle, cancellationToken);
        }

        await Task.WhenAll(tasks);
        return namedDevices;
    }

    private async Task AddHostnameAsync(
        NetworkDevice device,
        int index,
        NetworkDevice[] namedDevices,
        SemaphoreSlim throttle,
        CancellationToken cancellationToken)
    {
        await throttle.WaitAsync(cancellationToken);
        try
        {
            var hostname = await hostnameResolver.ResolveHostnameAsync(device.IpAddress, cancellationToken);
            var normalizedHostname = string.IsNullOrWhiteSpace(hostname) ? null : hostname.Trim().TrimEnd('.');
            var deviceTypeGuess = GuessDeviceType(device.IpAddress, normalizedHostname, device.DeviceTypeGuess);
            namedDevices[index] = device with
            {
                Hostname = normalizedHostname,
                DeviceTypeGuess = deviceTypeGuess,
                Notes = MergeDeviceNotes(device.Notes, deviceTypeGuess)
            };
        }
        finally
        {
            throttle.Release();
        }
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
/// Actively probes local subnets before passive Windows table reads.
/// </summary>
public interface ISubnetProbeRunner
{
    /// <summary>
    /// Sends low-cost probes to local subnet addresses.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task ProbeAsync(CancellationToken cancellationToken);
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
    public async Task<string> RunAsync(CancellationToken cancellationToken)
    {
        var ipv4Output = await WindowsNetworkCommandRunner.RunAsync("netsh.exe", "interface ip show neighbors", cancellationToken, "IPv4 neighbor table");
        var ipv6Output = await WindowsNetworkCommandRunner.RunAsync("netsh.exe", "interface ipv6 show neighbors", cancellationToken, "IPv6 neighbor table");
        return string.Concat(ipv4Output, Environment.NewLine, ipv6Output);
    }
}

/// <summary>
/// Ping-backed subnet probe that encourages Windows to populate ARP and neighbor tables.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Thin network boundary; discovery orchestration is covered with deterministic probe fakes.")]
public sealed class WindowsSubnetProbeRunner : ISubnetProbeRunner
{
    private const int ProbeTimeoutMilliseconds = 120;
    private const int MaxConcurrentProbes = 32;

    /// <inheritdoc />
    public async Task ProbeAsync(CancellationToken cancellationToken)
    {
        var addresses = EnumerateLocalSubnetAddresses().Distinct().ToArray();
        using var throttle = new SemaphoreSlim(MaxConcurrentProbes);
        var probes = new List<Task>(addresses.Length);
        foreach (var address in addresses)
        {
            await throttle.WaitAsync(cancellationToken);
            probes.Add(ProbeAddressAsync(address, throttle, cancellationToken));
        }

        await Task.WhenAll(probes);
    }

    private static async Task ProbeAddressAsync(string address, SemaphoreSlim throttle, CancellationToken cancellationToken)
    {
        try
        {
            using var ping = new Ping();
            await ping.SendPingAsync(address, ProbeTimeoutMilliseconds);
        }
        catch when (!cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            throttle.Release();
        }
    }

    private static IEnumerable<string> EnumerateLocalSubnetAddresses()
    {
        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (networkInterface.OperationalStatus != OperationalStatus.Up ||
                networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            foreach (var unicast in networkInterface.GetIPProperties().UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != AddressFamily.InterNetwork || unicast.IPv4Mask is null)
                {
                    continue;
                }

                foreach (var address in EnumerateSubnet(unicast.Address, unicast.IPv4Mask))
                {
                    yield return address;
                }
            }
        }
    }

    private static IEnumerable<string> EnumerateSubnet(IPAddress address, IPAddress mask)
    {
        var addressBytes = address.GetAddressBytes();
        var maskBytes = mask.GetAddressBytes();
        var network = ToUInt32(addressBytes) & ToUInt32(maskBytes);
        var broadcast = network | ~ToUInt32(maskBytes);
        var hostCount = broadcast > network ? broadcast - network - 1 : 0;
        if (hostCount == 0 || hostCount > 254)
        {
            yield break;
        }

        for (var current = network + 1; current < broadcast; current++)
        {
            var candidate = FromUInt32(current);
            if (!candidate.Equals(address))
            {
                yield return candidate.ToString();
            }
        }
    }

    private static uint ToUInt32(byte[] bytes)
    {
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    private static IPAddress FromUInt32(uint value)
    {
        return new IPAddress([
            (byte)(value >> 24),
            (byte)(value >> 16),
            (byte)(value >> 8),
            (byte)value]);
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
