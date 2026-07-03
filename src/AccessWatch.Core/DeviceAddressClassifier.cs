using System.Net;
using System.Net.Sockets;

namespace AccessWatch.Core;

/// <summary>
/// Classifies network addresses that represent real devices AccessWatch should display.
/// </summary>
public static class DeviceAddressClassifier
{
    /// <summary>
    /// Returns whether an observed IP and MAC pair looks like a real host device.
    /// </summary>
    /// <param name="ipAddress">Observed IP address.</param>
    /// <param name="macAddress">Observed MAC address when available.</param>
    /// <returns>True when the address pair should be shown as a device.</returns>
    public static bool IsUsableDeviceAddress(string ipAddress, string? macAddress)
    {
        if (string.Equals(macAddress, "FF:FF:FF:FF:FF:FF", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(macAddress) &&
            (macAddress.StartsWith("01:00:5E:", StringComparison.OrdinalIgnoreCase) ||
            macAddress.StartsWith("33:33:", StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        if (!IPAddress.TryParse(ipAddress, out var parsedAddress))
        {
            return false;
        }

        if (parsedAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = parsedAddress.GetAddressBytes();
            return !IPAddress.IsLoopback(parsedAddress)
                && !parsedAddress.Equals(IPAddress.Any)
                && !parsedAddress.Equals(IPAddress.None)
                && bytes[0] < 224
                && bytes[3] != 255;
        }

        return parsedAddress.AddressFamily == AddressFamily.InterNetworkV6
            && !IPAddress.IsLoopback(parsedAddress)
            && !parsedAddress.Equals(IPAddress.IPv6Any)
            && !parsedAddress.Equals(IPAddress.IPv6None)
            && !parsedAddress.IsIPv6Multicast;
    }
}
