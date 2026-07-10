using System.Net;
using AccessWatch.Core;

namespace AccessWatch.Enforcement;

/// <summary>
/// Creates Windows Firewall PowerShell plans without applying them automatically.
/// </summary>
public sealed class WindowsFirewallEnforcementPlanner : IFirewallEnforcementPlanner
{
    /// <inheritdoc />
    public FirewallEnforcementPlan CreateBlockDevicePlan(NetworkDevice device)
    {
        var targetName = FirstUseful(device.UserAlias, device.Hostname, device.IpAddress, "Unknown device");
        if (!IPAddress.TryParse(device.IpAddress, out _))
        {
            return new FirewallEnforcementPlan(
                "Device",
                targetName,
                "Cannot create firewall commands because the device IP address is invalid.",
                "AccessWatch needs a valid device IP address before it can create Windows Firewall remote-address rules.",
                [],
                true);
        }

        var ruleBaseName = $"AccessWatch Block Device {targetName}";
        return new FirewallEnforcementPlan(
            "Device",
            targetName,
            $"Block all traffic to and from {targetName} ({device.IpAddress}).",
            "This creates inbound and outbound Windows Firewall rules for the selected remote IP address. Review before applying, especially if the address may change by DHCP.",
            [
                new FirewallRuleAction(string.Concat(ruleBaseName, " inbound"), FirewallRuleDirection.Inbound, FirewallRuleTargetKind.RemoteAddress, device.IpAddress),
                new FirewallRuleAction(string.Concat(ruleBaseName, " outbound"), FirewallRuleDirection.Outbound, FirewallRuleTargetKind.RemoteAddress, device.IpAddress)
            ],
            true);
    }

    /// <inheritdoc />
    public FirewallEnforcementPlan CreateBlockApplicationPlan(ApplicationIdentity application)
    {
        var targetName = FirstUseful(application.DisplayName, application.ProcessName, "Unknown application");
        if (string.IsNullOrWhiteSpace(application.FilePath))
        {
            return new FirewallEnforcementPlan(
                "Application",
                targetName,
                "Cannot create firewall commands because the executable path is unavailable.",
                "Windows Firewall application rules need a full executable path. Run a fresh scan or investigate the port until AccessWatch can resolve the app path.",
                [],
                true);
        }

        var ruleBaseName = $"AccessWatch Block App {targetName}";
        return new FirewallEnforcementPlan(
            "Application",
            targetName,
            $"Block network traffic for {targetName}.",
            "This creates inbound and outbound Windows Firewall rules for the selected executable path. Review before applying so a trusted app is not blocked accidentally.",
            [
                new FirewallRuleAction(string.Concat(ruleBaseName, " inbound"), FirewallRuleDirection.Inbound, FirewallRuleTargetKind.Program, application.FilePath),
                new FirewallRuleAction(string.Concat(ruleBaseName, " outbound"), FirewallRuleDirection.Outbound, FirewallRuleTargetKind.Program, application.FilePath)
            ],
            true);
    }


    private static string FirstUseful(string? first, string? second, string fallback)
    {
        if (!string.IsNullOrWhiteSpace(first))
        {
            return first.Trim();
        }

        return string.IsNullOrWhiteSpace(second) ? fallback : second.Trim();
    }

    private static string FirstUseful(string? first, string? second, string? third, string fallback)
    {
        if (!string.IsNullOrWhiteSpace(first))
        {
            return first.Trim();
        }

        return FirstUseful(second, third, fallback);
    }
}
