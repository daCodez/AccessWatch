using AccessWatch.Core;

namespace AccessWatch.Enforcement;

/// <summary>
/// Direction for a reviewed Windows Firewall rule action.
/// </summary>
public enum FirewallRuleDirection
{
    /// <summary>Inbound traffic.</summary>
    Inbound,

    /// <summary>Outbound traffic.</summary>
    Outbound
}

/// <summary>
/// Target type for a reviewed Windows Firewall rule action.
/// </summary>
public enum FirewallRuleTargetKind
{
    /// <summary>Remote IP address or range.</summary>
    RemoteAddress,

    /// <summary>Local executable path.</summary>
    Program
}

/// <summary>
/// Structured Windows Firewall rule action reviewed by the user before execution.
/// </summary>
/// <param name="DisplayName">Firewall rule display name.</param>
/// <param name="Direction">Traffic direction to block.</param>
/// <param name="TargetKind">Firewall target kind.</param>
/// <param name="TargetValue">Firewall target value, such as an IP address or executable path.</param>
public sealed record FirewallRuleAction(
    string DisplayName,
    FirewallRuleDirection Direction,
    FirewallRuleTargetKind TargetKind,
    string TargetValue);

/// <summary>
/// Describes a reviewed Windows Firewall action AccessWatch can show before applying protection.
/// </summary>
public sealed record FirewallEnforcementPlan(
    string TargetType,
    string TargetName,
    string Summary,
    string Explanation,
    IReadOnlyList<FirewallRuleAction> FirewallActions,
    bool RequiresAdministrator)
{
    /// <summary>Preview commands generated from structured firewall actions.</summary>
    public IReadOnlyList<string> PowerShellCommands => FirewallCommandFormatter.FormatAll(FirewallActions);
}

/// <summary>
/// Creates safe, reviewable Windows Firewall plans from AccessWatch trust decisions.
/// </summary>
public interface IFirewallEnforcementPlanner
{
    /// <summary>
    /// Creates a firewall plan that blocks traffic to and from a device address.
    /// </summary>
    /// <param name="device">The device to block.</param>
    /// <returns>A reviewable firewall plan.</returns>
    FirewallEnforcementPlan CreateBlockDevicePlan(NetworkDevice device);

    /// <summary>
    /// Creates a firewall plan that blocks an application executable when its path is known.
    /// </summary>
    /// <param name="application">The application to block.</param>
    /// <returns>A reviewable firewall plan.</returns>
    FirewallEnforcementPlan CreateBlockApplicationPlan(ApplicationIdentity application);
}

internal static class FirewallCommandFormatter
{
    public static IReadOnlyList<string> FormatAll(IReadOnlyList<FirewallRuleAction> actions)
    {
        var commands = new string[actions.Count];
        for (var index = 0; index < actions.Count; index++)
        {
            commands[index] = Format(actions[index]);
        }

        return commands;
    }

    public static string Format(FirewallRuleAction action)
    {
        var targetSwitch = action.TargetKind switch
        {
            FirewallRuleTargetKind.RemoteAddress => "RemoteAddress",
            FirewallRuleTargetKind.Program => "Program",
            _ => throw new InvalidOperationException($"Unsupported firewall target kind '{action.TargetKind}'.")
        };
        return $"New-NetFirewallRule -DisplayName {Quote(action.DisplayName)} -Direction {action.Direction} -Action Block -{targetSwitch} {Quote(action.TargetValue)} -Profile Any";
    }

    private static string Quote(string value)
    {
        return string.Concat("'", value.Replace("'", "''", StringComparison.Ordinal), "'");
    }
}
