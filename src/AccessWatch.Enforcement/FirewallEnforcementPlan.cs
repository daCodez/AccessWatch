using AccessWatch.Core;

namespace AccessWatch.Enforcement;

/// <summary>
/// Describes a reviewed Windows Firewall action AccessWatch can show before applying protection.
/// </summary>
public sealed record FirewallEnforcementPlan(
    string TargetType,
    string TargetName,
    string Summary,
    string Explanation,
    IReadOnlyList<string> PowerShellCommands,
    bool RequiresAdministrator);

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
