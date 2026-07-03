using AccessWatch.Core;
using AccessWatch.Enforcement;
using AppIdentity = AccessWatch.Core.ApplicationIdentity;
using Microsoft.Extensions.DependencyInjection;

namespace AccessWatch.Tests;

/// <summary>
/// Tests Windows Firewall enforcement planning behavior.
/// </summary>
public sealed class FirewallEnforcementPlannerTests
{
    /// <summary>
    /// Verifies device block plans create inbound and outbound remote-address rules.
    /// </summary>
    [Fact]
    public void CreateBlockDevicePlan_CreatesInboundAndOutboundRemoteAddressRules()
    {
        var planner = new WindowsFirewallEnforcementPlanner();
        var device = new NetworkDevice
        {
            IpAddress = "192.168.1.55",
            Hostname = "guest-phone",
            UserAlias = "Kid's phone"
        };

        var plan = planner.CreateBlockDevicePlan(device);

        Assert.Equal("Device", plan.TargetType);
        Assert.Equal("Kid's phone", plan.TargetName);
        Assert.True(plan.RequiresAdministrator);
        Assert.Contains("192.168.1.55", plan.Summary);
        Assert.Contains("DHCP", plan.Explanation);
        Assert.Collection(
            plan.PowerShellCommands,
            command =>
            {
                Assert.Contains("-Direction Inbound", command);
                Assert.Contains("-RemoteAddress '192.168.1.55'", command);
                Assert.Contains("Kid''s phone inbound", command);
            },
            command =>
            {
                Assert.Contains("-Direction Outbound", command);
                Assert.Contains("-RemoteAddress '192.168.1.55'", command);
                Assert.Contains("Kid''s phone outbound", command);
            });
    }

    /// <summary>
    /// Verifies invalid device addresses produce review guidance without unsafe commands.
    /// </summary>
    [Fact]
    public void CreateBlockDevicePlan_ExplainsInvalidAddressWithoutCommands()
    {
        var planner = new WindowsFirewallEnforcementPlanner();
        var device = new NetworkDevice { IpAddress = "not-an-ip", Hostname = "unknown-device" };

        var plan = planner.CreateBlockDevicePlan(device);

        Assert.Empty(plan.PowerShellCommands);
        Assert.Equal("unknown-device", plan.TargetName);
        Assert.Contains("invalid", plan.Summary);
        Assert.Contains("valid device IP address", plan.Explanation);
    }

    /// <summary>
    /// Verifies application block plans create inbound and outbound program rules.
    /// </summary>
    [Fact]
    public void CreateBlockApplicationPlan_CreatesInboundAndOutboundProgramRules()
    {
        var planner = new WindowsFirewallEnforcementPlanner();
        var application = new AppIdentity
        {
            DisplayName = "Visual Studio",
            ProcessName = "devenv",
            FilePath = "C:\\Program Files\\Microsoft Visual Studio\\devenv.exe"
        };

        var plan = planner.CreateBlockApplicationPlan(application);

        Assert.Equal("Application", plan.TargetType);
        Assert.Equal("Visual Studio", plan.TargetName);
        Assert.True(plan.RequiresAdministrator);
        Assert.Contains("Block network traffic", plan.Summary);
        Assert.Collection(
            plan.PowerShellCommands,
            command =>
            {
                Assert.Contains("-Direction Inbound", command);
                Assert.Contains("-Program 'C:\\Program Files\\Microsoft Visual Studio\\devenv.exe'", command);
            },
            command =>
            {
                Assert.Contains("-Direction Outbound", command);
                Assert.Contains("-Program 'C:\\Program Files\\Microsoft Visual Studio\\devenv.exe'", command);
            });
    }

    /// <summary>
    /// Verifies application plans avoid commands when the executable path is unavailable.
    /// </summary>
    [Fact]
    public void CreateBlockApplicationPlan_ExplainsMissingPathWithoutCommands()
    {
        var planner = new WindowsFirewallEnforcementPlanner();
        var application = new AppIdentity { DisplayName = string.Empty, ProcessName = "mystery" };

        var plan = planner.CreateBlockApplicationPlan(application);

        Assert.Empty(plan.PowerShellCommands);
        Assert.Equal("mystery", plan.TargetName);
        Assert.Contains("path is unavailable", plan.Summary);
        Assert.Contains("full executable path", plan.Explanation);
    }


    /// <summary>
    /// Verifies application plans use a clear fallback name when identity fields are blank.
    /// </summary>
    [Fact]
    public void CreateBlockApplicationPlan_UsesFallbackNameWhenIdentityIsBlank()
    {
        var planner = new WindowsFirewallEnforcementPlanner();
        var application = new AppIdentity
        {
            DisplayName = string.Empty,
            ProcessName = string.Empty,
            FilePath = "C:\\Tools\\blocked.exe"
        };

        var plan = planner.CreateBlockApplicationPlan(application);

        Assert.Equal("Unknown application", plan.TargetName);
        Assert.Contains("Unknown application", plan.Summary);
    }
    /// <summary>
    /// Verifies enforcement services can be registered through dependency injection.
    /// </summary>
    [Fact]
    public void AddAccessWatchEnforcement_RegistersFirewallPlanner()
    {
        using var provider = new ServiceCollection().AddAccessWatchEnforcement().BuildServiceProvider();

        Assert.IsType<WindowsFirewallEnforcementPlanner>(provider.GetRequiredService<IFirewallEnforcementPlanner>());
    }
}
