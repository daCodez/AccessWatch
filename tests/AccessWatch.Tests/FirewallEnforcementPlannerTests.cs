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
    /// Verifies protection is not applied when a plan has no firewall commands.
    /// </summary>
    [Fact]
    public async Task ApplyAsync_RejectsPlansWithoutCommands()
    {
        var executor = new WindowsFirewallEnforcementExecutor(
            () => true,
            (_, _) => Task.FromResult(new FirewallCommandResult(0, string.Empty, string.Empty)));
        var plan = new FirewallEnforcementPlan("Device", "unknown", "No commands", "Missing address", [], true);

        var result = await executor.ApplyAsync(plan, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Empty(result.AppliedCommands);
        Assert.Contains("does not have firewall commands", result.Detail);
    }

    /// <summary>
    /// Verifies administrator-only plans are not run from a normal process.
    /// </summary>
    [Fact]
    public async Task ApplyAsync_RejectsAdministratorPlansWhenNotElevated()
    {
        var commandWasRun = false;
        var executor = new WindowsFirewallEnforcementExecutor(
            () => false,
            (_, _) =>
            {
                commandWasRun = true;
                return Task.FromResult(new FirewallCommandResult(0, string.Empty, string.Empty));
            });
        var plan = new FirewallEnforcementPlan("Device", "guest-phone", "Block", "Review", [Rule("review")], true);

        var result = await executor.ApplyAsync(plan, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.False(commandWasRun);
        Assert.Empty(result.AppliedCommands);
        Assert.Contains("administrator", result.Summary, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Verifies command failures stop the plan and report the firewall error.
    /// </summary>
    [Fact]
    public async Task ApplyAsync_StopsWhenCommandFails()
    {
        var executor = new WindowsFirewallEnforcementExecutor(
            () => true,
            (command, _) => Task.FromResult(command.Contains("outbound", StringComparison.Ordinal)
                ? new FirewallCommandResult(1, string.Empty, "Firewall rule failed")
                : new FirewallCommandResult(0, "ok", string.Empty)));
        var plan = new FirewallEnforcementPlan(
            "Device",
            "guest-phone",
            "Block",
            "Review",
            [Rule("inbound"), Rule("outbound", FirewallRuleDirection.Outbound)],
            true);

        var result = await executor.ApplyAsync(plan, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Single(result.AppliedCommands);
        Assert.Contains("Firewall rule failed", result.Detail);
    }

    /// <summary>
    /// Verifies plans that do not require administrator rights skip the elevation check.
    /// </summary>
    [Fact]
    public async Task ApplyAsync_SkipsAdministratorCheckWhenPlanDoesNotRequireElevation()
    {
        var adminCheckWasCalled = false;
        var executor = new WindowsFirewallEnforcementExecutor(
            () =>
            {
                adminCheckWasCalled = true;
                return false;
            },
            (_, _) => Task.FromResult(new FirewallCommandResult(0, "ok", string.Empty)));
        var plan = new FirewallEnforcementPlan(
            "Device",
            "lab-sensor",
            "Review",
            "Review",
            [Rule("review")],
            false);

        var result = await executor.ApplyAsync(plan, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.False(adminCheckWasCalled);
    }

    /// <summary>
    /// Verifies command failures still explain the problem when PowerShell returns no error text.
    /// </summary>
    [Fact]
    public async Task ApplyAsync_UsesFallbackErrorWhenCommandFailsWithoutErrorText()
    {
        var executor = new WindowsFirewallEnforcementExecutor(
            () => true,
            (_, _) => Task.FromResult(new FirewallCommandResult(1, string.Empty, string.Empty)));
        var plan = new FirewallEnforcementPlan(
            "Application",
            "Unknown app",
            "Block",
            "Review",
            [Rule("inbound")],
            true);

        var result = await executor.ApplyAsync(plan, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Contains("No additional error text", result.Detail);
    }

    /// <summary>
    /// Verifies successful command execution records every applied command.
    /// </summary>
    [Fact]
    public async Task ApplyAsync_ReturnsSuccessForAppliedCommands()
    {
        var executor = new WindowsFirewallEnforcementExecutor(
            () => true,
            (_, _) => Task.FromResult(new FirewallCommandResult(0, "ok", string.Empty)));
        var plan = new FirewallEnforcementPlan(
            "Application",
            "Visual Studio",
            "Block",
            "Review",
            [Rule("inbound"), Rule("outbound", FirewallRuleDirection.Outbound)],
            true);

        var result = await executor.ApplyAsync(plan, CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Equal(2, result.AppliedCommands.Count);
        Assert.Contains("Visual Studio", result.Summary);
    }
    /// <summary>
    /// Verifies command previews reject unsupported structured firewall actions.
    /// </summary>
    [Fact]
    public void PowerShellCommands_RejectUnsupportedStructuredAction()
    {
        var plan = new FirewallEnforcementPlan(
            "Device",
            "bad-action",
            "Review",
            "Review",
            [new FirewallRuleAction("bad", FirewallRuleDirection.Inbound, (FirewallRuleTargetKind)999, "192.0.2.55")],
            true);

        Assert.Throws<InvalidOperationException>(() => _ = plan.PowerShellCommands);
    }
    private static FirewallRuleAction Rule(string displayName, FirewallRuleDirection direction = FirewallRuleDirection.Inbound)
    {
        return new FirewallRuleAction(displayName, direction, FirewallRuleTargetKind.RemoteAddress, "192.0.2.55");
    }

    /// <summary>
    /// Verifies enforcement services can be registered through dependency injection.
    /// </summary>
    [Fact]
    public void AddAccessWatchEnforcement_RegistersFirewallPlanner()
    {
        using var provider = new ServiceCollection().AddAccessWatchEnforcement().BuildServiceProvider();

        Assert.IsType<WindowsFirewallEnforcementPlanner>(provider.GetRequiredService<IFirewallEnforcementPlanner>());
        Assert.IsType<WindowsFirewallEnforcementExecutor>(provider.GetRequiredService<IFirewallEnforcementExecutor>());
    }
}
