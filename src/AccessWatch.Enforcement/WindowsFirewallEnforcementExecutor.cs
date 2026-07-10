using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;

namespace AccessWatch.Enforcement;

/// <summary>
/// Represents the result of applying a reviewed firewall protection plan.
/// </summary>
public sealed record FirewallEnforcementResult(
    bool Succeeded,
    string Summary,
    string Detail,
    IReadOnlyList<string> AppliedCommands);

/// <summary>
/// Executes reviewed firewall protection plans after safety checks pass.
/// </summary>
public interface IFirewallEnforcementExecutor
{
    /// <summary>
    /// Applies a reviewed firewall protection plan.
    /// </summary>
    /// <param name="plan">The reviewed plan to apply.</param>
    /// <param name="cancellationToken">Token used to cancel command execution.</param>
    /// <returns>The enforcement result.</returns>
    Task<FirewallEnforcementResult> ApplyAsync(FirewallEnforcementPlan plan, CancellationToken cancellationToken);
}

/// <summary>
/// Applies reviewed Windows Firewall plans through PowerShell when the process has administrator rights.
/// </summary>
public sealed class WindowsFirewallEnforcementExecutor : IFirewallEnforcementExecutor
{
    private readonly Func<bool> isAdministrator;
    private readonly Func<string, CancellationToken, Task<FirewallCommandResult>> runCommandAsync;

    /// <summary>
    /// Initializes a Windows Firewall executor.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public WindowsFirewallEnforcementExecutor()
        : this(IsCurrentProcessAdministrator, RunPowerShellCommandAsync)
    {
    }

    /// <summary>
    /// Initializes a Windows Firewall executor with testable security and command seams.
    /// </summary>
    public WindowsFirewallEnforcementExecutor(
        Func<bool> isAdministrator,
        Func<string, CancellationToken, Task<FirewallCommandResult>> runCommandAsync)
    {
        this.isAdministrator = isAdministrator;
        this.runCommandAsync = runCommandAsync;
    }

    /// <inheritdoc />
    public async Task<FirewallEnforcementResult> ApplyAsync(FirewallEnforcementPlan plan, CancellationToken cancellationToken)
    {
        if (plan.FirewallActions.Count == 0)
        {
            return new FirewallEnforcementResult(
                false,
                "No firewall protection was applied.",
                "The selected protection plan does not have firewall commands ready yet.",
                []);
        }

        if (plan.RequiresAdministrator && !isAdministrator())
        {
            return new FirewallEnforcementResult(
                false,
                "Administrator approval is required before applying protection.",
                "Restart AccessWatch as administrator, review the plan again, then apply protection.",
                []);
        }

        var appliedCommands = new List<string>(plan.FirewallActions.Count);
        foreach (var action in plan.FirewallActions)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var command = FirewallCommandFormatter.Format(action);
            var result = await runCommandAsync(command, cancellationToken).ConfigureAwait(false);
            if (result.ExitCode != 0)
            {
                var detail = string.IsNullOrWhiteSpace(result.Error)
                    ? "Windows Firewall rejected the command. No additional error text was returned."
                    : result.Error.Trim();
                return new FirewallEnforcementResult(
                    false,
                    $"Could not apply protection for {plan.TargetName}.",
                    detail,
                    appliedCommands);
            }

            appliedCommands.Add(command);
        }

        return new FirewallEnforcementResult(
            true,
            $"Applied firewall protection for {plan.TargetName}.",
            $"AccessWatch applied {appliedCommands.Count} Windows Firewall rule(s).",
            appliedCommands);
    }

    [ExcludeFromCodeCoverage]
    [SupportedOSPlatform("windows")]
    private static bool IsCurrentProcessAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    [ExcludeFromCodeCoverage]
    private static async Task<FirewallCommandResult> RunPowerShellCommandAsync(string command, CancellationToken cancellationToken)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                ArgumentList = { "-NoProfile", "-NonInteractive", "-Command", command },
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            }
        };

        var output = new StringBuilder();
        var error = new StringBuilder();
        process.OutputDataReceived += (_, args) =>
        {
            if (args.Data is not null)
            {
                output.AppendLine(args.Data);
            }
        };
        process.ErrorDataReceived += (_, args) =>
        {
            if (args.Data is not null)
            {
                error.AppendLine(args.Data);
            }
        };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        return new FirewallCommandResult(process.ExitCode, output.ToString(), error.ToString());
    }
}

/// <summary>
/// Captures one PowerShell firewall command result.
/// </summary>
/// <param name="ExitCode">The process exit code.</param>
/// <param name="Output">The standard output text.</param>
/// <param name="Error">The standard error text.</param>
public sealed record FirewallCommandResult(int ExitCode, string Output, string Error);
