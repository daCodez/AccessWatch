using AccessWatch.Enforcement;

namespace AccessWatch.App.ViewModels;

/// <summary>
/// Holds the reviewed firewall protection plan text and apply state for the dashboard.
/// </summary>
public sealed class FirewallEnforcementPlanReviewViewModel
{
    private const string EmptyPlanText = "Block a device or app to prepare a reviewed Windows Firewall protection plan.";

    /// <summary>
    /// Gets the current reviewed plan, when one can still be applied.
    /// </summary>
    public FirewallEnforcementPlan? SelectedPlan { get; private set; }

    /// <summary>
    /// Gets the text shown in the firewall plan review area.
    /// </summary>
    public string Text { get; private set; } = EmptyPlanText;

    /// <summary>
    /// Gets whether the review area has text to display.
    /// </summary>
    public bool HasText => !string.IsNullOrWhiteSpace(Text);

    /// <summary>
    /// Gets whether the current plan can be applied while the dashboard is idle.
    /// </summary>
    /// <param name="isLoading">Whether the dashboard is running another operation.</param>
    /// <returns>True when a plan has firewall commands and the dashboard is idle.</returns>
    public bool CanApply(bool isLoading)
    {
        return SelectedPlan is not null &&
            SelectedPlan.PowerShellCommands.Count > 0 &&
            !isLoading;
    }

    /// <summary>
    /// Stores a reviewed firewall plan for display and possible application.
    /// </summary>
    /// <param name="plan">The reviewed plan.</param>
    public void SetPlan(FirewallEnforcementPlan plan)
    {
        SelectedPlan = plan;
        Text = FormatPlan(plan);
    }

    /// <summary>
    /// Shows that firewall plan creation is not available in this dashboard session.
    /// </summary>
    public void ShowPlanningDisconnected()
    {
        SelectedPlan = null;
        Text = "Firewall protection planning is not connected for this dashboard session.";
    }

    /// <summary>
    /// Shows the result of applying a reviewed firewall plan.
    /// </summary>
    /// <param name="plan">The plan that was applied.</param>
    /// <param name="result">The application result.</param>
    public void ShowApplyResult(FirewallEnforcementPlan plan, FirewallEnforcementResult result)
    {
        if (result.Succeeded)
        {
            SelectedPlan = null;
        }

        Text = string.Join(Environment.NewLine, FormatPlan(plan), string.Empty, "Last apply result:", result.Summary, result.Detail);
    }

    /// <summary>
    /// Resets the review area to its idle instructions.
    /// </summary>
    public void Reset()
    {
        SelectedPlan = null;
        Text = EmptyPlanText;
    }

    private static string FormatPlan(FirewallEnforcementPlan plan)
    {
        var commands = plan.PowerShellCommands.Count == 0
            ? "No firewall command is ready yet."
            : string.Join(Environment.NewLine, plan.PowerShellCommands);
        return string.Join(
            Environment.NewLine,
            plan.Summary,
            plan.Explanation,
            plan.RequiresAdministrator ? "Requires administrator approval before applying." : "Does not require administrator approval.",
            commands);
    }
}
