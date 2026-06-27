namespace AccessWatch.Tray;

/// <summary>
/// Describes a tray quick action that can be wired to UI later.
/// </summary>
public sealed record TrayQuickAction(string Name, string Command);

/// <summary>
/// Provides MVP tray quick actions.
/// </summary>
public sealed class TrayQuickActionsViewModel
{
    /// <summary>
    /// Gets quick actions planned for the tray app.
    /// </summary>
    public IReadOnlyList<TrayQuickAction> Actions { get; } =
    [
        new("Open dashboard", "OpenDashboard"),
        new("Quiet mode", "SetQuietMode"),
        new("Review incidents", "OpenIncidents")
    ];
}
