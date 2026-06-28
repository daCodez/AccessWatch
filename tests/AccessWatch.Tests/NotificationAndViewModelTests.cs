using AccessWatch.App.ViewModels;
using AccessWatch.Core;
using AccessWatch.Notifications;
using AccessWatch.Tray;

namespace AccessWatch.Tests;

/// <summary>
/// Tests notification and shell view-model behavior.
/// </summary>
public sealed class NotificationAndViewModelTests
{
    /// <summary>
    /// Verifies notification messages preserve assessment context.
    /// </summary>
    [Fact]
    public void NotificationMessageFactory_CreatesFriendlyMessage()
    {
        var factory = new NotificationMessageFactory();
        var assessment = new PortRiskAssessment(
            RiskLevel.High,
            RiskStatus.HighRisk,
            NotificationAction.AskBeforeAllow,
            "Discord updater opened a port.",
            "It is network reachable.",
            "Review it.");

        var message = factory.Create(assessment);

        Assert.Equal("AccessWatch", message.Title);
        Assert.Contains("Discord updater opened a port.", message.Body);
        Assert.Contains("It is network reachable.", message.Body);
        Assert.Equal(RiskLevel.High, message.RiskLevel);
        Assert.Equal(NotificationAction.AskBeforeAllow, message.Action);
        Assert.Equal("Review it.", message.SuggestedAction);
    }

    /// <summary>
    /// Verifies dashboard shell pages include the MVP areas.
    /// </summary>
    [Fact]
    public void DashboardShellViewModel_ContainsMvpPages()
    {
        var model = new DashboardShellViewModel();

        Assert.Equal(["Overview", "Devices", "Applications", "Ports", "Incidents", "Settings"], model.Pages.Select(page => page.Name));
        Assert.All(model.Pages, page => Assert.False(string.IsNullOrWhiteSpace(page.Summary)));
    }

    /// <summary>
    /// Verifies tray quick actions include opening the dashboard.
    /// </summary>
    [Fact]
    public void TrayQuickActionsViewModel_ContainsDashboardAction()
    {
        var model = new TrayQuickActionsViewModel();

        Assert.Contains(model.Actions, action => action.Command == "OpenDashboard" && action.Name == "Open dashboard");
    }
}
