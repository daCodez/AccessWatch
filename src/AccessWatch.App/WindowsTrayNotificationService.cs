using System.Diagnostics.CodeAnalysis;
using AccessWatch.Core;
using AccessWatch.Notifications;
using Forms = System.Windows.Forms;
using Drawing = System.Drawing;

namespace AccessWatch.App;

/// <summary>
/// Shows AccessWatch notifications through the Windows notification area.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Thin Windows notification boundary; scan notification routing is covered with fakes.")]
public sealed class WindowsTrayNotificationService : ITrayNotificationService, IDisposable
{
    private readonly Forms.NotifyIcon notifyIcon;

    /// <summary>
    /// Initializes a Windows tray notification service.
    /// </summary>
    public WindowsTrayNotificationService()
    {
        notifyIcon = new Forms.NotifyIcon
        {
            Icon = Drawing.SystemIcons.Shield,
            Text = "AccessWatch",
            Visible = true
        };
    }

    /// <inheritdoc />
    public Task ShowAsync(NotificationMessage message, CancellationToken cancellationToken)
    {
        if (message.Action == NotificationAction.SilentLog || cancellationToken.IsCancellationRequested)
        {
            return Task.CompletedTask;
        }

        notifyIcon.ShowBalloonTip(
            7000,
            message.Title,
            $"{message.Body}{Environment.NewLine}{message.SuggestedAction}",
            ToToolTipIcon(message.RiskLevel));
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        notifyIcon.Visible = false;
        notifyIcon.Dispose();
    }

    private static Forms.ToolTipIcon ToToolTipIcon(RiskLevel riskLevel)
    {
        return riskLevel switch
        {
            RiskLevel.Critical or RiskLevel.High => Forms.ToolTipIcon.Warning,
            RiskLevel.Medium => Forms.ToolTipIcon.Info,
            _ => Forms.ToolTipIcon.None
        };
    }
}