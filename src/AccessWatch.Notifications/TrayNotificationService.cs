namespace AccessWatch.Notifications;

/// <summary>
/// Delivers notification messages to a user-facing tray surface.
/// </summary>
public interface ITrayNotificationService
{
    /// <summary>
    /// Sends a notification message when the selected action should interrupt or inform the user.
    /// </summary>
    /// <param name="message">The notification message to deliver.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    Task ShowAsync(NotificationMessage message, CancellationToken cancellationToken);
}

/// <summary>
/// Safe MVP notification sink that records messages without showing OS popups.
/// </summary>
public sealed class InMemoryTrayNotificationService : ITrayNotificationService
{
    private readonly List<NotificationMessage> deliveredNotifications = [];

    /// <summary>
    /// Gets delivered messages for tests and future tray UI polling.
    /// </summary>
    public IReadOnlyList<NotificationMessage> DeliveredNotifications => deliveredNotifications;

    /// <inheritdoc />
    public Task ShowAsync(NotificationMessage message, CancellationToken cancellationToken)
    {
        if (message.Action != AccessWatch.Core.NotificationAction.SilentLog)
        {
            deliveredNotifications.Add(message);
        }

        return Task.CompletedTask;
    }
}
