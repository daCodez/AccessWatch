using Microsoft.Extensions.DependencyInjection;

namespace AccessWatch.Notifications;

/// <summary>
/// Registers AccessWatch notification services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds notification helpers.
    /// </summary>
    /// <param name="services">The service collection to update.</param>
    /// <returns>The updated service collection.</returns>
    public static IServiceCollection AddAccessWatchNotifications(this IServiceCollection services)
    {
        services.AddSingleton<NotificationMessageFactory>();
        return services;
    }
}
