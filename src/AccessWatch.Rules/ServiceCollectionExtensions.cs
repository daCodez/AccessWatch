using AccessWatch.Core;
using Microsoft.Extensions.DependencyInjection;

namespace AccessWatch.Rules;

/// <summary>
/// Registers AccessWatch rule services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds rule and scoring services.
    /// </summary>
    /// <param name="services">The service collection to update.</param>
    /// <returns>The updated service collection.</returns>
    public static IServiceCollection AddAccessWatchRules(this IServiceCollection services)
    {
        services.AddSingleton<NotificationActionPolicy>();
        services.AddSingleton<IRiskScoringService, RiskScoringService>();
        return services;
    }
}
