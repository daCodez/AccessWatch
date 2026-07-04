using AccessWatch.Core;
using Microsoft.Extensions.DependencyInjection;

namespace AccessWatch.AI;

/// <summary>
/// Registers AccessWatch AI handoff services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds manual AI handoff services.
    /// </summary>
    /// <param name="services">The service collection to update.</param>
    /// <returns>The updated service collection.</returns>
    public static IServiceCollection AddAccessWatchAi(this IServiceCollection services)
    {
        services.AddSingleton<IAiHandoffService, ManualAiHandoffService>();
        services.AddSingleton<IAiInvestigationBridge, OpenClawGatewayInvestigationBridge>();
        return services;
    }
}
