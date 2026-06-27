using Microsoft.Extensions.DependencyInjection;

namespace AccessWatch.Core;

/// <summary>
/// Registers core AccessWatch services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds core AccessWatch settings.
    /// </summary>
    /// <param name="services">The service collection to update.</param>
    /// <returns>The updated service collection.</returns>
    public static IServiceCollection AddAccessWatchCore(this IServiceCollection services)
    {
        services.AddSingleton(new AccessWatchSettings());
        return services;
    }
}
