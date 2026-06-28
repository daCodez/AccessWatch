using AccessWatch.Core;
using Microsoft.Extensions.DependencyInjection;

namespace AccessWatch.Detection;

/// <summary>
/// Registers AccessWatch detection services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds detection services.
    /// </summary>
    /// <param name="services">The service collection to update.</param>
    /// <returns>The updated service collection.</returns>
    public static IServiceCollection AddAccessWatchDetection(this IServiceCollection services)
    {
        services.AddSingleton<INetstatRunner, NetstatRunner>();
        services.AddSingleton<IAppIdentityResolver, AppIdentityResolver>();
        services.AddSingleton<IListeningPortScanner, ListeningPortScanner>();
        services.AddSingleton<ConnectionTrustHelper>();
        return services;
    }
}
