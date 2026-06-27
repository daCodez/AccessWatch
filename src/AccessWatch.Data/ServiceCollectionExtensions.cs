using AccessWatch.Core;
using Microsoft.Extensions.DependencyInjection;

namespace AccessWatch.Data;

/// <summary>
/// Registers AccessWatch data services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds SQLite persistence for AccessWatch.
    /// </summary>
    /// <param name="services">The service collection to update.</param>
    /// <param name="databasePath">Optional database path override.</param>
    /// <returns>The updated service collection.</returns>
    public static IServiceCollection AddAccessWatchData(this IServiceCollection services, string? databasePath = null)
    {
        services.AddSingleton(new AccessWatchDatabaseOptions
        {
            DatabasePath = databasePath ?? AccessWatchDatabaseOptions.DefaultDatabasePath
        });
        services.AddSingleton<IAccessWatchRepository, SqliteAccessWatchRepository>();
        return services;
    }
}
