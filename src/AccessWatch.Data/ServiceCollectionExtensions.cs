using AccessWatch.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AccessWatch.Data;

/// <summary>
/// Registers AccessWatch data services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the default local persistence provider for AccessWatch.
    /// </summary>
    /// <param name="services">The service collection to update.</param>
    /// <param name="connectionString">Optional SQL Server connection string override.</param>
    /// <returns>The updated service collection.</returns>
    public static IServiceCollection AddAccessWatchData(this IServiceCollection services, string? connectionString = null)
    {
        return services.AddAccessWatchData(new AccessWatchDatabaseOptions
        {
            SqlServerConnectionString = connectionString ?? AccessWatchDatabaseOptions.DefaultSqlServerConnectionString
        });
    }

    /// <summary>
    /// Adds AccessWatch persistence using the configured AccessWatch database section.
    /// </summary>
    /// <param name="services">The service collection to update.</param>
    /// <param name="configuration">Application configuration.</param>
    /// <returns>The updated service collection.</returns>
    public static IServiceCollection AddAccessWatchData(this IServiceCollection services, IConfiguration configuration)
    {
        var options = new AccessWatchDatabaseOptions();
        configuration.GetSection(AccessWatchDatabaseOptions.ConfigurationSectionName).Bind(options);
        return services.AddAccessWatchData(options);
    }
    /// <summary>
    /// Adds AccessWatch persistence for the selected database provider.
    /// </summary>
    /// <param name="services">The service collection to update.</param>
    /// <param name="options">Database provider options.</param>
    /// <returns>The updated service collection.</returns>
    /// <exception cref="NotSupportedException">Thrown when the selected provider has no implementation yet.</exception>
    public static IServiceCollection AddAccessWatchData(this IServiceCollection services, AccessWatchDatabaseOptions options)
    {
        services.AddSingleton(options);
        switch (options.Provider)
        {
            case DatabaseProvider.SqlServer:
                services.AddSingleton<IAccessWatchRepository, SqlServerAccessWatchRepository>();
                break;
            default:
                throw new NotSupportedException($"Database provider '{options.Provider}' is not supported.");
        }

        return services;
    }
}



