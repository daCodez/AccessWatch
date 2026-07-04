using Microsoft.Extensions.DependencyInjection;

namespace AccessWatch.Enforcement;

/// <summary>
/// Registers AccessWatch enforcement planning and application services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds firewall enforcement planning and application services.
    /// </summary>
    /// <param name="services">The service collection to update.</param>
    /// <returns>The updated service collection.</returns>
    public static IServiceCollection AddAccessWatchEnforcement(this IServiceCollection services)
    {
        services.AddSingleton<IFirewallEnforcementPlanner, WindowsFirewallEnforcementPlanner>();
        services.AddSingleton<IFirewallEnforcementExecutor, WindowsFirewallEnforcementExecutor>();
        return services;
    }
}
