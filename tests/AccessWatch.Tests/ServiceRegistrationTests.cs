using AccessWatch.AI;
using AccessWatch.Core;
using AccessWatch.Data;
using AccessWatch.Detection;
using AccessWatch.Notifications;
using AccessWatch.Rules;
using Microsoft.Extensions.DependencyInjection;

namespace AccessWatch.Tests;

/// <summary>
/// Tests dependency injection registration extensions.
/// </summary>
public sealed class ServiceRegistrationTests
{
    /// <summary>
    /// Verifies core settings registration.
    /// </summary>
    [Fact]
    public void AddAccessWatchCore_RegistersSettings()
    {
        using var provider = new ServiceCollection().AddAccessWatchCore().BuildServiceProvider();

        Assert.Equal(ProtectionMode.Balanced, provider.GetRequiredService<AccessWatchSettings>().ProtectionMode);
    }

    /// <summary>
    /// Verifies data registration uses the configured database path.
    /// </summary>
    [Fact]
    public void AddAccessWatchData_RegistersRepository()
    {
        using var provider = new ServiceCollection().AddAccessWatchData("C:\\Temp\\AccessWatch.db").BuildServiceProvider();

        Assert.Equal("C:\\Temp\\AccessWatch.db", provider.GetRequiredService<AccessWatchDatabaseOptions>().DatabasePath);
        Assert.IsType<SqliteAccessWatchRepository>(provider.GetRequiredService<IAccessWatchRepository>());
    }

    /// <summary>
    /// Verifies data registration defaults to ProgramData when no path is supplied.
    /// </summary>
    [Fact]
    public void AddAccessWatchData_UsesDefaultDatabasePath()
    {
        using var provider = new ServiceCollection().AddAccessWatchData().BuildServiceProvider();

        Assert.Equal(AccessWatchDatabaseOptions.DefaultDatabasePath, provider.GetRequiredService<AccessWatchDatabaseOptions>().DatabasePath);
    }

    /// <summary>
    /// Verifies detection registration wires scanners and helpers.
    /// </summary>
    [Fact]
    public void AddAccessWatchDetection_RegistersDetectionServices()
    {
        using var provider = new ServiceCollection().AddAccessWatchDetection().BuildServiceProvider();

        Assert.IsType<AppIdentityResolver>(provider.GetRequiredService<IAppIdentityResolver>());
        Assert.IsType<ListeningPortScanner>(provider.GetRequiredService<IListeningPortScanner>());
        Assert.IsType<ConnectionTrustHelper>(provider.GetRequiredService<ConnectionTrustHelper>());
    }

    /// <summary>
    /// Verifies rule registration wires scoring services.
    /// </summary>
    [Fact]
    public void AddAccessWatchRules_RegistersScoring()
    {
        using var provider = new ServiceCollection().AddAccessWatchRules().BuildServiceProvider();

        Assert.IsType<RiskScoringService>(provider.GetRequiredService<IRiskScoringService>());
        Assert.IsType<NotificationActionPolicy>(provider.GetRequiredService<NotificationActionPolicy>());
    }

    /// <summary>
    /// Verifies notification registration wires message creation.
    /// </summary>
    [Fact]
    public void AddAccessWatchNotifications_RegistersFactory()
    {
        using var provider = new ServiceCollection().AddAccessWatchNotifications().BuildServiceProvider();

        Assert.IsType<NotificationMessageFactory>(provider.GetRequiredService<NotificationMessageFactory>());
    }

    /// <summary>
    /// Verifies AI registration wires manual handoff.
    /// </summary>
    [Fact]
    public void AddAccessWatchAi_RegistersManualHandoff()
    {
        using var provider = new ServiceCollection().AddAccessWatchAi().BuildServiceProvider();

        Assert.IsType<ManualAiHandoffService>(provider.GetRequiredService<IAiHandoffService>());
    }
}
