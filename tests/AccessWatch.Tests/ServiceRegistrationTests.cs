using AccessWatch.AI;
using AccessWatch.Core;
using AccessWatch.Data;
using AccessWatch.Detection;
using AccessWatch.Notifications;
using AccessWatch.Rules;
using Microsoft.Extensions.Configuration;
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
    /// Verifies data registration uses the configured SQL Server connection string.
    /// </summary>
    [Fact]
    public void AddAccessWatchData_RegistersRepository()
    {
        const string connectionString = "Server=.\\SQLEXPRESS;Database=AccessWatch;Trusted_Connection=True;";
        using var provider = new ServiceCollection().AddAccessWatchData(connectionString).BuildServiceProvider();

        Assert.Equal(DatabaseProvider.SqlServer, provider.GetRequiredService<AccessWatchDatabaseOptions>().Provider);
        Assert.Equal(connectionString, provider.GetRequiredService<AccessWatchDatabaseOptions>().SqlServerConnectionString);
        Assert.IsType<SqlServerAccessWatchRepository>(provider.GetRequiredService<IAccessWatchRepository>());
    }

    /// <summary>
    /// Verifies data registration defaults to SQL Server LocalDB when no connection string is supplied.
    /// </summary>
    [Fact]
    public void AddAccessWatchData_UsesDefaultConnectionString()
    {
        using var provider = new ServiceCollection().AddAccessWatchData().BuildServiceProvider();

        Assert.Equal(AccessWatchDatabaseOptions.DefaultSqlServerConnectionString, provider.GetRequiredService<AccessWatchDatabaseOptions>().SqlServerConnectionString);
    }

    /// <summary>
    /// Verifies data registration binds SQL Server options from configuration.
    /// </summary>
    [Fact]
    public void AddAccessWatchData_WithConfiguration_BindsDatabaseOptions()
    {
        const string connectionString = "Server=.\\SQLEXPRESS;Database=AccessWatch;Trusted_Connection=True;";
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["AccessWatch:Database:Provider"] = "SqlServer",
                ["AccessWatch:Database:SqlServerConnectionString"] = connectionString
            })
            .Build();

        using var provider = new ServiceCollection().AddAccessWatchData(configuration).BuildServiceProvider();

        Assert.Equal(connectionString, provider.GetRequiredService<AccessWatchDatabaseOptions>().SqlServerConnectionString);
    }
    /// <summary>
    /// Verifies explicit SQL Server options register the SQL Server repository.
    /// </summary>
    [Fact]
    public void AddAccessWatchData_WithSqlServerOptions_RegistersRepository()
    {
        const string connectionString = "Server=(localdb)\\MSSQLLocalDB;Database=AccessWatch;Trusted_Connection=True;";
        using var provider = new ServiceCollection()
            .AddAccessWatchData(new AccessWatchDatabaseOptions { SqlServerConnectionString = connectionString })
            .BuildServiceProvider();

        Assert.Equal(connectionString, provider.GetRequiredService<AccessWatchDatabaseOptions>().ToConnectionString());
        Assert.IsType<SqlServerAccessWatchRepository>(provider.GetRequiredService<IAccessWatchRepository>());
    }

    /// <summary>
    /// Verifies SQL Server connection strings are retained.
    /// </summary>
    [Fact]
    public void AccessWatchDatabaseOptions_WithSqlServerConnectionString_ReturnsConfiguredValue()
    {
        var options = new AccessWatchDatabaseOptions
        {
            Provider = DatabaseProvider.SqlServer,
            SqlServerConnectionString = "Server=.\\SQLEXPRESS;Database=AccessWatch;Trusted_Connection=True;"
        };

        Assert.Equal("Server=.\\SQLEXPRESS;Database=AccessWatch;Trusted_Connection=True;", options.ToConnectionString());
    }

    /// <summary>
    /// Verifies SQL Server options provide a LocalDB default connection string.
    /// </summary>
    [Fact]
    public void AccessWatchDatabaseOptions_WithDefaultConnectionString_ReturnsLocalDb()
    {
        var options = new AccessWatchDatabaseOptions { Provider = DatabaseProvider.SqlServer };

        Assert.Equal(AccessWatchDatabaseOptions.DefaultSqlServerConnectionString, options.ToConnectionString());
    }

    /// <summary>
    /// Verifies unknown provider values are rejected by options.
    /// </summary>
    [Fact]
    public void AccessWatchDatabaseOptions_WithUnknownProvider_Throws()
    {
        var options = new AccessWatchDatabaseOptions { Provider = (DatabaseProvider)999 };

        var exception = Assert.Throws<NotSupportedException>(options.ToConnectionString);

        Assert.Contains("999", exception.Message);
    }

    /// <summary>
    /// Verifies unknown provider values are rejected by service registration.
    /// </summary>
    [Fact]
    public void AddAccessWatchData_WithUnknownProvider_Throws()
    {
        var services = new ServiceCollection();

        var exception = Assert.Throws<NotSupportedException>(() => services.AddAccessWatchData(new AccessWatchDatabaseOptions
        {
            Provider = (DatabaseProvider)999
        }));

        Assert.Contains("999", exception.Message);
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
        Assert.IsType<NetworkDeviceDiscoveryService>(provider.GetRequiredService<INetworkDeviceDiscoveryService>());
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
        Assert.IsType<InMemoryTrayNotificationService>(provider.GetRequiredService<ITrayNotificationService>());
    }

    /// <summary>
    /// Verifies AI registration wires manual handoff.
    /// </summary>
    [Fact]
    public void AddAccessWatchAi_RegistersManualHandoff()
    {
        using var provider = new ServiceCollection().AddAccessWatchAi().BuildServiceProvider();

        Assert.IsType<ManualAiHandoffService>(provider.GetRequiredService<IAiHandoffService>());
        Assert.IsType<SupportBridgeInvestigationBridge>(provider.GetRequiredService<IAiInvestigationBridge>());
    }
}




