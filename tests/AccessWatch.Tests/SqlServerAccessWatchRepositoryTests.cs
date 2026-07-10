using AccessWatch.Core;
using AccessWatch.Data;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;
using ApplicationIdentity = AccessWatch.Core.ApplicationIdentity;

namespace AccessWatch.Tests;

/// <summary>
/// Tests SQL Server repository persistence behavior.
/// </summary>
public sealed class SqlServerAccessWatchRepositoryTests
{
    /// <summary>
    /// Verifies schema initialization creates required tables.
    /// </summary>
    [Fact]
    public async Task InitializeAsync_CreatesMvpTables()
    {
        using var database = TempDatabase.Create();
        var repository = database.CreateRepository();

        await repository.InitializeAsync(CancellationToken.None);

        Assert.Equal(7, await database.CountAsync("SELECT COUNT(*) FROM sys.tables WHERE name IN ('Devices','Applications','Ports','NetworkEvents','Incidents','Rules','TrustDecisions')"));
    }

    /// <summary>
    /// Verifies schema initialization works when the active connection string has no database catalog.
    /// </summary>
    [Fact]
    public async Task InitializeAsync_WithServerOnlyConnectionString_SkipsDatabaseCreation()
    {
        using var database = TempDatabase.CreateWithoutCatalog();
        var repository = database.CreateRepository();

        await repository.InitializeAsync(CancellationToken.None);

        Assert.Equal(7, await database.CountAsync("SELECT COUNT(*) FROM sys.tables WHERE name IN ('Devices','Applications','Ports','NetworkEvents','Incidents','Rules','TrustDecisions')"));
    }

    /// <summary>
    /// Verifies device upsert inserts once, updates the same row, and lists recent devices.
    /// </summary>
    [Fact]
    public async Task UpsertDeviceAsync_InsertsUpdatesAndListsDevice()
    {
        using var database = TempDatabase.Create();
        var repository = database.CreateRepository();
        await repository.InitializeAsync(CancellationToken.None);

        var device = new NetworkDevice
        {
            IpAddress = "192.168.1.25",
            MacAddress = "AA:BB:CC:DD:EE:FF",
            Hostname = "living-room",
            DeviceTypeGuess = "Unknown",
            TrustStatus = TrustStatus.Unknown,
            RiskStatus = RiskStatus.Normal,
            FirstSeenUtc = DateTimeOffset.UnixEpoch,
            LastSeenUtc = DateTimeOffset.UnixEpoch
        };

        var firstId = await repository.UpsertDeviceAsync(device, CancellationToken.None);
        await repository.UpdateDeviceAliasAsync(firstId, "  Media Center  ", CancellationToken.None);
        var secondId = await repository.UpsertDeviceAsync(device with { Hostname = "living-room-tv", Vendor = "Example Vendor", LastConfirmedUtc = DateTimeOffset.UnixEpoch.AddMinutes(2) }, CancellationToken.None);
        await repository.UpsertDeviceAsync(device with { IpAddress = "192.168.1.26", LastConfirmedUtc = null }, CancellationToken.None);
        await repository.UpsertDeviceAsync(device with { IpAddress = "192.168.1.27", UserAlias = "Kitchen Tablet" }, CancellationToken.None);
        var devices = await repository.ListRecentDevicesAsync(10, CancellationToken.None);

        Assert.Equal(3, devices.Count);
        var saved = Assert.Single(devices, device => device.IpAddress == "192.168.1.25");
        var unconfirmed = Assert.Single(devices, device => device.IpAddress == "192.168.1.26");
        var aliased = Assert.Single(devices, device => device.IpAddress == "192.168.1.27");
        Assert.Equal(firstId, secondId);
        Assert.Equal("living-room-tv", saved.Hostname);
        Assert.Equal("Media Center", saved.UserAlias);
        Assert.Equal("Example Vendor", saved.Vendor);
        Assert.Equal("Kitchen Tablet", aliased.UserAlias);
        Assert.Equal(DateTimeOffset.UnixEpoch.AddMinutes(2), saved.LastConfirmedUtc);
        Assert.Null(unconfirmed.LastConfirmedUtc);

        await repository.UpdateDeviceAliasAsync(firstId, null, CancellationToken.None);
        saved = Assert.Single(await repository.ListRecentDevicesAsync(10, CancellationToken.None), device => device.IpAddress == "192.168.1.25");
        Assert.Null(saved.UserAlias);
    }

    /// <summary>
    /// Verifies incident and rule persistence round trips rows for future dashboard and editor surfaces.
    /// </summary>
    [Fact]
    public async Task IncidentAndRulePersistence_RoundTripsRows()
    {
        using var database = TempDatabase.Create();
        var repository = database.CreateRepository();
        await repository.InitializeAsync(CancellationToken.None);

        var incidentId = await repository.UpsertIncidentAsync(new Incident
        {
            Title = "Remote access review",
            Summary = "Remote Desktop opened on the network.",
            RiskLevel = RiskLevel.High,
            Status = IncidentStatus.Open,
            EventCount = 1,
            StartedUtc = DateTimeOffset.UnixEpoch,
            LastUpdatedUtc = DateTimeOffset.UnixEpoch.AddMinutes(1)
        }, CancellationToken.None);
        await repository.UpsertIncidentAsync(new Incident
        {
            IncidentId = incidentId,
            Title = "Remote access review",
            Summary = "Two related events.",
            RiskLevel = RiskLevel.High,
            Status = IncidentStatus.Watching,
            EventCount = 2,
            StartedUtc = DateTimeOffset.UnixEpoch,
            LastUpdatedUtc = DateTimeOffset.UnixEpoch.AddMinutes(2),
            ResolvedUtc = DateTimeOffset.UnixEpoch.AddMinutes(3),
            UserNotes = "Reviewed"
        }, CancellationToken.None);

        var disabledRuleId = await repository.UpsertRuleAsync(new AccessWatchRule
        {
            Name = "Disabled remote admin rule",
            Description = "Disabled test rule.",
            ConditionJson = "{\"port\":3389}",
            RiskLevel = RiskLevel.High,
            Action = NotificationAction.AskBeforeAllow,
            Enabled = false,
            CreatedUtc = DateTimeOffset.UnixEpoch,
            UpdatedUtc = DateTimeOffset.UnixEpoch
        }, CancellationToken.None);
        await repository.UpsertRuleAsync(new AccessWatchRule
        {
            RuleId = disabledRuleId,
            Name = "Disabled remote admin rule",
            Description = "Still disabled.",
            ConditionJson = "{\"port\":3389}",
            RiskLevel = RiskLevel.High,
            Action = NotificationAction.AskBeforeAllow,
            Enabled = false,
            CreatedUtc = DateTimeOffset.UnixEpoch,
            UpdatedUtc = DateTimeOffset.UnixEpoch.AddMinutes(1)
        }, CancellationToken.None);
        await repository.UpsertRuleAsync(new AccessWatchRule
        {
            Name = "Active SSH rule",
            Description = "Review SSH listeners.",
            ConditionJson = "{\"port\":22}",
            RiskLevel = RiskLevel.High,
            Action = NotificationAction.AskBeforeAllow,
            Enabled = true,
            CreatedUtc = DateTimeOffset.UnixEpoch,
            UpdatedUtc = DateTimeOffset.UnixEpoch
        }, CancellationToken.None);

        var incident = Assert.Single(await repository.ListRecentIncidentsAsync(10, CancellationToken.None));
        var activeRule = Assert.Single(await repository.ListRulesAsync(false, CancellationToken.None));
        var allRules = await repository.ListRulesAsync(true, CancellationToken.None);

        Assert.Equal(IncidentStatus.Watching, incident.Status);
        Assert.Equal(2, incident.EventCount);
        Assert.Equal(DateTimeOffset.UnixEpoch.AddMinutes(3), incident.ResolvedUtc);
        Assert.Equal("Active SSH rule", activeRule.Name);
        Assert.Equal(2, allRules.Count);
    }

    /// <summary>
    /// Verifies application upsert inserts once and then updates the same row.
    /// </summary>
    [Fact]
    public async Task UpsertApplicationAsync_InsertsAndUpdatesApplication()
    {
        using var database = TempDatabase.Create();
        var repository = database.CreateRepository();
        await repository.InitializeAsync(CancellationToken.None);

        var application = new ApplicationIdentity
        {
            DisplayName = "Original",
            ProcessName = "app",
            FilePath = "C:\\App\\app.exe",
            HashSha256 = "HASH",
            SignatureStatus = SignatureStatus.Unsigned,
            TrustStatus = TrustStatus.Unknown,
            FirstSeenUtc = DateTimeOffset.UnixEpoch,
            LastSeenUtc = DateTimeOffset.UnixEpoch
        };

        var firstId = await repository.UpsertApplicationAsync(application, CancellationToken.None);
        var secondId = await repository.UpsertApplicationAsync(application with { DisplayName = "Updated" }, CancellationToken.None);

        Assert.Equal(firstId, secondId);
        Assert.Equal("Updated", await database.ScalarStringAsync("SELECT DisplayName FROM dbo.Applications WHERE ApplicationId = @id", firstId));
    }

    /// <summary>
    /// Verifies port upsert reports new rows once and existing rows afterward.
    /// </summary>
    [Fact]
    public async Task UpsertPortAsync_InsertsAndUpdatesPort()
    {
        using var database = TempDatabase.Create();
        var repository = database.CreateRepository();
        await repository.InitializeAsync(CancellationToken.None);

        var port = new ListeningPort
        {
            PortNumber = 3389,
            Protocol = "TCP",
            LocalAddress = "0.0.0.0",
            Reachability = PortReachability.NetworkReachable,
            RiskStatus = RiskStatus.HighRisk,
            FirstSeenUtc = DateTimeOffset.UnixEpoch,
            LastSeenUtc = DateTimeOffset.UnixEpoch
        };

        var first = await repository.UpsertPortAsync(port, null, CancellationToken.None);
        var second = await repository.UpsertPortAsync(port with { RiskStatus = RiskStatus.Watched }, null, CancellationToken.None);

        Assert.True(first);
        Assert.False(second);
        Assert.Equal("Watched", await database.ScalarStringAsync("SELECT RiskStatus FROM dbo.Ports WHERE PortNumber = 3389", null));
    }


    /// <summary>
    /// Verifies the current application attached to a known port can be read before an update.
    /// </summary>
    [Fact]
    public async Task GetListeningPortApplicationIdAsync_ReturnsCurrentApplication()
    {
        using var database = TempDatabase.Create();
        var repository = database.CreateRepository();
        await repository.InitializeAsync(CancellationToken.None);

        var applicationId = await repository.UpsertApplicationAsync(new ApplicationIdentity
        {
            DisplayName = "Owner",
            ProcessName = "owner",
            SignatureStatus = SignatureStatus.TrustedSigned
        }, CancellationToken.None);
        var port = new ListeningPort
        {
            PortNumber = 8080,
            Protocol = "TCP",
            LocalAddress = "0.0.0.0",
            Reachability = PortReachability.NetworkReachable
        };
        await repository.UpsertPortAsync(port, applicationId, CancellationToken.None);

        var storedApplicationId = await repository.GetListeningPortApplicationIdAsync(port, CancellationToken.None);
        var missingApplicationId = await repository.GetListeningPortApplicationIdAsync(port with { PortNumber = 8081 }, CancellationToken.None);

        Assert.Equal(applicationId, storedApplicationId);
        Assert.Null(missingApplicationId);
    }
    /// <summary>
    /// Verifies network events are persisted with notification state.
    /// </summary>
    [Fact]
    public async Task AddNetworkEventAsync_InsertsEvent()
    {
        using var database = TempDatabase.Create();
        var repository = database.CreateRepository();
        await repository.InitializeAsync(CancellationToken.None);

        await repository.AddNetworkEventAsync(new NetworkEvent
        {
            EventType = "NewListeningPort",
            DestinationIp = "0.0.0.0",
            DestinationPort = 22,
            Protocol = "TCP",
            Direction = "Inbound",
            RiskLevel = RiskLevel.High,
            Summary = "SSH opened.",
            DetailsJson = "{}",
            WasUserNotified = true,
            CreatedUtc = DateTimeOffset.UnixEpoch
        }, CancellationToken.None);

        Assert.Equal(1, await database.CountAsync("SELECT COUNT(*) FROM dbo.NetworkEvents WHERE WasUserNotified = 1"));
    }

    /// <summary>
    /// Verifies silent network events are persisted.
    /// </summary>
    [Fact]
    public async Task AddNetworkEventAsync_InsertsSilentEvent()
    {
        using var database = TempDatabase.Create();
        var repository = database.CreateRepository();
        await repository.InitializeAsync(CancellationToken.None);

        await repository.AddNetworkEventAsync(new NetworkEvent
        {
            EventType = "NewListeningPort",
            Protocol = "TCP",
            Direction = "Inbound",
            RiskLevel = RiskLevel.Low,
            Summary = "Local port opened.",
            DetailsJson = "{}",
            WasUserNotified = false
        }, CancellationToken.None);

        Assert.Equal(1, await database.CountAsync("SELECT COUNT(*) FROM dbo.NetworkEvents WHERE WasUserNotified = 0"));
    }

    /// <summary>
    /// Verifies recent read models return saved apps, ports, and events.
    /// </summary>
    [Fact]
    public async Task RecentReadModels_ReturnSavedRows()
    {
        using var database = TempDatabase.Create();
        var repository = database.CreateRepository();
        await repository.InitializeAsync(CancellationToken.None);

        var applicationId = await repository.UpsertApplicationAsync(new ApplicationIdentity
        {
            DisplayName = "Plex Media Server",
            ProcessName = "plex",
            SignatureStatus = SignatureStatus.TrustedSigned,
            FirstSeenUtc = DateTimeOffset.UnixEpoch,
            LastSeenUtc = DateTimeOffset.UnixEpoch.AddMinutes(1)
        }, CancellationToken.None);
        await repository.UpsertPortAsync(new ListeningPort
        {
            PortNumber = 32400,
            Protocol = "TCP",
            LocalAddress = "0.0.0.0",
            Reachability = PortReachability.NetworkReachable,
            OwningProcessId = 123,
            FirstSeenUtc = DateTimeOffset.UnixEpoch,
            LastSeenUtc = DateTimeOffset.UnixEpoch.AddMinutes(1)
        }, applicationId, CancellationToken.None);
        await repository.AddNetworkEventAsync(new NetworkEvent
        {
            EventType = "NewListeningPort",
            DestinationIp = "0.0.0.0",
            DestinationPort = 32400,
            Protocol = "TCP",
            Direction = "Inbound",
            ApplicationId = applicationId,
            RiskLevel = RiskLevel.Medium,
            Summary = "Plex opened a network-reachable port.",
            DetailsJson = "{}",
            CreatedUtc = DateTimeOffset.UnixEpoch.AddMinutes(1)
        }, CancellationToken.None);

        var applications = await repository.ListRecentApplicationsAsync(10, CancellationToken.None);
        var ports = await repository.ListRecentPortsAsync(10, CancellationToken.None);
        var events = await repository.ListRecentNetworkEventsAsync(10, CancellationToken.None);

        Assert.Equal("Plex Media Server", Assert.Single(applications).DisplayName);
        Assert.Equal(32400, Assert.Single(ports).PortNumber);
        Assert.Equal("NewListeningPort", Assert.Single(events).EventType);
    }

    /// <summary>
    /// Verifies recent read models handle nullable integer columns.
    /// </summary>
    [Fact]
    public async Task RecentReadModels_HandleNullableIntegerColumns()
    {
        using var database = TempDatabase.Create();
        var repository = database.CreateRepository();
        await repository.InitializeAsync(CancellationToken.None);

        await repository.UpsertPortAsync(new ListeningPort
        {
            PortNumber = 7000,
            Protocol = "TCP",
            LocalAddress = "127.0.0.1",
            Reachability = PortReachability.LocalOnly
        }, null, CancellationToken.None);
        await repository.AddNetworkEventAsync(new NetworkEvent
        {
            EventType = "NewListeningPort",
            Protocol = "TCP",
            Direction = "Inbound",
            RiskLevel = RiskLevel.Low,
            Summary = "Local port opened.",
            DetailsJson = "{}"
        }, CancellationToken.None);

        var port = Assert.Single(await repository.ListRecentPortsAsync(1, CancellationToken.None));
        var networkEvent = Assert.Single(await repository.ListRecentNetworkEventsAsync(1, CancellationToken.None));

        Assert.Null(port.OwningProcessId);
        Assert.Null(networkEvent.DestinationPort);
    }

    /// <summary>
    /// Verifies scan batch persistence stores devices, applications, and ports with trust context.
    /// </summary>
    [Fact]
    public async Task BatchPersistence_RoundTripsScanWrites()
    {
        using var database = TempDatabase.Create();
        var logger = new CapturingLogger<SqlServerAccessWatchRepository>();
        var repository = database.CreateRepository(logger);
        await repository.InitializeAsync(CancellationToken.None);
        var device = new NetworkDevice
        {
            IpAddress = "192.168.1.40",
            MacAddress = "AA:BB:CC:DD:EE:40",
            TrustStatus = TrustStatus.Unknown,
            RiskStatus = RiskStatus.Normal,
            FirstSeenUtc = DateTimeOffset.UnixEpoch,
            LastSeenUtc = DateTimeOffset.UnixEpoch
        };
        var watchedDevice = device with { IpAddress = "192.168.1.42", MacAddress = "AA:BB:CC:DD:EE:42" };
        var guestDevice = device with { IpAddress = "192.168.1.43", MacAddress = "AA:BB:CC:DD:EE:43" };
        var trustedDevice = device with { IpAddress = "192.168.1.44", MacAddress = "AA:BB:CC:DD:EE:44" };
        var deviceId = await repository.UpsertDeviceAsync(device, CancellationToken.None);
        var watchedDeviceId = await repository.UpsertDeviceAsync(watchedDevice, CancellationToken.None);
        var guestDeviceId = await repository.UpsertDeviceAsync(guestDevice, CancellationToken.None);
        var trustedDeviceId = await repository.UpsertDeviceAsync(trustedDevice, CancellationToken.None);
        await repository.AddTrustDecisionAsync(new TrustDecision
        {
            TargetType = "Device",
            TargetId = deviceId,
            Decision = TrustStatus.Blocked,
            Reason = "Test block",
            CreatedUtc = DateTimeOffset.UtcNow
        }, CancellationToken.None);
        await repository.AddTrustDecisionAsync(new TrustDecision
        {
            TargetType = "Device",
            TargetId = watchedDeviceId,
            Decision = TrustStatus.KnownWatched,
            Reason = "Test watch",
            CreatedUtc = DateTimeOffset.UtcNow
        }, CancellationToken.None);
        await repository.AddTrustDecisionAsync(new TrustDecision
        {
            TargetType = "Device",
            TargetId = guestDeviceId,
            Decision = TrustStatus.Guest,
            Reason = "Test guest",
            CreatedUtc = DateTimeOffset.UtcNow
        }, CancellationToken.None);
        await repository.AddTrustDecisionAsync(new TrustDecision
        {
            TargetType = "Device",
            TargetId = trustedDeviceId,
            Decision = TrustStatus.Trusted,
            Reason = "Test trust",
            CreatedUtc = DateTimeOffset.UtcNow
        }, CancellationToken.None);
        var application = new ApplicationIdentity
        {
            DisplayName = "Remote Admin",
            ProcessName = "remote-admin",
            SignatureStatus = SignatureStatus.Unsigned,
            FirstSeenUtc = DateTimeOffset.UnixEpoch,
            LastSeenUtc = DateTimeOffset.UnixEpoch
        };
        var applicationId = await repository.UpsertApplicationAsync(application, CancellationToken.None);
        await repository.AddTrustDecisionAsync(new TrustDecision
        {
            TargetType = "Application",
            TargetId = applicationId,
            Decision = TrustStatus.KnownWatched,
            Reason = "Test watch",
            CreatedUtc = DateTimeOffset.UtcNow
        }, CancellationToken.None);
        var invalidTrustApplication = new ApplicationIdentity
        {
            DisplayName = "Broken trust text should be ignored",
            ProcessName = "broken-trust",
            SignatureStatus = SignatureStatus.Unsigned,
            FirstSeenUtc = DateTimeOffset.UnixEpoch,
            LastSeenUtc = DateTimeOffset.UnixEpoch
        };
        var invalidTrustApplicationId = await repository.UpsertApplicationAsync(invalidTrustApplication, CancellationToken.None);
        await repository.AddTrustDecisionAsync(new TrustDecision
        {
            TargetType = "Application",
            TargetId = invalidTrustApplicationId,
            Decision = TrustStatus.Trusted,
            Reason = "Will be corrupted",
            CreatedUtc = DateTimeOffset.UtcNow
        }, CancellationToken.None);
        await database.ExecuteAsync($"UPDATE dbo.TrustDecisions SET Decision = 'DefinitelyNotTrust' WHERE TargetType = 'Application' AND TargetId = {invalidTrustApplicationId};");
        var deviceResults = await repository.UpsertDevicesAsync([device, watchedDevice, guestDevice, trustedDevice], CancellationToken.None);
        var applicationResults = await repository.UpsertApplicationsAsync([application], CancellationToken.None);
        var invalidTrustResults = await repository.UpsertApplicationsAsync([invalidTrustApplication], CancellationToken.None);
        var firstPortResults = await repository.UpsertPortsAsync([
            new PortPersistenceRequest(new ListeningPort
            {
                PortNumber = 9443,
                Protocol = "TCP",
                LocalAddress = "0.0.0.0",
                Reachability = PortReachability.NetworkReachable,
                RiskStatus = RiskStatus.HighRisk,
                FirstSeenUtc = DateTimeOffset.UnixEpoch,
                LastSeenUtc = DateTimeOffset.UnixEpoch
            }, applicationId)
        ], CancellationToken.None);
        var replacementApplicationId = await repository.UpsertApplicationAsync(application with { ProcessName = "remote-admin-2", FilePath = "C:\\Tools\\remote-admin-2.exe" }, CancellationToken.None);
        var secondPortResults = await repository.UpsertPortsAsync([
            new PortPersistenceRequest(new ListeningPort
            {
                PortNumber = 9443,
                Protocol = "TCP",
                LocalAddress = "0.0.0.0",
                Reachability = PortReachability.NetworkReachable,
                RiskStatus = RiskStatus.Critical,
                LastSeenUtc = DateTimeOffset.UnixEpoch.AddMinutes(1)
            }, replacementApplicationId)
        ], CancellationToken.None);

        Assert.Equal(TrustStatus.Blocked, Assert.Single(deviceResults, result => result.Device.IpAddress == device.IpAddress).ActiveTrustStatus);
        Assert.Equal(TrustStatus.KnownWatched, Assert.Single(deviceResults, result => result.Device.IpAddress == watchedDevice.IpAddress).ActiveTrustStatus);
        Assert.Equal(TrustStatus.Guest, Assert.Single(deviceResults, result => result.Device.IpAddress == guestDevice.IpAddress).ActiveTrustStatus);
        Assert.Equal(TrustStatus.Trusted, Assert.Single(deviceResults, result => result.Device.IpAddress == trustedDevice.IpAddress).ActiveTrustStatus);
        Assert.Equal(TrustStatus.KnownWatched, Assert.Single(applicationResults).ActiveTrustStatus);
        Assert.Null(Assert.Single(invalidTrustResults).ActiveTrustStatus);
        Assert.Contains(logger.Messages, message => message.Contains("DefinitelyNotTrust", StringComparison.Ordinal));
        Assert.True(Assert.Single(firstPortResults).IsNewPort);
        var secondPort = Assert.Single(secondPortResults);
        Assert.False(secondPort.IsNewPort);
        Assert.Equal(applicationId, secondPort.PreviousApplicationId);
        Assert.Equal(replacementApplicationId, secondPort.ApplicationId);
        var savedDevices = await repository.ListRecentDevicesAsync(10, CancellationToken.None);
        Assert.Equal(RiskStatus.Critical, Assert.Single(savedDevices, savedDevice => savedDevice.IpAddress == device.IpAddress).RiskStatus);
        Assert.Equal(RiskStatus.Watched, Assert.Single(savedDevices, savedDevice => savedDevice.IpAddress == watchedDevice.IpAddress).RiskStatus);
        Assert.Equal(RiskStatus.Watched, Assert.Single(savedDevices, savedDevice => savedDevice.IpAddress == guestDevice.IpAddress).RiskStatus);
        Assert.Equal(RiskStatus.Normal, Assert.Single(savedDevices, savedDevice => savedDevice.IpAddress == trustedDevice.IpAddress).RiskStatus);
    }

    /// <summary>
    /// Verifies unexpected enum text in storage falls back safely and is logged.
    /// </summary>
    [Fact]
    public async Task RecentReadModels_FallbackAndLogInvalidEnumValues()
    {
        using var database = TempDatabase.Create();
        var logger = new CapturingLogger<SqlServerAccessWatchRepository>();
        var repository = database.CreateRepository(logger);
        await repository.InitializeAsync(CancellationToken.None);
        await repository.UpsertDeviceAsync(new NetworkDevice
        {
            IpAddress = "192.168.1.41",
            MacAddress = "AA:BB:CC:DD:EE:41",
            TrustStatus = TrustStatus.Trusted,
            RiskStatus = RiskStatus.Watched,
            FirstSeenUtc = DateTimeOffset.UnixEpoch,
            LastSeenUtc = DateTimeOffset.UnixEpoch
        }, CancellationToken.None);
        await database.ExecuteAsync("UPDATE dbo.Devices SET TrustStatus = 'DefinitelyNotTrust', RiskStatus = 'DefinitelyNotRisk';");

        var device = Assert.Single(await repository.ListRecentDevicesAsync(10, CancellationToken.None));

        Assert.Equal(TrustStatus.Unknown, device.TrustStatus);
        Assert.Equal(RiskStatus.Normal, device.RiskStatus);
        Assert.Contains(logger.Messages, message => message.Contains("DefinitelyNotTrust", StringComparison.Ordinal));
        Assert.Contains(logger.Messages, message => message.Contains("DefinitelyNotRisk", StringComparison.Ordinal));
    }
    /// <summary>
    /// Verifies active trust decisions are returned while expired decisions are ignored.
    /// </summary>
    [Fact]
    public async Task TrustDecisions_ReturnOnlyActiveLatestDecision()
    {
        using var database = TempDatabase.Create();
        var repository = database.CreateRepository();
        await repository.InitializeAsync(CancellationToken.None);

        await repository.AddTrustDecisionAsync(new TrustDecision
        {
            TargetType = "Application",
            TargetId = 42,
            Decision = TrustStatus.Guest,
            ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(-1),
            Reason = "Expired",
            CreatedUtc = DateTimeOffset.UnixEpoch
        }, CancellationToken.None);
        await repository.AddTrustDecisionAsync(new TrustDecision
        {
            TargetType = "Application",
            TargetId = 42,
            Decision = TrustStatus.Trusted,
            Reason = "User trusted Plex",
            CreatedUtc = DateTimeOffset.UnixEpoch.AddMinutes(1)
        }, CancellationToken.None);

        var decision = await repository.GetActiveTrustDecisionAsync("Application", 42, CancellationToken.None);

        Assert.Equal(TrustStatus.Trusted, decision);
        Assert.Null(await repository.GetActiveTrustDecisionAsync("Application", 99, CancellationToken.None));
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Messages.Add(formatter(state, exception));
        }
    }

    private sealed class TempDatabase : IDisposable
    {
        private const string MasterConnectionString = "Server=(localdb)\\MSSQLLocalDB;Database=master;Trusted_Connection=True;TrustServerCertificate=True;";
        private const string ServerOnlyConnectionString = "Server=(localdb)\\MSSQLLocalDB;Trusted_Connection=True;TrustServerCertificate=True;";
        private readonly string connectionString;
        private readonly string? databaseName;

        private TempDatabase(string connectionString, string? databaseName)
        {
            this.connectionString = connectionString;
            this.databaseName = databaseName;
        }

        public static TempDatabase Create()
        {
            var databaseName = $"AccessWatchTests_{Guid.NewGuid():N}";
            return new TempDatabase($"Server=(localdb)\\MSSQLLocalDB;Database={databaseName};Trusted_Connection=True;TrustServerCertificate=True;", databaseName);
        }

        public static TempDatabase CreateWithoutCatalog()
        {
            return new TempDatabase(ServerOnlyConnectionString, null);
        }

        public SqlServerAccessWatchRepository CreateRepository(ILogger<SqlServerAccessWatchRepository>? logger = null)
        {
            return new SqlServerAccessWatchRepository(new AccessWatchDatabaseOptions { SqlServerConnectionString = connectionString }, logger);
        }

        public async Task<int> CountAsync(string sql)
        {
            await using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            return Convert.ToInt32(await command.ExecuteScalarAsync());
        }

        public async Task ExecuteAsync(string sql)
        {
            await using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            await command.ExecuteNonQueryAsync();
        }

        public async Task<string?> ScalarStringAsync(string sql, long? id)
        {
            await using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            if (id is not null)
            {
                command.Parameters.AddWithValue("@id", id.Value);
            }

            return Convert.ToString(await command.ExecuteScalarAsync());
        }

        public void Dispose()
        {
            SqlConnection.ClearAllPools();
            if (databaseName is null)
            {
                return;
            }

            using var connection = new SqlConnection(MasterConnectionString);
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = $"""
                IF DB_ID(@databaseName) IS NOT NULL
                BEGIN
                    ALTER DATABASE {QuoteSqlIdentifier(databaseName)} SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
                    DROP DATABASE {QuoteSqlIdentifier(databaseName)};
                END;
                """;
            command.Parameters.AddWithValue("@databaseName", databaseName);
            command.ExecuteNonQuery();
        }

        private static string QuoteSqlIdentifier(string identifier)
        {
            return $"[{identifier.Replace("]", "]]", StringComparison.Ordinal)}]";
        }
    }
}
