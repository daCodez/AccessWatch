using AccessWatch.Core;
using AccessWatch.Data;
using Microsoft.Data.Sqlite;
using ApplicationIdentity = AccessWatch.Core.ApplicationIdentity;

namespace AccessWatch.Tests;

/// <summary>
/// Tests SQLite repository persistence behavior.
/// </summary>
public sealed class SqliteAccessWatchRepositoryTests
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

        Assert.Equal(7, await database.CountAsync("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('Devices','Applications','Ports','NetworkEvents','Incidents','Rules','TrustDecisions')"));
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
        Assert.Equal("Updated", await database.ScalarStringAsync("SELECT DisplayName FROM Applications WHERE ApplicationId = $id", firstId));
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
        Assert.Equal("Watched", await database.ScalarStringAsync("SELECT RiskStatus FROM Ports WHERE PortNumber = 3389", null));
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

        Assert.Equal(1, await database.CountAsync("SELECT COUNT(*) FROM NetworkEvents WHERE WasUserNotified = 1"));
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

        Assert.Equal(1, await database.CountAsync("SELECT COUNT(*) FROM NetworkEvents WHERE WasUserNotified = 0"));
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

    private sealed class TempDatabase : IDisposable
    {
        private readonly string path;

        private TempDatabase(string path)
        {
            this.path = path;
        }

        public static TempDatabase Create()
        {
            return new TempDatabase(Path.Combine(Path.GetTempPath(), $"AccessWatch.Tests.{Guid.NewGuid():N}.db"));
        }

        public SqliteAccessWatchRepository CreateRepository()
        {
            return new SqliteAccessWatchRepository(new AccessWatchDatabaseOptions { DatabasePath = path });
        }

        public async Task<int> CountAsync(string sql)
        {
            await using var connection = new SqliteConnection($"Data Source={path}");
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            return Convert.ToInt32(await command.ExecuteScalarAsync());
        }

        public async Task<string?> ScalarStringAsync(string sql, long? id)
        {
            await using var connection = new SqliteConnection($"Data Source={path}");
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            if (id is not null)
            {
                command.Parameters.AddWithValue("$id", id.Value);
            }

            return Convert.ToString(await command.ExecuteScalarAsync());
        }

        public void Dispose()
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}
