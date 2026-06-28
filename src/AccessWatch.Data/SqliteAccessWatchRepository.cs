using AccessWatch.Core;
using Microsoft.Data.Sqlite;

namespace AccessWatch.Data;

/// <summary>
/// SQLite-backed repository for AccessWatch observations.
/// </summary>
public sealed class SqliteAccessWatchRepository : IAccessWatchRepository
{
    private readonly AccessWatchDatabaseOptions options;

    /// <summary>
    /// Initializes a new repository instance.
    /// </summary>
    /// <param name="options">Database options.</param>
    public SqliteAccessWatchRepository(AccessWatchDatabaseOptions options)
    {
        this.options = options;
    }

    /// <inheritdoc />
    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(options.DatabasePath)!);
        using var connection = await OpenConnectionAsync(cancellationToken);

        foreach (var statement in SchemaStatements)
        {
            using var command = connection.CreateCommand();
            command.CommandText = statement;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    /// <inheritdoc />
    public async Task<long> UpsertApplicationAsync(ApplicationIdentity application, CancellationToken cancellationToken)
    {
        using var connection = await OpenConnectionAsync(cancellationToken);
        var existingId = await FindApplicationIdAsync(connection, application, cancellationToken);
        var now = DateTimeOffset.UtcNow;

        if (existingId is not null)
        {
            using var update = connection.CreateCommand();
            update.CommandText = """
                UPDATE Applications
                SET DisplayName = $displayName,
                    ProcessName = $processName,
                    FilePath = $filePath,
                    Publisher = $publisher,
                    ProductName = $productName,
                    FileDescription = $fileDescription,
                    SignatureStatus = $signatureStatus,
                    HashSha256 = $hashSha256,
                    InstallFolder = $installFolder,
                    ParentProcessName = $parentProcessName,
                    LastSeenUtc = $lastSeenUtc
                WHERE ApplicationId = $applicationId;
                """;
            AddApplicationParameters(update, application, now);
            update.Parameters.AddWithValue("$applicationId", existingId.Value);
            await update.ExecuteNonQueryAsync(cancellationToken);
            return existingId.Value;
        }

        using var insert = connection.CreateCommand();
        insert.CommandText = """
            INSERT INTO Applications
            (DisplayName, ProcessName, FilePath, Publisher, ProductName, FileDescription, SignatureStatus,
             HashSha256, InstallFolder, ParentProcessName, FirstSeenUtc, LastSeenUtc, TrustStatus, Notes)
            VALUES
            ($displayName, $processName, $filePath, $publisher, $productName, $fileDescription, $signatureStatus,
             $hashSha256, $installFolder, $parentProcessName, $firstSeenUtc, $lastSeenUtc, $trustStatus, $notes);
            SELECT last_insert_rowid();
            """;
        AddApplicationParameters(insert, application, now);
        insert.Parameters.AddWithValue("$firstSeenUtc", ToDatabaseTime(application.FirstSeenUtc, now));
        insert.Parameters.AddWithValue("$trustStatus", application.TrustStatus.ToString());
        insert.Parameters.AddWithValue("$notes", DbValue(application.Notes));
        return Convert.ToInt64(await insert.ExecuteScalarAsync(cancellationToken));
    }

    /// <inheritdoc />
    public async Task<bool> UpsertPortAsync(ListeningPort port, long? applicationId, CancellationToken cancellationToken)
    {
        using var connection = await OpenConnectionAsync(cancellationToken);
        var existingId = await FindPortIdAsync(connection, port, cancellationToken);
        var now = DateTimeOffset.UtcNow;

        if (existingId is not null)
        {
            using var update = connection.CreateCommand();
            update.CommandText = """
                UPDATE Ports
                SET Reachability = $reachability,
                    OwningProcessId = $owningProcessId,
                    ApplicationId = $applicationId,
                    LastSeenUtc = $lastSeenUtc,
                    TrustStatus = $trustStatus,
                    RiskStatus = $riskStatus
                WHERE PortId = $portId;
                """;
            AddPortParameters(update, port, applicationId, now);
            update.Parameters.AddWithValue("$portId", existingId.Value);
            await update.ExecuteNonQueryAsync(cancellationToken);
            return false;
        }

        using var insert = connection.CreateCommand();
        insert.CommandText = """
            INSERT INTO Ports
            (PortNumber, Protocol, LocalAddress, Reachability, OwningProcessId, ApplicationId,
             FirstSeenUtc, LastSeenUtc, TrustStatus, RiskStatus)
            VALUES
            ($portNumber, $protocol, $localAddress, $reachability, $owningProcessId, $applicationId,
             $firstSeenUtc, $lastSeenUtc, $trustStatus, $riskStatus);
            """;
        AddPortParameters(insert, port, applicationId, now);
        insert.Parameters.AddWithValue("$firstSeenUtc", ToDatabaseTime(port.FirstSeenUtc, now));
        await insert.ExecuteNonQueryAsync(cancellationToken);
        return true;
    }

    /// <inheritdoc />
    public async Task AddNetworkEventAsync(NetworkEvent networkEvent, CancellationToken cancellationToken)
    {
        using var connection = await OpenConnectionAsync(cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO NetworkEvents
            (EventType, SourceIp, SourceDeviceId, DestinationIp, DestinationPort, Protocol, Direction,
             ApplicationId, RiskLevel, Summary, DetailsJson, WasUserNotified, CreatedUtc)
            VALUES
            ($eventType, $sourceIp, $sourceDeviceId, $destinationIp, $destinationPort, $protocol, $direction,
             $applicationId, $riskLevel, $summary, $detailsJson, $wasUserNotified, $createdUtc);
            """;
        command.Parameters.AddWithValue("$eventType", networkEvent.EventType);
        command.Parameters.AddWithValue("$sourceIp", DbValue(networkEvent.SourceIp));
        command.Parameters.AddWithValue("$sourceDeviceId", DbValue(networkEvent.SourceDeviceId));
        command.Parameters.AddWithValue("$destinationIp", DbValue(networkEvent.DestinationIp));
        command.Parameters.AddWithValue("$destinationPort", DbValue(networkEvent.DestinationPort));
        command.Parameters.AddWithValue("$protocol", networkEvent.Protocol);
        command.Parameters.AddWithValue("$direction", networkEvent.Direction);
        command.Parameters.AddWithValue("$applicationId", DbValue(networkEvent.ApplicationId));
        command.Parameters.AddWithValue("$riskLevel", networkEvent.RiskLevel.ToString());
        command.Parameters.AddWithValue("$summary", networkEvent.Summary);
        command.Parameters.AddWithValue("$detailsJson", networkEvent.DetailsJson);
        command.Parameters.AddWithValue("$wasUserNotified", networkEvent.WasUserNotified ? 1 : 0);
        command.Parameters.AddWithValue("$createdUtc", ToDatabaseTime(networkEvent.CreatedUtc, DateTimeOffset.UtcNow));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<long> AddTrustDecisionAsync(TrustDecision trustDecision, CancellationToken cancellationToken)
    {
        using var connection = await OpenConnectionAsync(cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO TrustDecisions
            (TargetType, TargetId, Decision, ExpiresUtc, Reason, CreatedUtc)
            VALUES
            ($targetType, $targetId, $decision, $expiresUtc, $reason, $createdUtc);
            SELECT last_insert_rowid();
            """;
        command.Parameters.AddWithValue("$targetType", trustDecision.TargetType);
        command.Parameters.AddWithValue("$targetId", trustDecision.TargetId);
        command.Parameters.AddWithValue("$decision", trustDecision.Decision.ToString());
        command.Parameters.AddWithValue("$expiresUtc", DbValue(ToNullableDatabaseTime(trustDecision.ExpiresUtc)));
        command.Parameters.AddWithValue("$reason", trustDecision.Reason);
        command.Parameters.AddWithValue("$createdUtc", ToDatabaseTime(trustDecision.CreatedUtc, DateTimeOffset.UtcNow));
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken));
    }

    /// <inheritdoc />
    public async Task<TrustStatus?> GetActiveTrustDecisionAsync(string targetType, long targetId, CancellationToken cancellationToken)
    {
        using var connection = await OpenConnectionAsync(cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT Decision
            FROM TrustDecisions
            WHERE TargetType = $targetType
              AND TargetId = $targetId
              AND (ExpiresUtc IS NULL OR ExpiresUtc > $nowUtc)
            ORDER BY CreatedUtc DESC, TrustDecisionId DESC
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$targetType", targetType);
        command.Parameters.AddWithValue("$targetId", targetId);
        command.Parameters.AddWithValue("$nowUtc", DateTimeOffset.UtcNow.UtcDateTime.ToString("O"));
        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value is string decision && Enum.TryParse<TrustStatus>(decision, out var trustStatus)
            ? trustStatus
            : null;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<ApplicationIdentity>> ListRecentApplicationsAsync(int limit, CancellationToken cancellationToken)
    {
        using var connection = await OpenConnectionAsync(cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT ApplicationId, DisplayName, ProcessName, FilePath, Publisher, ProductName, FileDescription,
                   SignatureStatus, HashSha256, InstallFolder, ParentProcessName, FirstSeenUtc, LastSeenUtc,
                   TrustStatus, Notes
            FROM Applications
            ORDER BY LastSeenUtc DESC, ApplicationId DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", NormalizeLimit(limit));
        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var applications = new List<ApplicationIdentity>();
        while (await reader.ReadAsync(cancellationToken))
        {
            applications.Add(ReadApplication(reader));
        }

        return applications;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<ListeningPort>> ListRecentPortsAsync(int limit, CancellationToken cancellationToken)
    {
        using var connection = await OpenConnectionAsync(cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT PortId, PortNumber, Protocol, LocalAddress, Reachability, OwningProcessId, ApplicationId,
                   FirstSeenUtc, LastSeenUtc, TrustStatus, RiskStatus
            FROM Ports
            ORDER BY LastSeenUtc DESC, PortId DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", NormalizeLimit(limit));
        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var ports = new List<ListeningPort>();
        while (await reader.ReadAsync(cancellationToken))
        {
            ports.Add(ReadPort(reader));
        }

        return ports;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<NetworkEvent>> ListRecentNetworkEventsAsync(int limit, CancellationToken cancellationToken)
    {
        using var connection = await OpenConnectionAsync(cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT EventId, EventType, SourceIp, SourceDeviceId, DestinationIp, DestinationPort, Protocol, Direction,
                   ApplicationId, RiskLevel, Summary, DetailsJson, WasUserNotified, CreatedUtc
            FROM NetworkEvents
            ORDER BY CreatedUtc DESC, EventId DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", NormalizeLimit(limit));
        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var events = new List<NetworkEvent>();
        while (await reader.ReadAsync(cancellationToken))
        {
            events.Add(ReadNetworkEvent(reader));
        }

        return events;
    }

    private static readonly string[] SchemaStatements =
    [
        """
        CREATE TABLE IF NOT EXISTS Devices (
            DeviceId INTEGER PRIMARY KEY AUTOINCREMENT,
            IpAddress TEXT NOT NULL,
            MacAddress TEXT NULL,
            Hostname TEXT NULL,
            Vendor TEXT NULL,
            DeviceTypeGuess TEXT NULL,
            TrustStatus TEXT NOT NULL,
            RiskStatus TEXT NOT NULL,
            FirstSeenUtc TEXT NOT NULL,
            LastSeenUtc TEXT NOT NULL,
            LastConfirmedUtc TEXT NULL,
            Notes TEXT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Applications (
            ApplicationId INTEGER PRIMARY KEY AUTOINCREMENT,
            DisplayName TEXT NOT NULL,
            ProcessName TEXT NOT NULL,
            FilePath TEXT NULL,
            Publisher TEXT NULL,
            ProductName TEXT NULL,
            FileDescription TEXT NULL,
            SignatureStatus TEXT NOT NULL,
            HashSha256 TEXT NULL,
            InstallFolder TEXT NULL,
            ParentProcessName TEXT NULL,
            FirstSeenUtc TEXT NOT NULL,
            LastSeenUtc TEXT NOT NULL,
            TrustStatus TEXT NOT NULL,
            Notes TEXT NULL
        );
        """,
        "CREATE UNIQUE INDEX IF NOT EXISTS IX_Applications_Identity ON Applications (ProcessName, IFNULL(FilePath, ''), IFNULL(HashSha256, ''));",
        """
        CREATE TABLE IF NOT EXISTS Ports (
            PortId INTEGER PRIMARY KEY AUTOINCREMENT,
            PortNumber INTEGER NOT NULL,
            Protocol TEXT NOT NULL,
            LocalAddress TEXT NOT NULL,
            Reachability TEXT NOT NULL,
            OwningProcessId INTEGER NULL,
            ApplicationId INTEGER NULL,
            FirstSeenUtc TEXT NOT NULL,
            LastSeenUtc TEXT NOT NULL,
            TrustStatus TEXT NOT NULL,
            RiskStatus TEXT NOT NULL,
            FOREIGN KEY (ApplicationId) REFERENCES Applications(ApplicationId)
        );
        """,
        "CREATE UNIQUE INDEX IF NOT EXISTS IX_Ports_Identity ON Ports (PortNumber, Protocol, LocalAddress);",
        """
        CREATE TABLE IF NOT EXISTS NetworkEvents (
            EventId INTEGER PRIMARY KEY AUTOINCREMENT,
            EventType TEXT NOT NULL,
            SourceIp TEXT NULL,
            SourceDeviceId INTEGER NULL,
            DestinationIp TEXT NULL,
            DestinationPort INTEGER NULL,
            Protocol TEXT NOT NULL,
            Direction TEXT NOT NULL,
            ApplicationId INTEGER NULL,
            RiskLevel TEXT NOT NULL,
            Summary TEXT NOT NULL,
            DetailsJson TEXT NOT NULL,
            WasUserNotified INTEGER NOT NULL,
            CreatedUtc TEXT NOT NULL,
            FOREIGN KEY (SourceDeviceId) REFERENCES Devices(DeviceId),
            FOREIGN KEY (ApplicationId) REFERENCES Applications(ApplicationId)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Incidents (
            IncidentId INTEGER PRIMARY KEY AUTOINCREMENT,
            Title TEXT NOT NULL,
            Summary TEXT NOT NULL,
            MainDeviceId INTEGER NULL,
            MainApplicationId INTEGER NULL,
            RiskLevel TEXT NOT NULL,
            Status TEXT NOT NULL,
            EventCount INTEGER NOT NULL,
            StartedUtc TEXT NOT NULL,
            LastUpdatedUtc TEXT NOT NULL,
            ResolvedUtc TEXT NULL,
            UserNotes TEXT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS Rules (
            RuleId INTEGER PRIMARY KEY AUTOINCREMENT,
            Name TEXT NOT NULL,
            Description TEXT NOT NULL,
            ConditionJson TEXT NOT NULL,
            RiskLevel TEXT NOT NULL,
            Action TEXT NOT NULL,
            Enabled INTEGER NOT NULL,
            CreatedUtc TEXT NOT NULL,
            UpdatedUtc TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS TrustDecisions (
            TrustDecisionId INTEGER PRIMARY KEY AUTOINCREMENT,
            TargetType TEXT NOT NULL,
            TargetId INTEGER NOT NULL,
            Decision TEXT NOT NULL,
            ExpiresUtc TEXT NULL,
            Reason TEXT NOT NULL,
            CreatedUtc TEXT NOT NULL
        );
        """
    ];

    private async Task<SqliteConnection> OpenConnectionAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(options.ToConnectionString());
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    private static async Task<long?> FindApplicationIdAsync(SqliteConnection connection, ApplicationIdentity application, CancellationToken cancellationToken)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT ApplicationId
            FROM Applications
            WHERE ProcessName = $processName
              AND IFNULL(FilePath, '') = IFNULL($filePath, '')
              AND IFNULL(HashSha256, '') = IFNULL($hashSha256, '')
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$processName", application.ProcessName);
        command.Parameters.AddWithValue("$filePath", DbValue(application.FilePath));
        command.Parameters.AddWithValue("$hashSha256", DbValue(application.HashSha256));
        return await command.ExecuteScalarAsync(cancellationToken) as long?;
    }

    private static async Task<long?> FindPortIdAsync(SqliteConnection connection, ListeningPort port, CancellationToken cancellationToken)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT PortId
            FROM Ports
            WHERE PortNumber = $portNumber AND Protocol = $protocol AND LocalAddress = $localAddress
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$portNumber", port.PortNumber);
        command.Parameters.AddWithValue("$protocol", port.Protocol);
        command.Parameters.AddWithValue("$localAddress", port.LocalAddress);
        return await command.ExecuteScalarAsync(cancellationToken) as long?;
    }

    private static void AddApplicationParameters(SqliteCommand command, ApplicationIdentity application, DateTimeOffset now)
    {
        command.Parameters.AddWithValue("$displayName", application.DisplayName);
        command.Parameters.AddWithValue("$processName", application.ProcessName);
        command.Parameters.AddWithValue("$filePath", DbValue(application.FilePath));
        command.Parameters.AddWithValue("$publisher", DbValue(application.Publisher));
        command.Parameters.AddWithValue("$productName", DbValue(application.ProductName));
        command.Parameters.AddWithValue("$fileDescription", DbValue(application.FileDescription));
        command.Parameters.AddWithValue("$signatureStatus", application.SignatureStatus.ToString());
        command.Parameters.AddWithValue("$hashSha256", DbValue(application.HashSha256));
        command.Parameters.AddWithValue("$installFolder", DbValue(application.InstallFolder));
        command.Parameters.AddWithValue("$parentProcessName", DbValue(application.ParentProcessName));
        command.Parameters.AddWithValue("$lastSeenUtc", ToDatabaseTime(application.LastSeenUtc, now));
    }

    private static void AddPortParameters(SqliteCommand command, ListeningPort port, long? applicationId, DateTimeOffset now)
    {
        command.Parameters.AddWithValue("$portNumber", port.PortNumber);
        command.Parameters.AddWithValue("$protocol", port.Protocol);
        command.Parameters.AddWithValue("$localAddress", port.LocalAddress);
        command.Parameters.AddWithValue("$reachability", port.Reachability.ToString());
        command.Parameters.AddWithValue("$owningProcessId", DbValue(port.OwningProcessId));
        command.Parameters.AddWithValue("$applicationId", DbValue(applicationId));
        command.Parameters.AddWithValue("$lastSeenUtc", ToDatabaseTime(port.LastSeenUtc, now));
        command.Parameters.AddWithValue("$trustStatus", port.TrustStatus.ToString());
        command.Parameters.AddWithValue("$riskStatus", port.RiskStatus.ToString());
    }

    private static object DbValue<T>(T? value)
    {
        return value is null ? DBNull.Value : value;
    }

    private static string ToDatabaseTime(DateTimeOffset value, DateTimeOffset fallback)
    {
        return (value == default ? fallback : value).UtcDateTime.ToString("O");
    }

    private static string? ToNullableDatabaseTime(DateTimeOffset? value)
    {
        return value?.UtcDateTime.ToString("O");
    }

    private static int NormalizeLimit(int limit)
    {
        return Math.Clamp(limit, 1, 500);
    }

    private static ApplicationIdentity ReadApplication(SqliteDataReader reader)
    {
        return new ApplicationIdentity
        {
            ApplicationId = reader.GetInt64(0),
            DisplayName = reader.GetString(1),
            ProcessName = reader.GetString(2),
            FilePath = ReadNullableString(reader, 3),
            Publisher = ReadNullableString(reader, 4),
            ProductName = ReadNullableString(reader, 5),
            FileDescription = ReadNullableString(reader, 6),
            SignatureStatus = Enum.Parse<SignatureStatus>(reader.GetString(7)),
            HashSha256 = ReadNullableString(reader, 8),
            InstallFolder = ReadNullableString(reader, 9),
            ParentProcessName = ReadNullableString(reader, 10),
            FirstSeenUtc = DateTimeOffset.Parse(reader.GetString(11)),
            LastSeenUtc = DateTimeOffset.Parse(reader.GetString(12)),
            TrustStatus = Enum.Parse<TrustStatus>(reader.GetString(13)),
            Notes = ReadNullableString(reader, 14)
        };
    }

    private static ListeningPort ReadPort(SqliteDataReader reader)
    {
        return new ListeningPort
        {
            PortId = reader.GetInt64(0),
            PortNumber = reader.GetInt32(1),
            Protocol = reader.GetString(2),
            LocalAddress = reader.GetString(3),
            Reachability = Enum.Parse<PortReachability>(reader.GetString(4)),
            OwningProcessId = ReadNullableInt32(reader, 5),
            FirstSeenUtc = DateTimeOffset.Parse(reader.GetString(7)),
            LastSeenUtc = DateTimeOffset.Parse(reader.GetString(8)),
            TrustStatus = Enum.Parse<TrustStatus>(reader.GetString(9)),
            RiskStatus = Enum.Parse<RiskStatus>(reader.GetString(10))
        };
    }

    private static NetworkEvent ReadNetworkEvent(SqliteDataReader reader)
    {
        return new NetworkEvent
        {
            EventId = reader.GetInt64(0),
            EventType = reader.GetString(1),
            SourceIp = ReadNullableString(reader, 2),
            SourceDeviceId = ReadNullableInt64(reader, 3),
            DestinationIp = ReadNullableString(reader, 4),
            DestinationPort = ReadNullableInt32(reader, 5),
            Protocol = reader.GetString(6),
            Direction = reader.GetString(7),
            ApplicationId = ReadNullableInt64(reader, 8),
            RiskLevel = Enum.Parse<RiskLevel>(reader.GetString(9)),
            Summary = reader.GetString(10),
            DetailsJson = reader.GetString(11),
            WasUserNotified = reader.GetInt32(12) == 1,
            CreatedUtc = DateTimeOffset.Parse(reader.GetString(13))
        };
    }

    private static string? ReadNullableString(SqliteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    }

    private static int? ReadNullableInt32(SqliteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? null : reader.GetInt32(ordinal);
    }

    private static long? ReadNullableInt64(SqliteDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? null : reader.GetInt64(ordinal);
    }
}

