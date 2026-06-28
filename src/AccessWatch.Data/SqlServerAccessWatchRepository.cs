using AccessWatch.Core;
using Microsoft.Data.SqlClient;

namespace AccessWatch.Data;

/// <summary>
/// SQL Server-backed repository for AccessWatch observations.
/// </summary>
public sealed class SqlServerAccessWatchRepository : IAccessWatchRepository
{
    private readonly AccessWatchDatabaseOptions options;

    /// <summary>
    /// Initializes a new repository instance.
    /// </summary>
    /// <param name="options">Database options.</param>
    public SqlServerAccessWatchRepository(AccessWatchDatabaseOptions options)
    {
        this.options = options;
    }

    /// <inheritdoc />
    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await EnsureDatabaseExistsAsync(cancellationToken);
        await using var connection = await OpenConnectionAsync(cancellationToken);

        foreach (var statement in SchemaStatements)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = statement;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    /// <inheritdoc />
    public async Task<long> UpsertApplicationAsync(ApplicationIdentity application, CancellationToken cancellationToken)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken);
        var existingId = await FindApplicationIdAsync(connection, application, cancellationToken);
        var now = DateTimeOffset.UtcNow;

        if (existingId is not null)
        {
            await using var update = connection.CreateCommand();
            update.CommandText = """
                UPDATE dbo.Applications
                SET DisplayName = @displayName,
                    ProcessName = @processName,
                    FilePath = @filePath,
                    Publisher = @publisher,
                    ProductName = @productName,
                    FileDescription = @fileDescription,
                    SignatureStatus = @signatureStatus,
                    HashSha256 = @hashSha256,
                    InstallFolder = @installFolder,
                    ParentProcessName = @parentProcessName,
                    LastSeenUtc = @lastSeenUtc
                WHERE ApplicationId = @applicationId;
                """;
            AddApplicationParameters(update, application, now);
            update.Parameters.AddWithValue("@applicationId", existingId.Value);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
        else
        {
            await using var insert = connection.CreateCommand();
            insert.CommandText = """
                INSERT INTO dbo.Applications
                (DisplayName, ProcessName, FilePath, Publisher, ProductName, FileDescription, SignatureStatus,
                 HashSha256, InstallFolder, ParentProcessName, FirstSeenUtc, LastSeenUtc, TrustStatus, Notes)
                VALUES
                (@displayName, @processName, @filePath, @publisher, @productName, @fileDescription, @signatureStatus,
                 @hashSha256, @installFolder, @parentProcessName, @firstSeenUtc, @lastSeenUtc, @trustStatus, @notes);
                SELECT CONVERT(bigint, SCOPE_IDENTITY());
                """;
            AddApplicationParameters(insert, application, now);
            insert.Parameters.AddWithValue("@firstSeenUtc", ToDatabaseTime(application.FirstSeenUtc, now));
            insert.Parameters.AddWithValue("@trustStatus", application.TrustStatus.ToString());
            insert.Parameters.AddWithValue("@notes", DbValue(application.Notes));
            existingId = Convert.ToInt64(await insert.ExecuteScalarAsync(cancellationToken));
        }

        return existingId.Value;
    }

    /// <inheritdoc />
    public async Task<bool> UpsertPortAsync(ListeningPort port, long? applicationId, CancellationToken cancellationToken)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken);
        var existingId = await FindPortIdAsync(connection, port, cancellationToken);
        var now = DateTimeOffset.UtcNow;
        var isNewPort = existingId is null;

        if (!isNewPort)
        {
            await using var update = connection.CreateCommand();
            update.CommandText = """
                UPDATE dbo.Ports
                SET Reachability = @reachability,
                    OwningProcessId = @owningProcessId,
                    ApplicationId = @applicationId,
                    LastSeenUtc = @lastSeenUtc,
                    TrustStatus = @trustStatus,
                    RiskStatus = @riskStatus
                WHERE PortId = @portId;
            """;
            AddPortParameters(update, port, applicationId, now);
            update.Parameters.AddWithValue("@portId", existingId.GetValueOrDefault());
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
        else
        {
            await using var insert = connection.CreateCommand();
            insert.CommandText = """
                INSERT INTO dbo.Ports
                (PortNumber, Protocol, LocalAddress, Reachability, OwningProcessId, ApplicationId,
                 FirstSeenUtc, LastSeenUtc, TrustStatus, RiskStatus)
                VALUES
                (@portNumber, @protocol, @localAddress, @reachability, @owningProcessId, @applicationId,
                 @firstSeenUtc, @lastSeenUtc, @trustStatus, @riskStatus);
                """;
            AddPortParameters(insert, port, applicationId, now);
            insert.Parameters.AddWithValue("@firstSeenUtc", ToDatabaseTime(port.FirstSeenUtc, now));
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        return isNewPort;
    }

    /// <inheritdoc />
    public async Task AddNetworkEventAsync(NetworkEvent networkEvent, CancellationToken cancellationToken)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO dbo.NetworkEvents
            (EventType, SourceIp, SourceDeviceId, DestinationIp, DestinationPort, Protocol, Direction,
             ApplicationId, RiskLevel, Summary, DetailsJson, WasUserNotified, CreatedUtc)
            VALUES
            (@eventType, @sourceIp, @sourceDeviceId, @destinationIp, @destinationPort, @protocol, @direction,
             @applicationId, @riskLevel, @summary, @detailsJson, @wasUserNotified, @createdUtc);
            """;
        command.Parameters.AddWithValue("@eventType", networkEvent.EventType);
        command.Parameters.AddWithValue("@sourceIp", DbValue(networkEvent.SourceIp));
        command.Parameters.AddWithValue("@sourceDeviceId", DbValue(networkEvent.SourceDeviceId));
        command.Parameters.AddWithValue("@destinationIp", DbValue(networkEvent.DestinationIp));
        command.Parameters.AddWithValue("@destinationPort", DbValue(networkEvent.DestinationPort));
        command.Parameters.AddWithValue("@protocol", networkEvent.Protocol);
        command.Parameters.AddWithValue("@direction", networkEvent.Direction);
        command.Parameters.AddWithValue("@applicationId", DbValue(networkEvent.ApplicationId));
        command.Parameters.AddWithValue("@riskLevel", networkEvent.RiskLevel.ToString());
        command.Parameters.AddWithValue("@summary", networkEvent.Summary);
        command.Parameters.AddWithValue("@detailsJson", networkEvent.DetailsJson);
        command.Parameters.AddWithValue("@wasUserNotified", networkEvent.WasUserNotified);
        command.Parameters.AddWithValue("@createdUtc", ToDatabaseTime(networkEvent.CreatedUtc, DateTimeOffset.UtcNow));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<long> AddTrustDecisionAsync(TrustDecision trustDecision, CancellationToken cancellationToken)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO dbo.TrustDecisions
            (TargetType, TargetId, Decision, ExpiresUtc, Reason, CreatedUtc)
            VALUES
            (@targetType, @targetId, @decision, @expiresUtc, @reason, @createdUtc);
            SELECT CONVERT(bigint, SCOPE_IDENTITY());
            """;
        command.Parameters.AddWithValue("@targetType", trustDecision.TargetType);
        command.Parameters.AddWithValue("@targetId", trustDecision.TargetId);
        command.Parameters.AddWithValue("@decision", trustDecision.Decision.ToString());
        command.Parameters.AddWithValue("@expiresUtc", DbValue(trustDecision.ExpiresUtc));
        command.Parameters.AddWithValue("@reason", trustDecision.Reason);
        command.Parameters.AddWithValue("@createdUtc", ToDatabaseTime(trustDecision.CreatedUtc, DateTimeOffset.UtcNow));
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken));
    }

    /// <inheritdoc />
    public async Task<TrustStatus?> GetActiveTrustDecisionAsync(string targetType, long targetId, CancellationToken cancellationToken)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT TOP (1) Decision
            FROM dbo.TrustDecisions
            WHERE TargetType = @targetType
              AND TargetId = @targetId
              AND (ExpiresUtc IS NULL OR ExpiresUtc > @nowUtc)
            ORDER BY CreatedUtc DESC, TrustDecisionId DESC;
            """;
        command.Parameters.AddWithValue("@targetType", targetType);
        command.Parameters.AddWithValue("@targetId", targetId);
        command.Parameters.AddWithValue("@nowUtc", DateTimeOffset.UtcNow);
        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value is string decision && Enum.TryParse<TrustStatus>(decision, out var trustStatus)
            ? trustStatus
            : null;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<ApplicationIdentity>> ListRecentApplicationsAsync(int limit, CancellationToken cancellationToken)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT TOP (@limit) ApplicationId, DisplayName, ProcessName, FilePath, Publisher, ProductName, FileDescription,
                   SignatureStatus, HashSha256, InstallFolder, ParentProcessName, FirstSeenUtc, LastSeenUtc,
                   TrustStatus, Notes
            FROM dbo.Applications
            ORDER BY LastSeenUtc DESC, ApplicationId DESC;
            """;
        command.Parameters.AddWithValue("@limit", NormalizeLimit(limit));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
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
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT TOP (@limit) PortId, PortNumber, Protocol, LocalAddress, Reachability, OwningProcessId, ApplicationId,
                   FirstSeenUtc, LastSeenUtc, TrustStatus, RiskStatus
            FROM dbo.Ports
            ORDER BY LastSeenUtc DESC, PortId DESC;
            """;
        command.Parameters.AddWithValue("@limit", NormalizeLimit(limit));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
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
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT TOP (@limit) EventId, EventType, SourceIp, SourceDeviceId, DestinationIp, DestinationPort, Protocol, Direction,
                   ApplicationId, RiskLevel, Summary, DetailsJson, WasUserNotified, CreatedUtc
            FROM dbo.NetworkEvents
            ORDER BY CreatedUtc DESC, EventId DESC;
            """;
        command.Parameters.AddWithValue("@limit", NormalizeLimit(limit));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
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
        IF OBJECT_ID(N'dbo.Devices', N'U') IS NULL
        CREATE TABLE dbo.Devices (
            DeviceId bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_Devices PRIMARY KEY,
            IpAddress nvarchar(45) NOT NULL,
            MacAddress nvarchar(32) NULL,
            Hostname nvarchar(255) NULL,
            Vendor nvarchar(255) NULL,
            DeviceTypeGuess nvarchar(128) NULL,
            TrustStatus nvarchar(64) NOT NULL,
            RiskStatus nvarchar(64) NOT NULL,
            FirstSeenUtc datetimeoffset NOT NULL,
            LastSeenUtc datetimeoffset NOT NULL,
            LastConfirmedUtc datetimeoffset NULL,
            Notes nvarchar(max) NULL
        );
        """,
        """
        IF OBJECT_ID(N'dbo.Applications', N'U') IS NULL
        CREATE TABLE dbo.Applications (
            ApplicationId bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_Applications PRIMARY KEY,
            DisplayName nvarchar(255) NOT NULL,
            ProcessName nvarchar(255) NOT NULL,
            FilePath nvarchar(1024) NULL,
            Publisher nvarchar(255) NULL,
            ProductName nvarchar(255) NULL,
            FileDescription nvarchar(512) NULL,
            SignatureStatus nvarchar(64) NOT NULL,
            HashSha256 nvarchar(64) NULL,
            InstallFolder nvarchar(1024) NULL,
            ParentProcessName nvarchar(255) NULL,
            FirstSeenUtc datetimeoffset NOT NULL,
            LastSeenUtc datetimeoffset NOT NULL,
            TrustStatus nvarchar(64) NOT NULL,
            Notes nvarchar(max) NULL
        );
        """,
        """
        IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_Applications_Identity' AND object_id = OBJECT_ID(N'dbo.Applications'))
        CREATE UNIQUE INDEX IX_Applications_Identity ON dbo.Applications (ProcessName, FilePath, HashSha256);
        """,
        """
        IF OBJECT_ID(N'dbo.Ports', N'U') IS NULL
        CREATE TABLE dbo.Ports (
            PortId bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_Ports PRIMARY KEY,
            PortNumber int NOT NULL,
            Protocol nvarchar(16) NOT NULL,
            LocalAddress nvarchar(45) NOT NULL,
            Reachability nvarchar(64) NOT NULL,
            OwningProcessId int NULL,
            ApplicationId bigint NULL,
            FirstSeenUtc datetimeoffset NOT NULL,
            LastSeenUtc datetimeoffset NOT NULL,
            TrustStatus nvarchar(64) NOT NULL,
            RiskStatus nvarchar(64) NOT NULL,
            CONSTRAINT FK_Ports_Applications FOREIGN KEY (ApplicationId) REFERENCES dbo.Applications(ApplicationId)
        );
        """,
        """
        IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_Ports_Identity' AND object_id = OBJECT_ID(N'dbo.Ports'))
        CREATE UNIQUE INDEX IX_Ports_Identity ON dbo.Ports (PortNumber, Protocol, LocalAddress);
        """,
        """
        IF OBJECT_ID(N'dbo.NetworkEvents', N'U') IS NULL
        CREATE TABLE dbo.NetworkEvents (
            EventId bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_NetworkEvents PRIMARY KEY,
            EventType nvarchar(128) NOT NULL,
            SourceIp nvarchar(45) NULL,
            SourceDeviceId bigint NULL,
            DestinationIp nvarchar(45) NULL,
            DestinationPort int NULL,
            Protocol nvarchar(16) NOT NULL,
            Direction nvarchar(64) NOT NULL,
            ApplicationId bigint NULL,
            RiskLevel nvarchar(64) NOT NULL,
            Summary nvarchar(1024) NOT NULL,
            DetailsJson nvarchar(max) NOT NULL,
            WasUserNotified bit NOT NULL,
            CreatedUtc datetimeoffset NOT NULL,
            CONSTRAINT FK_NetworkEvents_Devices FOREIGN KEY (SourceDeviceId) REFERENCES dbo.Devices(DeviceId),
            CONSTRAINT FK_NetworkEvents_Applications FOREIGN KEY (ApplicationId) REFERENCES dbo.Applications(ApplicationId)
        );
        """,
        """
        IF OBJECT_ID(N'dbo.Incidents', N'U') IS NULL
        CREATE TABLE dbo.Incidents (
            IncidentId bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_Incidents PRIMARY KEY,
            Title nvarchar(255) NOT NULL,
            Summary nvarchar(max) NOT NULL,
            MainDeviceId bigint NULL,
            MainApplicationId bigint NULL,
            RiskLevel nvarchar(64) NOT NULL,
            Status nvarchar(64) NOT NULL,
            EventCount int NOT NULL,
            StartedUtc datetimeoffset NOT NULL,
            LastUpdatedUtc datetimeoffset NOT NULL,
            ResolvedUtc datetimeoffset NULL,
            UserNotes nvarchar(max) NULL
        );
        """,
        """
        IF OBJECT_ID(N'dbo.Rules', N'U') IS NULL
        CREATE TABLE dbo.Rules (
            RuleId bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_Rules PRIMARY KEY,
            Name nvarchar(255) NOT NULL,
            Description nvarchar(max) NOT NULL,
            ConditionJson nvarchar(max) NOT NULL,
            RiskLevel nvarchar(64) NOT NULL,
            Action nvarchar(64) NOT NULL,
            Enabled bit NOT NULL,
            CreatedUtc datetimeoffset NOT NULL,
            UpdatedUtc datetimeoffset NOT NULL
        );
        """,
        """
        IF OBJECT_ID(N'dbo.TrustDecisions', N'U') IS NULL
        CREATE TABLE dbo.TrustDecisions (
            TrustDecisionId bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_TrustDecisions PRIMARY KEY,
            TargetType nvarchar(64) NOT NULL,
            TargetId bigint NOT NULL,
            Decision nvarchar(64) NOT NULL,
            ExpiresUtc datetimeoffset NULL,
            Reason nvarchar(1024) NOT NULL,
            CreatedUtc datetimeoffset NOT NULL
        );
        """
    ];

    private async Task EnsureDatabaseExistsAsync(CancellationToken cancellationToken)
    {
        var builder = new SqlConnectionStringBuilder(options.ToConnectionString());
        var databaseName = builder.InitialCatalog;
        if (string.IsNullOrWhiteSpace(databaseName))
        {
            return;
        }

        builder.InitialCatalog = "master";
        await using var connection = new SqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = $"""
            IF DB_ID(@databaseName) IS NULL
            BEGIN
                EXEC(N'CREATE DATABASE {QuoteSqlIdentifier(databaseName)}');
            END;
            """;
        command.Parameters.AddWithValue("@databaseName", databaseName);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task<SqlConnection> OpenConnectionAsync(CancellationToken cancellationToken)
    {
        var connection = new SqlConnection(options.ToConnectionString());
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    private static async Task<long?> FindApplicationIdAsync(SqlConnection connection, ApplicationIdentity application, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT TOP (1) ApplicationId
            FROM dbo.Applications
            WHERE ProcessName = @processName
              AND ISNULL(FilePath, '') = ISNULL(@filePath, '')
              AND ISNULL(HashSha256, '') = ISNULL(@hashSha256, '')
            ORDER BY ApplicationId;
            """;
        command.Parameters.AddWithValue("@processName", application.ProcessName);
        command.Parameters.AddWithValue("@filePath", DbValue(application.FilePath));
        command.Parameters.AddWithValue("@hashSha256", DbValue(application.HashSha256));
        return ToNullableInt64(await command.ExecuteScalarAsync(cancellationToken));
    }

    private static async Task<long?> FindPortIdAsync(SqlConnection connection, ListeningPort port, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT TOP (1) PortId
            FROM dbo.Ports
            WHERE PortNumber = @portNumber AND Protocol = @protocol AND LocalAddress = @localAddress
            ORDER BY PortId;
            """;
        command.Parameters.AddWithValue("@portNumber", port.PortNumber);
        command.Parameters.AddWithValue("@protocol", port.Protocol);
        command.Parameters.AddWithValue("@localAddress", port.LocalAddress);
        return ToNullableInt64(await command.ExecuteScalarAsync(cancellationToken));
    }

    private static void AddApplicationParameters(SqlCommand command, ApplicationIdentity application, DateTimeOffset now)
    {
        command.Parameters.AddWithValue("@displayName", application.DisplayName);
        command.Parameters.AddWithValue("@processName", application.ProcessName);
        command.Parameters.AddWithValue("@filePath", DbValue(application.FilePath));
        command.Parameters.AddWithValue("@publisher", DbValue(application.Publisher));
        command.Parameters.AddWithValue("@productName", DbValue(application.ProductName));
        command.Parameters.AddWithValue("@fileDescription", DbValue(application.FileDescription));
        command.Parameters.AddWithValue("@signatureStatus", application.SignatureStatus.ToString());
        command.Parameters.AddWithValue("@hashSha256", DbValue(application.HashSha256));
        command.Parameters.AddWithValue("@installFolder", DbValue(application.InstallFolder));
        command.Parameters.AddWithValue("@parentProcessName", DbValue(application.ParentProcessName));
        command.Parameters.AddWithValue("@lastSeenUtc", ToDatabaseTime(application.LastSeenUtc, now));
    }

    private static void AddPortParameters(SqlCommand command, ListeningPort port, long? applicationId, DateTimeOffset now)
    {
        command.Parameters.AddWithValue("@portNumber", port.PortNumber);
        command.Parameters.AddWithValue("@protocol", port.Protocol);
        command.Parameters.AddWithValue("@localAddress", port.LocalAddress);
        command.Parameters.AddWithValue("@reachability", port.Reachability.ToString());
        command.Parameters.AddWithValue("@owningProcessId", DbValue(port.OwningProcessId));
        command.Parameters.AddWithValue("@applicationId", DbValue(applicationId));
        command.Parameters.AddWithValue("@lastSeenUtc", ToDatabaseTime(port.LastSeenUtc, now));
        command.Parameters.AddWithValue("@trustStatus", port.TrustStatus.ToString());
        command.Parameters.AddWithValue("@riskStatus", port.RiskStatus.ToString());
    }

    private static object DbValue<T>(T? value)
    {
        return value is null ? DBNull.Value : value;
    }

    private static DateTimeOffset ToDatabaseTime(DateTimeOffset value, DateTimeOffset fallback)
    {
        return value == default ? fallback : value;
    }

    private static long? ToNullableInt64(object? value)
    {
        return value is null || value == DBNull.Value ? null : Convert.ToInt64(value);
    }

    private static int NormalizeLimit(int limit)
    {
        return Math.Clamp(limit, 1, 500);
    }

    private static ApplicationIdentity ReadApplication(SqlDataReader reader)
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
            FirstSeenUtc = reader.GetFieldValue<DateTimeOffset>(11),
            LastSeenUtc = reader.GetFieldValue<DateTimeOffset>(12),
            TrustStatus = Enum.Parse<TrustStatus>(reader.GetString(13)),
            Notes = ReadNullableString(reader, 14)
        };
    }

    private static ListeningPort ReadPort(SqlDataReader reader)
    {
        return new ListeningPort
        {
            PortId = reader.GetInt64(0),
            PortNumber = reader.GetInt32(1),
            Protocol = reader.GetString(2),
            LocalAddress = reader.GetString(3),
            Reachability = Enum.Parse<PortReachability>(reader.GetString(4)),
            OwningProcessId = ReadNullableInt32(reader, 5),
            FirstSeenUtc = reader.GetFieldValue<DateTimeOffset>(7),
            LastSeenUtc = reader.GetFieldValue<DateTimeOffset>(8),
            TrustStatus = Enum.Parse<TrustStatus>(reader.GetString(9)),
            RiskStatus = Enum.Parse<RiskStatus>(reader.GetString(10))
        };
    }

    private static NetworkEvent ReadNetworkEvent(SqlDataReader reader)
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
            WasUserNotified = reader.GetBoolean(12),
            CreatedUtc = reader.GetFieldValue<DateTimeOffset>(13)
        };
    }

    private static string? ReadNullableString(SqlDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
    }

    private static int? ReadNullableInt32(SqlDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? null : reader.GetInt32(ordinal);
    }

    private static long? ReadNullableInt64(SqlDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? null : reader.GetInt64(ordinal);
    }

    private static string QuoteSqlIdentifier(string identifier)
    {
        return $"[{identifier.Replace("]", "]]", StringComparison.Ordinal)}]";
    }
}
