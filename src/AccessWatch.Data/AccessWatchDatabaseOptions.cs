namespace AccessWatch.Data;

/// <summary>
/// Configures the AccessWatch database provider and local connection details.
/// </summary>
public sealed class AccessWatchDatabaseOptions
{
    /// <summary>Default SQL Server LocalDB connection string for development and first-run local use.</summary>
    public const string DefaultSqlServerConnectionString = "Server=(localdb)\\MSSQLLocalDB;Database=AccessWatch;Trusted_Connection=True;TrustServerCertificate=True;";

    /// <summary>Configuration section used by the service host.</summary>
    public const string ConfigurationSectionName = "AccessWatch:Database";

    /// <summary>Selected database provider.</summary>
    public DatabaseProvider Provider { get; init; } = DatabaseProvider.SqlServer;

    /// <summary>SQL Server connection string for LocalDB or SQL Server Express.</summary>
    public string SqlServerConnectionString { get; init; } = DefaultSqlServerConnectionString;

    /// <summary>
    /// Builds the active provider connection string.
    /// </summary>
    /// <returns>The connection string for the selected provider.</returns>
    /// <exception cref="NotSupportedException">Thrown when the selected provider is not implemented.</exception>
    public string ToConnectionString()
    {
        return Provider switch
        {
            DatabaseProvider.SqlServer => SqlServerConnectionString,
            _ => throw new NotSupportedException($"Database provider '{Provider}' is not supported.")
        };
    }
}


