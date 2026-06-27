namespace AccessWatch.Data;

/// <summary>
/// Configures the AccessWatch SQLite database location.
/// </summary>
public sealed class AccessWatchDatabaseOptions
{
    /// <summary>Default database path under ProgramData.</summary>
    public static readonly string DefaultDatabasePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "AccessWatch",
        "AccessWatch.db");

    /// <summary>SQLite database file path.</summary>
    public string DatabasePath { get; init; } = DefaultDatabasePath;

    /// <summary>
    /// Builds a SQLite connection string for the configured database path.
    /// </summary>
    /// <returns>A SQLite connection string.</returns>
    public string ToConnectionString()
    {
        return $"Data Source={DatabasePath}";
    }
}
