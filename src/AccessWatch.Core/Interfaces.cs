namespace AccessWatch.Core;

/// <summary>
/// Scans the local host for listening ports.
/// </summary>
public interface IListeningPortScanner
{
    /// <summary>
    /// Gets the current listening TCP ports.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for the scan.</param>
    /// <returns>The listening ports currently visible to AccessWatch.</returns>
    Task<IReadOnlyList<ListeningPort>> ScanAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Resolves process and file metadata for an application.
/// </summary>
public interface IAppIdentityResolver
{
    /// <summary>
    /// Resolves application identity for a process identifier.
    /// </summary>
    /// <param name="processId">The process identifier to resolve.</param>
    /// <returns>The application identity, or a safe unknown identity when metadata is unavailable.</returns>
    ApplicationIdentity Resolve(int processId);
}

/// <summary>
/// Stores AccessWatch observations and events.
/// </summary>
public interface IAccessWatchRepository
{
    /// <summary>
    /// Initializes the AccessWatch database schema.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for initialization.</param>
    Task InitializeAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Saves or updates an application identity.
    /// </summary>
    /// <param name="application">The application to save.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The database application identifier.</returns>
    Task<long> UpsertApplicationAsync(ApplicationIdentity application, CancellationToken cancellationToken);

    /// <summary>
    /// Saves or updates a listening port.
    /// </summary>
    /// <param name="port">The listening port to save.</param>
    /// <param name="applicationId">The resolved application identifier, if known.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>True when the port was not previously known.</returns>
    Task<bool> UpsertPortAsync(ListeningPort port, long? applicationId, CancellationToken cancellationToken);

    /// <summary>
    /// Saves a network event.
    /// </summary>
    /// <param name="networkEvent">The event to save.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    Task AddNetworkEventAsync(NetworkEvent networkEvent, CancellationToken cancellationToken);
}

/// <summary>
/// Scores AccessWatch observations.
/// </summary>
public interface IRiskScoringService
{
    /// <summary>
    /// Scores a newly observed listening port.
    /// </summary>
    /// <param name="port">The observed port.</param>
    /// <param name="settings">Current AccessWatch settings.</param>
    /// <returns>The risk assessment.</returns>
    PortRiskAssessment ScoreNewListeningPort(ListeningPort port, AccessWatchSettings settings);
}

/// <summary>
/// Produces redacted AI handoff payloads.
/// </summary>
public interface IAiHandoffService
{
    /// <summary>
    /// Creates a safe JSON incident summary for manual ChatGPT review.
    /// </summary>
    /// <param name="networkEvent">The network event to summarize.</param>
    /// <param name="eventCount">The grouped event count.</param>
    /// <param name="timeWindow">The grouped event time window.</param>
    /// <returns>Redacted JSON suitable for manual copy.</returns>
    string CreateRedactedIncidentSummary(NetworkEvent networkEvent, int eventCount, TimeSpan timeWindow);
}
