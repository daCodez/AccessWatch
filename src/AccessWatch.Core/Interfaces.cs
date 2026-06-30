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
/// Discovers devices visible on the local network without packet sniffing.
/// </summary>
public interface INetworkDeviceDiscoveryService
{
    /// <summary>
    /// Gets devices visible from the current local network snapshot.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for the scan.</param>
    /// <returns>The devices currently visible to AccessWatch.</returns>
    Task<IReadOnlyList<NetworkDevice>> DiscoverAsync(CancellationToken cancellationToken);
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
    /// Saves or updates a local-network device observation.
    /// </summary>
    /// <param name="device">The device to save.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The database device identifier.</returns>
    Task<long> UpsertDeviceAsync(NetworkDevice device, CancellationToken cancellationToken);

    /// <summary>
    /// Lists recent local-network devices for future UI surfaces.
    /// </summary>
    /// <param name="limit">Maximum number of rows to return.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>Recent devices ordered newest first.</returns>
    Task<IReadOnlyList<NetworkDevice>> ListRecentDevicesAsync(int limit, CancellationToken cancellationToken);

    /// <summary>
    /// Updates the friendly alias for a known device.
    /// </summary>
    /// <param name="deviceId">Device row identifier.</param>
    /// <param name="userAlias">Friendly alias, or null to clear it.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    Task UpdateDeviceAliasAsync(long deviceId, string? userAlias, CancellationToken cancellationToken);

    /// <summary>
    /// Saves or updates an application identity.
    /// </summary>
    /// <param name="application">The application to save.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The database application identifier.</returns>
    Task<long> UpsertApplicationAsync(ApplicationIdentity application, CancellationToken cancellationToken);


    /// <summary>
    /// Gets the application currently associated with a known listening port.
    /// </summary>
    /// <param name="port">The listening port identity to look up.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The associated application identifier, or null when the port is unknown or has no application.</returns>
    Task<long?> GetListeningPortApplicationIdAsync(ListeningPort port, CancellationToken cancellationToken);
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

    /// <summary>
    /// Saves a trust decision.
    /// </summary>
    /// <param name="trustDecision">The trust decision to save.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The database trust decision identifier.</returns>
    Task<long> AddTrustDecisionAsync(TrustDecision trustDecision, CancellationToken cancellationToken);

    /// <summary>
    /// Gets the effective trust status for a target.
    /// </summary>
    /// <param name="targetType">Target kind, such as Application, Port, or Device.</param>
    /// <param name="targetId">Target row identifier.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The effective trust status, or null when no active decision exists.</returns>
    Task<TrustStatus?> GetActiveTrustDecisionAsync(string targetType, long targetId, CancellationToken cancellationToken);

    /// <summary>
    /// Saves or updates an incident.
    /// </summary>
    /// <param name="incident">The incident to save.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The database incident identifier.</returns>
    Task<long> UpsertIncidentAsync(Incident incident, CancellationToken cancellationToken);

    /// <summary>
    /// Lists recent incidents for dashboard and future UI surfaces.
    /// </summary>
    /// <param name="limit">Maximum number of rows to return.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>Recent incidents ordered newest first.</returns>
    Task<IReadOnlyList<Incident>> ListRecentIncidentsAsync(int limit, CancellationToken cancellationToken);

    /// <summary>
    /// Lists recent applications for future UI surfaces.
    /// </summary>
    /// <param name="limit">Maximum number of rows to return.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>Recent applications ordered newest first.</returns>
    Task<IReadOnlyList<ApplicationIdentity>> ListRecentApplicationsAsync(int limit, CancellationToken cancellationToken);

    /// <summary>
    /// Lists recent listening ports for future UI surfaces.
    /// </summary>
    /// <param name="limit">Maximum number of rows to return.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>Recent ports ordered newest first.</returns>
    Task<IReadOnlyList<ListeningPort>> ListRecentPortsAsync(int limit, CancellationToken cancellationToken);

    /// <summary>
    /// Lists recent network events for future UI surfaces.
    /// </summary>
    /// <param name="limit">Maximum number of rows to return.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>Recent events ordered newest first.</returns>
    Task<IReadOnlyList<NetworkEvent>> ListRecentNetworkEventsAsync(int limit, CancellationToken cancellationToken);
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

