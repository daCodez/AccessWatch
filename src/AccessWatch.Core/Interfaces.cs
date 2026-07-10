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
/// Scans operating system privacy telemetry for active camera and microphone usage.
/// </summary>
public interface ISensorAccessScanner
{
    /// <summary>
    /// Gets the sensitive sensor access sessions currently visible to AccessWatch.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for the scan.</param>
    /// <returns>The active camera and microphone access sessions.</returns>
    Task<IReadOnlyList<SensorAccessObservation>> ScanAsync(CancellationToken cancellationToken);
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
    /// Saves or updates a batch of local-network device observations.
    /// </summary>
    /// <param name="devices">The devices to save.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>Stored device results in input order.</returns>
    async Task<IReadOnlyList<DevicePersistenceResult>> UpsertDevicesAsync(IReadOnlyList<NetworkDevice> devices, CancellationToken cancellationToken)
    {
        var results = new List<DevicePersistenceResult>(devices.Count);
        foreach (var device in devices)
        {
            var deviceId = await UpsertDeviceAsync(device, cancellationToken).ConfigureAwait(false);
            var trustStatus = await GetActiveTrustDecisionAsync("Device", deviceId, cancellationToken).ConfigureAwait(false);
            if (trustStatus is not null)
            {
                var trustedDevice = device with { DeviceId = deviceId, TrustStatus = trustStatus.Value, RiskStatus = RiskStatusForDeviceTrust(trustStatus.Value) };
                await UpsertDeviceAsync(trustedDevice, cancellationToken).ConfigureAwait(false);
            }

            results.Add(new DevicePersistenceResult(device, deviceId, trustStatus));
        }

        return results;
    }
    private static RiskStatus RiskStatusForDeviceTrust(TrustStatus trustStatus)
    {
        return trustStatus switch
        {
            TrustStatus.KnownWatched or TrustStatus.Guest => RiskStatus.Watched,
            TrustStatus.Blocked => RiskStatus.Critical,
            _ => RiskStatus.Normal
        };
    }
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
    /// Saves or updates a batch of application observations.
    /// </summary>
    /// <param name="applications">The applications to save.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>Stored application results in input order.</returns>
    async Task<IReadOnlyList<ApplicationPersistenceResult>> UpsertApplicationsAsync(IReadOnlyList<ApplicationIdentity> applications, CancellationToken cancellationToken)
    {
        var results = new List<ApplicationPersistenceResult>(applications.Count);
        foreach (var application in applications)
        {
            var applicationId = await UpsertApplicationAsync(application, cancellationToken).ConfigureAwait(false);
            var trustStatus = await GetActiveTrustDecisionAsync("Application", applicationId, cancellationToken).ConfigureAwait(false);
            results.Add(new ApplicationPersistenceResult(application, applicationId, trustStatus));
        }

        return results;
    }
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
    /// Saves or updates a batch of listening ports.
    /// </summary>
    /// <param name="ports">The scored listening ports to save.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>Stored port results in input order.</returns>
    async Task<IReadOnlyList<PortPersistenceResult>> UpsertPortsAsync(IReadOnlyList<PortPersistenceRequest> ports, CancellationToken cancellationToken)
    {
        var results = new List<PortPersistenceResult>(ports.Count);
        foreach (var request in ports)
        {
            var previousApplicationId = await GetListeningPortApplicationIdAsync(request.Port, cancellationToken).ConfigureAwait(false);
            var isNewPort = await UpsertPortAsync(request.Port, request.ApplicationId, cancellationToken).ConfigureAwait(false);
            results.Add(new PortPersistenceResult(request.Port, request.ApplicationId, previousApplicationId, isNewPort));
        }

        return results;
    }
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
    /// Saves or updates an AccessWatch rule.
    /// </summary>
    /// <param name="rule">The rule to save.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>The database rule identifier.</returns>
    Task<long> UpsertRuleAsync(AccessWatchRule rule, CancellationToken cancellationToken);

    /// <summary>
    /// Lists stored AccessWatch rules.
    /// </summary>
    /// <param name="includeDisabled">Whether disabled rule suggestions should be included.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>Rules ordered for dashboard and future rule management surfaces.</returns>
    Task<IReadOnlyList<AccessWatchRule>> ListRulesAsync(bool includeDisabled, CancellationToken cancellationToken);

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

    /// <summary>
    /// Creates a safe JSON incident summary for manual ChatGPT review.
    /// </summary>
    /// <param name="incident">The grouped incident to summarize.</param>
    /// <returns>Redacted JSON suitable for manual copy.</returns>
    string CreateRedactedIncidentSummary(Incident incident);
}

/// <summary>
/// Sends redacted investigation requests to an approved AI bridge.
/// </summary>
public interface IAiInvestigationBridge
{
    /// <summary>
    /// Reviews an incident through the configured bridge.
    /// </summary>
    /// <param name="request">Redacted investigation request.</param>
    /// <param name="settings">Current AccessWatch AI settings.</param>
    /// <param name="cancellationToken">Cancellation token for the review.</param>
    /// <returns>The bridge review result or an unavailable result.</returns>
    Task<AiInvestigationResult> ReviewIncidentAsync(
        AiInvestigationRequest request,
        AccessWatchSettings settings,
        CancellationToken cancellationToken);
}
