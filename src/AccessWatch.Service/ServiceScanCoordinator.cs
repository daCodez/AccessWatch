using System.Text.Json;
using AccessWatch.Core;
using AccessWatch.Notifications;

namespace AccessWatch.Service;

/// <summary>
/// Coordinates the MVP AccessWatch service scan pipeline.
/// </summary>
public sealed class ServiceScanCoordinator
{
    private readonly IAccessWatchRepository repository;
    private readonly IListeningPortScanner portScanner;
    private readonly INetworkDeviceDiscoveryService deviceDiscoveryService;
    private readonly IRiskScoringService riskScoringService;
    private readonly AccessWatchSettings settings;
    private readonly NotificationMessageFactory notificationFactory;
    private readonly ITrayNotificationService trayNotificationService;
    private readonly ILogger<ServiceScanCoordinator> logger;

    /// <summary>
    /// Initializes a new service scan coordinator.
    /// </summary>
    /// <param name="repository">AccessWatch repository.</param>
    /// <param name="portScanner">Listening port scanner.</param>
    /// <param name="deviceDiscoveryService">Local network device discovery service.</param>
    /// <param name="riskScoringService">Risk scoring service.</param>
    /// <param name="settings">AccessWatch settings.</param>
    /// <param name="notificationFactory">Notification message factory.</param>
    /// <param name="trayNotificationService">User-facing notification delivery service.</param>
    /// <param name="logger">Logger for scan diagnostics.</param>
    public ServiceScanCoordinator(
        IAccessWatchRepository repository,
        IListeningPortScanner portScanner,
        INetworkDeviceDiscoveryService deviceDiscoveryService,
        IRiskScoringService riskScoringService,
        AccessWatchSettings settings,
        NotificationMessageFactory notificationFactory,
        ITrayNotificationService trayNotificationService,
        ILogger<ServiceScanCoordinator> logger)
    {
        this.repository = repository;
        this.portScanner = portScanner;
        this.deviceDiscoveryService = deviceDiscoveryService;
        this.riskScoringService = riskScoringService;
        this.settings = settings;
        this.notificationFactory = notificationFactory;
        this.trayNotificationService = trayNotificationService;
        this.logger = logger;
    }

    /// <summary>
    /// Initializes required storage before scanning begins.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task InitializeAsync(CancellationToken cancellationToken)
    {
        return repository.InitializeAsync(cancellationToken);
    }

    /// <summary>
    /// Runs one listening-port scan and stores newly detected port events.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The number of newly created events.</returns>
    public async Task<int> RunListeningPortScanAsync(CancellationToken cancellationToken)
    {
        var devices = await deviceDiscoveryService.DiscoverAsync(cancellationToken);
        foreach (var device in devices)
        {
            await repository.UpsertDeviceAsync(device, cancellationToken);
        }

        logger.LogInformation(
            "AccessWatch device discovery completed. Observed {DeviceCount} network devices.",
            devices.Count);

        var ports = await portScanner.ScanAsync(cancellationToken);
        var createdEvents = 0;

        foreach (var scannedPort in ports)
        {
            long? applicationId = null;
            var portForScoring = scannedPort;
            if (scannedPort.Application is not null)
            {
                applicationId = await repository.UpsertApplicationAsync(scannedPort.Application, cancellationToken);
                var trustStatus = await repository.GetActiveTrustDecisionAsync("Application", applicationId.Value, cancellationToken);
                if (trustStatus is not null)
                {
                    portForScoring = scannedPort with
                    {
                        Application = scannedPort.Application with { ApplicationId = applicationId.Value, TrustStatus = trustStatus.Value },
                        TrustStatus = trustStatus.Value
                    };
                }
            }

            var assessment = riskScoringService.ScoreNewListeningPort(portForScoring, settings);
            var port = portForScoring with { RiskStatus = assessment.RiskStatus };
            var previousApplicationId = await repository.GetListeningPortApplicationIdAsync(port, cancellationToken);
            var isNewPort = await repository.UpsertPortAsync(port, applicationId, cancellationToken);
            var applicationChanged = !isNewPort && previousApplicationId != applicationId;
            if (!isNewPort && !applicationChanged)
            {
                continue;
            }

            var notification = notificationFactory.Create(assessment);
            var eventType = isNewPort ? "NewListeningPort" : "ListeningPortApplicationChanged";
            var networkEvent = CreateListeningPortEvent(port, applicationId, assessment, eventType, notification.Action != NotificationAction.SilentLog);
            await repository.AddNetworkEventAsync(networkEvent, cancellationToken);
            if (notification.Action != NotificationAction.SilentLog)
            {
                await trayNotificationService.ShowAsync(notification, cancellationToken);
            }

            createdEvents++;

            logger.LogInformation(
                "Listening port event detected: {Summary} EventType={EventType} Action={Action} Risk={RiskLevel}",
                notification.Body,
                eventType,
                notification.Action,
                notification.RiskLevel);
        }

        return createdEvents;
    }

    private static NetworkEvent CreateListeningPortEvent(
        ListeningPort port,
        long? applicationId,
        PortRiskAssessment assessment,
        string eventType,
        bool wasUserNotified)
    {
        var details = new
        {
            whatHappened = eventType == "NewListeningPort"
                ? "A new listening TCP port appeared."
                : "A known listening TCP port is now owned by a different application.",
            app = port.Application?.DisplayName ?? "Unknown application",
            processName = port.Application?.ProcessName,
            port.PortNumber,
            port.LocalAddress,
            reachability = port.Reachability.ToString(),
            whyItMatters = assessment.WhyItMatters,
            suggestedAction = assessment.SuggestedAction
        };

        return new NetworkEvent
        {
            EventType = eventType,
            DestinationIp = port.LocalAddress,
            DestinationPort = port.PortNumber,
            Protocol = port.Protocol,
            Direction = "Inbound",
            ApplicationId = applicationId,
            RiskLevel = assessment.RiskLevel,
            Summary = assessment.Summary,
            DetailsJson = JsonSerializer.Serialize(details),
            WasUserNotified = wasUserNotified,
            CreatedUtc = DateTimeOffset.UtcNow
        };
    }
}