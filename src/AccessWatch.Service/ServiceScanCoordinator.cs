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
    private readonly IRiskScoringService riskScoringService;
    private readonly AccessWatchSettings settings;
    private readonly NotificationMessageFactory notificationFactory;
    private readonly ILogger<ServiceScanCoordinator> logger;

    /// <summary>
    /// Initializes a new service scan coordinator.
    /// </summary>
    /// <param name="repository">AccessWatch repository.</param>
    /// <param name="portScanner">Listening port scanner.</param>
    /// <param name="riskScoringService">Risk scoring service.</param>
    /// <param name="settings">AccessWatch settings.</param>
    /// <param name="notificationFactory">Notification message factory.</param>
    /// <param name="logger">Logger for scan diagnostics.</param>
    public ServiceScanCoordinator(
        IAccessWatchRepository repository,
        IListeningPortScanner portScanner,
        IRiskScoringService riskScoringService,
        AccessWatchSettings settings,
        NotificationMessageFactory notificationFactory,
        ILogger<ServiceScanCoordinator> logger)
    {
        this.repository = repository;
        this.portScanner = portScanner;
        this.riskScoringService = riskScoringService;
        this.settings = settings;
        this.notificationFactory = notificationFactory;
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
        var ports = await portScanner.ScanAsync(cancellationToken);
        var createdEvents = 0;

        foreach (var scannedPort in ports)
        {
            long? applicationId = null;
            if (scannedPort.Application is not null)
            {
                applicationId = await repository.UpsertApplicationAsync(scannedPort.Application, cancellationToken);
            }

            var assessment = riskScoringService.ScoreNewListeningPort(scannedPort, settings);
            var port = scannedPort with { RiskStatus = assessment.RiskStatus };
            var isNewPort = await repository.UpsertPortAsync(port, applicationId, cancellationToken);
            if (!isNewPort)
            {
                continue;
            }

            var notification = notificationFactory.Create(assessment);
            var networkEvent = CreateNewListeningPortEvent(port, applicationId, assessment, notification.Action != NotificationAction.SilentLog);
            await repository.AddNetworkEventAsync(networkEvent, cancellationToken);
            createdEvents++;

            logger.LogInformation(
                "New listening port detected: {Summary} Action={Action} Risk={RiskLevel}",
                notification.Body,
                notification.Action,
                notification.RiskLevel);
        }

        return createdEvents;
    }

    private static NetworkEvent CreateNewListeningPortEvent(
        ListeningPort port,
        long? applicationId,
        PortRiskAssessment assessment,
        bool wasUserNotified)
    {
        var details = new
        {
            whatHappened = "A new listening TCP port appeared.",
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
            EventType = "NewListeningPort",
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
