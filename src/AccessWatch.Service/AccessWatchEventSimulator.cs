using System.Text.Json;
using AccessWatch.Core;
using AccessWatch.Notifications;

namespace AccessWatch.Service;

/// <summary>
/// Creates demo AccessWatch observations so the dashboard can be exercised without waiting for real network changes.
/// </summary>
public sealed class AccessWatchEventSimulator
{
    private readonly IAccessWatchRepository repository;
    private readonly NotificationMessageFactory notificationFactory;
    private readonly ITrayNotificationService trayNotificationService;
    private readonly Func<DateTimeOffset, CancellationToken, Task<int>>[] scenarios;
    private int nextScenarioIndex = -1;

    /// <summary>
    /// Initializes a new simulator that persists and notifies through the normal AccessWatch paths.
    /// </summary>
    /// <param name="repository">Repository used to save simulated observations.</param>
    /// <param name="notificationFactory">Factory used to build the user-facing notification.</param>
    /// <param name="trayNotificationService">Tray notification sink.</param>
    public AccessWatchEventSimulator(
        IAccessWatchRepository repository,
        NotificationMessageFactory notificationFactory,
        ITrayNotificationService trayNotificationService)
    {
        this.repository = repository;
        this.notificationFactory = notificationFactory;
        this.trayNotificationService = trayNotificationService;
        scenarios =
        [
            TriggerNetworkExposureAsync,
            TriggerCameraActivationAsync,
            TriggerMicrophoneActivationAsync,
            TriggerNewDeviceAsync
        ];
    }

    /// <summary>
    /// Creates one simulated event from a rotating set of realistic AccessWatch scenarios.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The number of events created.</returns>
    public async Task<int> TriggerDemoEventAsync(CancellationToken cancellationToken)
    {
        await repository.InitializeAsync(cancellationToken);

        var scenarioIndex = Interlocked.Increment(ref nextScenarioIndex) % scenarios.Length;
        return await scenarios[scenarioIndex](DateTimeOffset.UtcNow, cancellationToken);
    }

    private async Task<int> TriggerNetworkExposureAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        var deviceId = await repository.UpsertDeviceAsync(CreateNetworkStorageDevice(now), cancellationToken);
        var application = CreateRemoteAdminApplication(now);
        var applicationId = await repository.UpsertApplicationAsync(application, cancellationToken);
        var port = CreatePort(now, application with { ApplicationId = applicationId });
        await repository.UpsertPortAsync(port, applicationId, cancellationToken);

        var assessment = new PortRiskAssessment(
            RiskLevel.High,
            RiskStatus.HighRisk,
            NotificationAction.AskBeforeAllow,
            "Simulated Remote Admin opened a network-reachable port.",
            "This simulated service is reachable from other devices, just like a real exposed listener would be.",
            "Use this event to verify dashboard review, toast, and inventory workflows.");
        await AddEventAndNotifyAsync(
            assessment,
            new NetworkEvent
            {
                EventType = "NewListeningPort",
                SourceIp = "192.168.1.240",
                SourceDeviceId = deviceId,
                DestinationIp = port.LocalAddress,
                DestinationPort = port.PortNumber,
                Protocol = port.Protocol,
                Direction = "Inbound",
                ApplicationId = applicationId,
                RiskLevel = assessment.RiskLevel,
                Summary = assessment.Summary,
                DetailsJson = BuildDetailsJson(
                    "A simulated listening TCP port appeared.",
                    application.DisplayName,
                    application.ProcessName,
                    "simulated-nas",
                    PortReachability.NetworkReachable.ToString(),
                    assessment.WhyItMatters,
                    assessment.SuggestedAction),
                WasUserNotified = true,
                CreatedUtc = now
            },
            cancellationToken);

        return 1;
    }

    private async Task<int> TriggerCameraActivationAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        var deviceId = await repository.UpsertDeviceAsync(CreateOfficeLaptopDevice(now), cancellationToken);
        var application = CreateVisualStudioApplication(now);
        var applicationId = await repository.UpsertApplicationAsync(application, cancellationToken);
        var assessment = new PortRiskAssessment(
            RiskLevel.High,
            RiskStatus.Suspicious,
            NotificationAction.AskBeforeAllow,
            "Visual Studio started using the camera.",
            "Camera activation is sensitive because it can capture the room around this device.",
            "Confirm you expected Visual Studio to use the camera right now.");
        await AddEventAndNotifyAsync(
            assessment,
            new NetworkEvent
            {
                EventType = "CameraActivated",
                SourceIp = "192.168.1.25",
                SourceDeviceId = deviceId,
                Protocol = "Local",
                Direction = "SensorAccess",
                ApplicationId = applicationId,
                RiskLevel = assessment.RiskLevel,
                Summary = assessment.Summary,
                DetailsJson = BuildDetailsJson(
                    "Visual Studio activated the camera.",
                    application.DisplayName,
                    application.ProcessName,
                    "office-laptop",
                    "Local sensor access",
                    assessment.WhyItMatters,
                    assessment.SuggestedAction,
                    "Camera"),
                WasUserNotified = true,
                CreatedUtc = now
            },
            cancellationToken);

        return 1;
    }

    private async Task<int> TriggerMicrophoneActivationAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        var deviceId = await repository.UpsertDeviceAsync(CreateOfficeLaptopDevice(now), cancellationToken);
        var application = CreateSkypeApplication(now);
        var applicationId = await repository.UpsertApplicationAsync(application, cancellationToken);
        var assessment = new PortRiskAssessment(
            RiskLevel.High,
            RiskStatus.Suspicious,
            NotificationAction.AskBeforeAllow,
            "Skype started using the microphone.",
            "Microphone activation is sensitive because it can capture nearby conversations.",
            "Confirm you expected Skype to use the microphone right now.");
        await AddEventAndNotifyAsync(
            assessment,
            new NetworkEvent
            {
                EventType = "MicrophoneActivated",
                SourceIp = "192.168.1.25",
                SourceDeviceId = deviceId,
                Protocol = "Local",
                Direction = "SensorAccess",
                ApplicationId = applicationId,
                RiskLevel = assessment.RiskLevel,
                Summary = assessment.Summary,
                DetailsJson = BuildDetailsJson(
                    "Skype activated the microphone.",
                    application.DisplayName,
                    application.ProcessName,
                    "office-laptop",
                    "Local sensor access",
                    assessment.WhyItMatters,
                    assessment.SuggestedAction,
                    "Microphone"),
                WasUserNotified = true,
                CreatedUtc = now
            },
            cancellationToken);

        return 1;
    }

    private async Task<int> TriggerNewDeviceAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        var deviceId = await repository.UpsertDeviceAsync(CreateKitchenTabletDevice(now), cancellationToken);
        var assessment = new PortRiskAssessment(
            RiskLevel.Medium,
            RiskStatus.Watched,
            NotificationAction.SoftNotify,
            "Kitchen tablet joined the network.",
            "A new device on the network may be expected, but it should be visible before it is trusted.",
            "Review the device inventory and mark it trusted if you recognize it.");
        await AddEventAndNotifyAsync(
            assessment,
            new NetworkEvent
            {
                EventType = "NewDeviceObserved",
                SourceIp = "192.168.1.88",
                SourceDeviceId = deviceId,
                Protocol = "ARP",
                Direction = "NetworkObservation",
                RiskLevel = assessment.RiskLevel,
                Summary = assessment.Summary,
                DetailsJson = BuildDetailsJson(
                    "Kitchen tablet joined the local network.",
                    "Network device",
                    "device-presence",
                    "kitchen-tablet",
                    "Local network",
                    assessment.WhyItMatters,
                    assessment.SuggestedAction),
                WasUserNotified = true,
                CreatedUtc = now
            },
            cancellationToken);

        return 1;
    }

    private async Task AddEventAndNotifyAsync(PortRiskAssessment assessment, NetworkEvent networkEvent, CancellationToken cancellationToken)
    {
        await repository.AddNetworkEventAsync(networkEvent, cancellationToken);
        var incident = IncidentFactory.CreateReviewIncident(networkEvent, networkEvent.CreatedUtc);
        if (incident is not null)
        {
            await repository.UpsertIncidentAsync(incident, cancellationToken);
        }

        await trayNotificationService.ShowAsync(notificationFactory.Create(assessment), cancellationToken);
    }

    private static NetworkDevice CreateNetworkStorageDevice(DateTimeOffset now)
    {
        return new NetworkDevice
        {
            IpAddress = "192.168.1.240",
            MacAddress = "02:AC:CE:55:10:01",
            Hostname = "simulated-nas",
            Vendor = "AccessWatch Lab",
            DeviceTypeGuess = "Network storage",
            FirstSeenUtc = now,
            LastSeenUtc = now,
            LastConfirmedUtc = now,
            TrustStatus = TrustStatus.Unknown,
            RiskStatus = RiskStatus.Suspicious,
            Notes = "Simulated device generated by AccessWatch."
        };
    }

    private static NetworkDevice CreateOfficeLaptopDevice(DateTimeOffset now)
    {
        return new NetworkDevice
        {
            IpAddress = "192.168.1.25",
            MacAddress = "02:AC:CE:55:20:25",
            Hostname = "office-laptop",
            Vendor = "AccessWatch Lab",
            DeviceTypeGuess = "Windows workstation",
            FirstSeenUtc = now,
            LastSeenUtc = now,
            LastConfirmedUtc = now,
            TrustStatus = TrustStatus.KnownWatched,
            RiskStatus = RiskStatus.Suspicious,
            Notes = "Simulated endpoint with local sensor activity."
        };
    }

    private static NetworkDevice CreateKitchenTabletDevice(DateTimeOffset now)
    {
        return new NetworkDevice
        {
            IpAddress = "192.168.1.88",
            MacAddress = "02:AC:CE:55:30:88",
            Hostname = "kitchen-tablet",
            Vendor = "AccessWatch Lab",
            DeviceTypeGuess = "Tablet",
            FirstSeenUtc = now,
            LastSeenUtc = now,
            LastConfirmedUtc = now,
            TrustStatus = TrustStatus.Unknown,
            RiskStatus = RiskStatus.Watched,
            Notes = "Simulated newly observed network device."
        };
    }

    private static ApplicationIdentity CreateRemoteAdminApplication(DateTimeOffset now)
    {
        return new ApplicationIdentity
        {
            DisplayName = "Simulated Remote Admin",
            ProcessName = "sim-remote-admin",
            FilePath = @"C:\AccessWatch\SimulatedRemoteAdmin.exe",
            Publisher = "Unknown publisher",
            ProductName = "AccessWatch Simulator",
            FileDescription = "Simulated remote administration service",
            SignatureStatus = SignatureStatus.Unsigned,
            InstallFolder = @"C:\AccessWatch",
            ParentProcessName = "accesswatch",
            FirstSeenUtc = now,
            LastSeenUtc = now,
            TrustStatus = TrustStatus.Unknown,
            Notes = "Simulated application generated by AccessWatch."
        };
    }

    private static ApplicationIdentity CreateVisualStudioApplication(DateTimeOffset now)
    {
        return new ApplicationIdentity
        {
            DisplayName = "Visual Studio",
            ProcessName = "devenv",
            FilePath = @"C:\Program Files\Microsoft Visual Studio\Common7\IDE\devenv.exe",
            Publisher = "Microsoft Corporation",
            ProductName = "Visual Studio",
            FileDescription = "Microsoft Visual Studio",
            SignatureStatus = SignatureStatus.TrustedSigned,
            InstallFolder = @"C:\Program Files\Microsoft Visual Studio\Common7\IDE",
            ParentProcessName = "explorer",
            FirstSeenUtc = now,
            LastSeenUtc = now,
            TrustStatus = TrustStatus.Unknown,
            Notes = "Simulated camera access application."
        };
    }

    private static ApplicationIdentity CreateSkypeApplication(DateTimeOffset now)
    {
        return new ApplicationIdentity
        {
            DisplayName = "Skype",
            ProcessName = "Skype",
            FilePath = @"C:\Program Files\WindowsApps\Microsoft.SkypeApp\Skype.exe",
            Publisher = "Microsoft Corporation",
            ProductName = "Skype",
            FileDescription = "Skype communications client",
            SignatureStatus = SignatureStatus.TrustedSigned,
            InstallFolder = @"C:\Program Files\WindowsApps\Microsoft.SkypeApp",
            ParentProcessName = "explorer",
            FirstSeenUtc = now,
            LastSeenUtc = now,
            TrustStatus = TrustStatus.Unknown,
            Notes = "Simulated microphone access application."
        };
    }

    private static ListeningPort CreatePort(DateTimeOffset now, ApplicationIdentity application)
    {
        return new ListeningPort
        {
            PortNumber = 9443,
            Protocol = "TCP",
            LocalAddress = "0.0.0.0",
            Reachability = PortReachability.NetworkReachable,
            OwningProcessId = 9443,
            Application = application,
            FirstSeenUtc = now,
            LastSeenUtc = now,
            TrustStatus = TrustStatus.Unknown,
            RiskStatus = RiskStatus.HighRisk
        };
    }

    private static string BuildDetailsJson(
        string whatHappened,
        string app,
        string processName,
        string deviceName,
        string reachability,
        string whyItMatters,
        string suggestedAction,
        string? sensor = null)
    {
        var details = new Dictionary<string, object?>
        {
            ["simulated"] = true,
            ["whatHappened"] = whatHappened,
            ["app"] = app,
            ["processName"] = processName,
            ["deviceName"] = deviceName,
            ["reachability"] = reachability,
            ["whyItMatters"] = whyItMatters,
            ["suggestedAction"] = suggestedAction
        };

        if (!string.IsNullOrWhiteSpace(sensor))
        {
            details["sensor"] = sensor;
        }

        return JsonSerializer.Serialize(details);
    }
}

