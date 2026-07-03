using AccessWatch.Core;
using AccessWatch.Notifications;
using AccessWatch.Rules;
using AccessWatch.Service;
using Microsoft.Extensions.Logging.Abstractions;
using ApplicationIdentity = AccessWatch.Core.ApplicationIdentity;
using AppIdentity = AccessWatch.Core.ApplicationIdentity;

namespace AccessWatch.Tests;

/// <summary>
/// Tests service scan coordination behavior.
/// </summary>
public sealed class ServiceScanCoordinatorTests
{
    /// <summary>
    /// Verifies initialization delegates to the repository.
    /// </summary>
    [Fact]
    public async Task InitializeAsync_InitializesRepository()
    {
        var repository = new FakeRepository();
        var coordinator = CreateCoordinator(repository, new FakeScanner([]));

        await coordinator.InitializeAsync(CancellationToken.None);

        Assert.True(repository.WasInitialized);
    }

    /// <summary>
    /// Verifies each scan saves devices discovered on the local network.
    /// </summary>
    [Fact]
    public async Task RunListeningPortScanAsync_SavesDiscoveredDevices()
    {
        var repository = new FakeRepository();
        var device = new NetworkDevice
        {
            IpAddress = "192.168.1.25",
            MacAddress = "AA:BB:CC:DD:EE:25",
            DeviceTypeGuess = "Unknown"
        };
        var coordinator = CreateCoordinator(repository, new FakeScanner([]), [device]);

        var count = await coordinator.RunListeningPortScanAsync(CancellationToken.None);

        Assert.Equal(0, count);
        var savedDevice = Assert.Single(repository.Devices);
        Assert.Equal("192.168.1.25", savedDevice.IpAddress);
        Assert.Equal("AA:BB:CC:DD:EE:25", savedDevice.MacAddress);
    }

    /// <summary>
    /// Verifies scan-time device observations preserve saved device trust decisions.
    /// </summary>
    /// <param name="decision">Saved device trust decision.</param>
    /// <param name="expectedRisk">Expected inventory risk status.</param>
    [Theory]
    [InlineData(TrustStatus.Trusted, RiskStatus.Normal)]
    [InlineData(TrustStatus.Guest, RiskStatus.Watched)]
    [InlineData(TrustStatus.KnownWatched, RiskStatus.Watched)]
    [InlineData(TrustStatus.Blocked, RiskStatus.Critical)]
    public async Task RunListeningPortScanAsync_PreservesDeviceTrustDecision(TrustStatus decision, RiskStatus expectedRisk)
    {
        var repository = new FakeRepository { TrustDecision = decision };
        var device = new NetworkDevice
        {
            IpAddress = "192.168.1.25",
            MacAddress = "AA:BB:CC:DD:EE:25",
            TrustStatus = TrustStatus.Unknown,
            RiskStatus = RiskStatus.Normal
        };
        var coordinator = CreateCoordinator(repository, new FakeScanner([]), [device]);

        var count = await coordinator.RunListeningPortScanAsync(CancellationToken.None);

        Assert.Equal(0, count);
        Assert.Collection(
            repository.Devices,
            first => Assert.Equal(TrustStatus.Unknown, first.TrustStatus),
            second =>
            {
                Assert.Equal(decision, second.TrustStatus);
                Assert.Equal(expectedRisk, second.RiskStatus);
            });
    }

    /// <summary>
    /// Verifies a newly observed port creates a new listening port event.
    /// </summary>
    [Fact]
    public async Task RunListeningPortScanAsync_CreatesEventForNewPort()
    {
        var repository = new FakeRepository { IsNewPort = true };
        var port = new ListeningPort
        {
            PortNumber = 3389,
            Protocol = "TCP",
            LocalAddress = "0.0.0.0",
            Reachability = PortReachability.NetworkReachable,
            Application = new ApplicationIdentity
            {
                DisplayName = "Remote Desktop",
                ProcessName = "svchost",
                SignatureStatus = SignatureStatus.TrustedSigned
            }
        };
        var coordinator = CreateCoordinator(repository, new FakeScanner([port]));

        var count = await coordinator.RunListeningPortScanAsync(CancellationToken.None);

        Assert.Equal(1, count);
        var networkEvent = Assert.Single(repository.Events);
        Assert.Equal("NewListeningPort", networkEvent.EventType);
        Assert.Equal(3389, networkEvent.DestinationPort);
        Assert.True(networkEvent.WasUserNotified);
        Assert.Contains("Remote Desktop", networkEvent.DetailsJson);
        var incident = Assert.Single(repository.Incidents);
        Assert.Contains("Network port opened: Remote Desktop", incident.Title);
        Assert.Equal(RiskLevel.High, incident.RiskLevel);
        Assert.Equal(99, incident.MainApplicationId);
        Assert.Contains("Why:", incident.Summary);
        var notification = Assert.Single(repository.Notifications);
        Assert.Equal(RiskLevel.High, notification.RiskLevel);
        Assert.Equal(NotificationAction.AskBeforeAllow, notification.Action);
    }

    /// <summary>
    /// Verifies existing ports update state without creating duplicate events.
    /// </summary>
    [Fact]
    public async Task RunListeningPortScanAsync_SkipsEventForExistingPort()
    {
        var repository = new FakeRepository { IsNewPort = false };
        var port = new ListeningPort
        {
            PortNumber = 8080,
            Protocol = "TCP",
            LocalAddress = "127.0.0.1",
            Reachability = PortReachability.LocalOnly
        };
        var coordinator = CreateCoordinator(repository, new FakeScanner([port]));

        var count = await coordinator.RunListeningPortScanAsync(CancellationToken.None);

        Assert.Equal(0, count);
        Assert.Empty(repository.Events);
    }

    /// <summary>
    /// Verifies new low-risk ports are logged without user notification.
    /// </summary>
    [Fact]
    public async Task RunListeningPortScanAsync_LogsSilentEventForLowRiskPort()
    {
        var repository = new FakeRepository { IsNewPort = true };
        var port = new ListeningPort
        {
            PortNumber = 7000,
            Protocol = "TCP",
            LocalAddress = "127.0.0.1",
            Reachability = PortReachability.LocalOnly
        };
        var coordinator = CreateCoordinator(repository, new FakeScanner([port]));

        var count = await coordinator.RunListeningPortScanAsync(CancellationToken.None);

        Assert.Equal(1, count);
        var networkEvent = Assert.Single(repository.Events);
        Assert.False(networkEvent.WasUserNotified);
        Assert.Null(networkEvent.ApplicationId);
        Assert.Contains("Unknown application", networkEvent.DetailsJson);
        Assert.Empty(repository.Incidents);
        Assert.Empty(repository.Notifications);
    }

    /// <summary>
    /// Verifies active application trust decisions are applied before scoring.
    /// </summary>
    [Fact]
    public async Task RunListeningPortScanAsync_AppliesApplicationTrustDecisionBeforeScoring()
    {
        var repository = new FakeRepository { IsNewPort = true, TrustDecision = TrustStatus.Trusted };
        var port = new ListeningPort
        {
            PortNumber = 32400,
            Protocol = "TCP",
            LocalAddress = "0.0.0.0",
            Reachability = PortReachability.NetworkReachable,
            Application = new ApplicationIdentity
            {
                DisplayName = "Plex Media Server",
                ProcessName = "plex",
                SignatureStatus = SignatureStatus.TrustedSigned
            }
        };
        var coordinator = CreateCoordinator(repository, new FakeScanner([port]));

        var count = await coordinator.RunListeningPortScanAsync(CancellationToken.None);

        Assert.Equal(1, count);
        var networkEvent = Assert.Single(repository.Events);
        Assert.Equal(RiskLevel.Low, networkEvent.RiskLevel);
        Assert.False(networkEvent.WasUserNotified);
    }


    /// <summary>
    /// Verifies watched application decisions reduce future scan noise while keeping events visible.
    /// </summary>
    [Fact]
    public async Task RunListeningPortScanAsync_AppliesWatchedApplicationDecisionBeforeScoring()
    {
        var repository = new FakeRepository { IsNewPort = true, TrustDecision = TrustStatus.KnownWatched };
        var port = new ListeningPort
        {
            PortNumber = 3389,
            Protocol = "TCP",
            LocalAddress = "0.0.0.0",
            Reachability = PortReachability.NetworkReachable,
            Application = new ApplicationIdentity
            {
                DisplayName = "Remote Desktop",
                ProcessName = "svchost",
                SignatureStatus = SignatureStatus.TrustedSigned
            }
        };
        var coordinator = CreateCoordinator(repository, new FakeScanner([port]));

        var count = await coordinator.RunListeningPortScanAsync(CancellationToken.None);

        Assert.Equal(1, count);
        var networkEvent = Assert.Single(repository.Events);
        Assert.Equal(RiskLevel.Medium, networkEvent.RiskLevel);
        Assert.True(networkEvent.WasUserNotified);
        var notification = Assert.Single(repository.Notifications);
        Assert.Equal(NotificationAction.SoftNotify, notification.Action);
        Assert.Equal(RiskLevel.Medium, Assert.Single(repository.Incidents).RiskLevel);
    }
    /// <summary>
    /// Verifies an existing port creates an event when a different application owns it.
    /// </summary>
    [Fact]
    public async Task RunListeningPortScanAsync_CreatesEventWhenExistingPortChangesApplication()
    {
        var repository = new FakeRepository { IsNewPort = false, ExistingPortApplicationId = 41 };
        var port = new ListeningPort
        {
            PortNumber = 8080,
            Protocol = "TCP",
            LocalAddress = "0.0.0.0",
            Reachability = PortReachability.NetworkReachable,
            Application = new ApplicationIdentity
            {
                DisplayName = "New owner",
                ProcessName = "new-owner",
                SignatureStatus = SignatureStatus.TrustedSigned
            }
        };
        var coordinator = CreateCoordinator(repository, new FakeScanner([port]));

        var count = await coordinator.RunListeningPortScanAsync(CancellationToken.None);

        Assert.Equal(1, count);
        var networkEvent = Assert.Single(repository.Events);
        Assert.Equal("ListeningPortApplicationChanged", networkEvent.EventType);
        Assert.Equal(99, networkEvent.ApplicationId);
        Assert.Contains("different application", networkEvent.DetailsJson);
        var incident = Assert.Single(repository.Incidents);
        Assert.Contains("Port ownership changed: New owner", incident.Title);
    }
    private static ServiceScanCoordinator CreateCoordinator(FakeRepository repository, FakeScanner scanner, IReadOnlyList<NetworkDevice>? devices = null)
    {
        return new ServiceScanCoordinator(
            repository,
            scanner,
            new FakeDeviceDiscovery(devices ?? []),
            new RiskScoringService(),
            new AccessWatchSettings(),
            new NotificationMessageFactory(),
            repository,
            NullLogger<ServiceScanCoordinator>.Instance);
    }

    private sealed class FakeDeviceDiscovery : INetworkDeviceDiscoveryService
    {
        private readonly IReadOnlyList<NetworkDevice> devices;

        public FakeDeviceDiscovery(IReadOnlyList<NetworkDevice> devices)
        {
            this.devices = devices;
        }

        public Task<IReadOnlyList<NetworkDevice>> DiscoverAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(devices);
        }

    }

    private sealed class FakeScanner : IListeningPortScanner
    {
        private readonly IReadOnlyList<ListeningPort> ports;

        public FakeScanner(IReadOnlyList<ListeningPort> ports)
        {
            this.ports = ports;
        }

        public Task<IReadOnlyList<ListeningPort>> ScanAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(ports);
        }
    }

    private sealed class FakeRepository : IAccessWatchRepository, ITrayNotificationService
    {
        public bool WasInitialized { get; private set; }

        public bool IsNewPort { get; init; }

        public TrustStatus? TrustDecision { get; init; }

        public long? ExistingPortApplicationId { get; init; }

        public List<NetworkEvent> Events { get; } = [];

        public List<NotificationMessage> Notifications { get; } = [];

        public List<NetworkDevice> Devices { get; } = [];

        public List<Incident> Incidents { get; } = [];

        public Task ShowAsync(NotificationMessage message, CancellationToken cancellationToken)
        {
            Notifications.Add(message);
            return Task.CompletedTask;
        }

        public Task InitializeAsync(CancellationToken cancellationToken)
        {
            WasInitialized = true;
            return Task.CompletedTask;
        }


        public Task<long> UpsertDeviceAsync(NetworkDevice device, CancellationToken cancellationToken)
        {
            Devices.Add(device);
            return Task.FromResult(1L);
        }

        public Task<IReadOnlyList<NetworkDevice>> ListRecentDevicesAsync(int limit, CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyList<NetworkDevice>>([]);
        }

        public Task UpdateDeviceAliasAsync(long deviceId, string? userAlias, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task<long> UpsertApplicationAsync(AppIdentity application, CancellationToken cancellationToken)
        {
            return Task.FromResult(99L);
        }


        public Task<long?> GetListeningPortApplicationIdAsync(ListeningPort port, CancellationToken cancellationToken)
        {
            return Task.FromResult(ExistingPortApplicationId);
        }
        public Task<bool> UpsertPortAsync(ListeningPort port, long? applicationId, CancellationToken cancellationToken)
        {
            return Task.FromResult(IsNewPort);
        }

        public Task AddNetworkEventAsync(NetworkEvent networkEvent, CancellationToken cancellationToken)
        {
            Events.Add(networkEvent);
            return Task.CompletedTask;
        }

        public Task<long> AddTrustDecisionAsync(TrustDecision trustDecision, CancellationToken cancellationToken)
        {
            return Task.FromResult(1L);
        }

        public Task<TrustStatus?> GetActiveTrustDecisionAsync(string targetType, long targetId, CancellationToken cancellationToken)
        {
            return Task.FromResult(TrustDecision);
        }


        public Task<long> UpsertIncidentAsync(Incident incident, CancellationToken cancellationToken)
        {
            var incidentId = Incidents.Count + 1L;
            Incidents.Add(incident with { IncidentId = incidentId });
            return Task.FromResult(incidentId);
        }

        public Task<long> UpsertRuleAsync(AccessWatchRule rule, CancellationToken cancellationToken)
        {
            return Task.FromResult(1L);
        }

        public Task<IReadOnlyList<Incident>> ListRecentIncidentsAsync(int limit, CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyList<Incident>>(Incidents);
        }

        public Task<IReadOnlyList<AccessWatchRule>> ListRulesAsync(bool includeDisabled, CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyList<AccessWatchRule>>([]);
        }
        public Task<IReadOnlyList<ApplicationIdentity>> ListRecentApplicationsAsync(int limit, CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyList<ApplicationIdentity>>([]);
        }

        public Task<IReadOnlyList<ListeningPort>> ListRecentPortsAsync(int limit, CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyList<ListeningPort>>([]);
        }

        public Task<IReadOnlyList<NetworkEvent>> ListRecentNetworkEventsAsync(int limit, CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyList<NetworkEvent>>([]);
        }
    }
}
