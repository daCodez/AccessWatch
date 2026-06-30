using AccessWatch.Core;
using AccessWatch.Notifications;
using AccessWatch.Service;
using AppIdentity = AccessWatch.Core.ApplicationIdentity;

namespace AccessWatch.Tests;

/// <summary>
/// Tests simulated AccessWatch event generation.
/// </summary>
public sealed class AccessWatchEventSimulatorTests
{
    /// <summary>
    /// Verifies the simulator persists varied scenarios and delivers toast notifications.
    /// </summary>
    [Fact]
    public async Task TriggerDemoEventAsync_RotatesThroughVariedScenariosAndNotifies()
    {
        var repository = new FakeRepository();
        var simulator = new AccessWatchEventSimulator(repository, new NotificationMessageFactory(), repository);

        for (var index = 0; index < 4; index++)
        {
            Assert.Equal(1, await simulator.TriggerDemoEventAsync(CancellationToken.None));
        }

        Assert.True(repository.WasInitialized);
        Assert.Equal(
            ["NewListeningPort", "CameraActivated", "MicrophoneActivated", "NewDeviceObserved"],
            repository.Events.Select(networkEvent => networkEvent.EventType));
        Assert.Contains(repository.Applications, application => application.DisplayName == "Simulated Remote Admin");
        Assert.Contains(repository.Applications, application => application.DisplayName == "Visual Studio");
        Assert.Contains(repository.Applications, application => application.DisplayName == "Skype");
        Assert.Contains(repository.Devices, device => device.Hostname == "simulated-nas");
        Assert.Contains(repository.Devices, device => device.Hostname == "office-laptop");
        Assert.Contains(repository.Devices, device => device.Hostname == "kitchen-tablet");
        var port = Assert.Single(repository.Ports);
        Assert.Equal(9443, port.PortNumber);
        Assert.Equal("0.0.0.0", port.LocalAddress);
        Assert.Equal(PortReachability.NetworkReachable, port.Reachability);
        Assert.All(repository.Events, networkEvent => Assert.True(networkEvent.WasUserNotified));
        Assert.Contains(repository.Events, networkEvent => networkEvent.DetailsJson.Contains("\"sensor\":\"Camera\""));
        Assert.Contains(repository.Events, networkEvent => networkEvent.DetailsJson.Contains("\"sensor\":\"Microphone\""));
        Assert.Contains(repository.Events, networkEvent => networkEvent.DetailsJson.Contains("Kitchen tablet joined"));
        Assert.Equal(4, repository.Notifications.Count);
        Assert.Contains(repository.Notifications, notification => notification.Body.Contains("camera"));
        Assert.Contains(repository.Notifications, notification => notification.Body.Contains("microphone"));
    }

    /// <summary>
    /// Verifies the simulator repeats the scenario rotation after all demo event types have run.
    /// </summary>
    [Fact]
    public async Task TriggerDemoEventAsync_RepeatsScenarioRotation()
    {
        var repository = new FakeRepository();
        var simulator = new AccessWatchEventSimulator(repository, new NotificationMessageFactory(), repository);

        for (var index = 0; index < 5; index++)
        {
            await simulator.TriggerDemoEventAsync(CancellationToken.None);
        }

        Assert.Equal("NewListeningPort", repository.Events[0].EventType);
        Assert.Equal("NewListeningPort", repository.Events[4].EventType);
    }

    private sealed class FakeRepository : IAccessWatchRepository, ITrayNotificationService
    {
        private long nextDeviceId = 100;
        private long nextApplicationId = 200;

        public bool WasInitialized { get; private set; }

        public List<NetworkDevice> Devices { get; } = [];

        public List<AppIdentity> Applications { get; } = [];

        public List<ListeningPort> Ports { get; } = [];

        public List<long?> PortApplicationIds { get; } = [];

        public List<NetworkEvent> Events { get; } = [];

        public List<NotificationMessage> Notifications { get; } = [];

        public Task InitializeAsync(CancellationToken cancellationToken)
        {
            WasInitialized = true;
            return Task.CompletedTask;
        }

        public Task<long> UpsertDeviceAsync(NetworkDevice device, CancellationToken cancellationToken)
        {
            var deviceId = ++nextDeviceId;
            Devices.Add(device with { DeviceId = deviceId });
            return Task.FromResult(deviceId);
        }

        public Task<IReadOnlyList<NetworkDevice>> ListRecentDevicesAsync(int limit, CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyList<NetworkDevice>>(Devices);
        }

        public Task<long> UpsertApplicationAsync(AppIdentity application, CancellationToken cancellationToken)
        {
            var applicationId = ++nextApplicationId;
            Applications.Add(application with { ApplicationId = applicationId });
            return Task.FromResult(applicationId);
        }

        public Task<long?> GetListeningPortApplicationIdAsync(ListeningPort port, CancellationToken cancellationToken)
        {
            return Task.FromResult<long?>(null);
        }

        public Task<bool> UpsertPortAsync(ListeningPort port, long? applicationId, CancellationToken cancellationToken)
        {
            Ports.Add(port);
            PortApplicationIds.Add(applicationId);
            return Task.FromResult(true);
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
            return Task.FromResult<TrustStatus?>(null);
        }

        public Task<IReadOnlyList<AppIdentity>> ListRecentApplicationsAsync(int limit, CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyList<AppIdentity>>(Applications);
        }

        public Task<IReadOnlyList<ListeningPort>> ListRecentPortsAsync(int limit, CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyList<ListeningPort>>(Ports);
        }

        public Task<IReadOnlyList<NetworkEvent>> ListRecentNetworkEventsAsync(int limit, CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyList<NetworkEvent>>(Events);
        }

        public Task<long> UpsertIncidentAsync(Incident incident, CancellationToken cancellationToken)
        {
            return Task.FromResult(1L);
        }

        public Task<long> UpsertRuleAsync(AccessWatchRule rule, CancellationToken cancellationToken)
        {
            return Task.FromResult(1L);
        }

        public Task<IReadOnlyList<Incident>> ListRecentIncidentsAsync(int limit, CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyList<Incident>>([]);
        }

        public Task<IReadOnlyList<AccessWatchRule>> ListRulesAsync(bool includeDisabled, CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyList<AccessWatchRule>>([]);
        }

        public Task ShowAsync(NotificationMessage message, CancellationToken cancellationToken)
        {
            Notifications.Add(message);
            return Task.CompletedTask;
        }
    }
}

