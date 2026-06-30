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
    /// Verifies the simulator persists the full scenario and delivers a toast notification.
    /// </summary>
    [Fact]
    public async Task TriggerDemoEventAsync_PersistsScenarioAndNotifies()
    {
        var repository = new FakeRepository();
        var simulator = new AccessWatchEventSimulator(repository, new NotificationMessageFactory(), repository);

        var createdEvents = await simulator.TriggerDemoEventAsync(CancellationToken.None);

        Assert.Equal(1, createdEvents);
        Assert.True(repository.WasInitialized);
        var device = Assert.Single(repository.Devices);
        Assert.Equal(101, device.DeviceId);
        Assert.Equal("192.168.1.240", device.IpAddress);
        Assert.Equal("simulated-nas", device.Hostname);
        Assert.Equal(RiskStatus.Suspicious, device.RiskStatus);
        var application = Assert.Single(repository.Applications);
        Assert.Equal(202, application.ApplicationId);
        Assert.Equal("Simulated Remote Admin", application.DisplayName);
        Assert.Equal(SignatureStatus.Unsigned, application.SignatureStatus);
        var port = Assert.Single(repository.Ports);
        Assert.Equal(9443, port.PortNumber);
        Assert.Equal("0.0.0.0", port.LocalAddress);
        Assert.Equal(PortReachability.NetworkReachable, port.Reachability);
        Assert.Equal(202, repository.PortApplicationIds.Single());
        var networkEvent = Assert.Single(repository.Events);
        Assert.Equal("NewListeningPort", networkEvent.EventType);
        Assert.Equal(101, networkEvent.SourceDeviceId);
        Assert.Equal(202, networkEvent.ApplicationId);
        Assert.Equal(9443, networkEvent.DestinationPort);
        Assert.Equal(RiskLevel.High, networkEvent.RiskLevel);
        Assert.True(networkEvent.WasUserNotified);
        Assert.Contains("\"simulated\":true", networkEvent.DetailsJson);
        Assert.Contains("Simulated Remote Admin", networkEvent.DetailsJson);
        var notification = Assert.Single(repository.Notifications);
        Assert.Equal(RiskLevel.High, notification.RiskLevel);
        Assert.Equal(NotificationAction.AskBeforeAllow, notification.Action);
        Assert.Contains("Simulated Remote Admin", notification.Body);
    }

    private sealed class FakeRepository : IAccessWatchRepository, ITrayNotificationService
    {
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
            Devices.Add(device with { DeviceId = 101 });
            return Task.FromResult(101L);
        }

        public Task<IReadOnlyList<NetworkDevice>> ListRecentDevicesAsync(int limit, CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyList<NetworkDevice>>(Devices);
        }

        public Task<long> UpsertApplicationAsync(AppIdentity application, CancellationToken cancellationToken)
        {
            Applications.Add(application with { ApplicationId = 202 });
            return Task.FromResult(202L);
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

