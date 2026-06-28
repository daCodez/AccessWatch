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
    }

    private static ServiceScanCoordinator CreateCoordinator(FakeRepository repository, FakeScanner scanner)
    {
        return new ServiceScanCoordinator(
            repository,
            scanner,
            new RiskScoringService(),
            new AccessWatchSettings(),
            new NotificationMessageFactory(),
            NullLogger<ServiceScanCoordinator>.Instance);
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

    private sealed class FakeRepository : IAccessWatchRepository
    {
        public bool WasInitialized { get; private set; }

        public bool IsNewPort { get; init; }

        public List<NetworkEvent> Events { get; } = [];

        public Task InitializeAsync(CancellationToken cancellationToken)
        {
            WasInitialized = true;
            return Task.CompletedTask;
        }

        public Task<long> UpsertApplicationAsync(AppIdentity application, CancellationToken cancellationToken)
        {
            return Task.FromResult(99L);
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
    }
}
