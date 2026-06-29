using AccessWatch.App.ViewModels;
using AccessWatch.Core;
using AccessWatch.Notifications;
using AccessWatch.Tray;
using AppIdentity = AccessWatch.Core.ApplicationIdentity;

namespace AccessWatch.Tests;

/// <summary>
/// Tests notification and shell view-model behavior.
/// </summary>
public sealed class NotificationAndViewModelTests
{
    /// <summary>
    /// Verifies notification messages preserve assessment context.
    /// </summary>
    [Fact]
    public void NotificationMessageFactory_CreatesFriendlyMessage()
    {
        var factory = new NotificationMessageFactory();
        var assessment = new PortRiskAssessment(
            RiskLevel.High,
            RiskStatus.HighRisk,
            NotificationAction.AskBeforeAllow,
            "Discord updater opened a port.",
            "It is network reachable.",
            "Review it.");

        var message = factory.Create(assessment);

        Assert.Equal("AccessWatch", message.Title);
        Assert.Contains("Discord updater opened a port.", message.Body);
        Assert.Contains("It is network reachable.", message.Body);
        Assert.Equal(RiskLevel.High, message.RiskLevel);
        Assert.Equal(NotificationAction.AskBeforeAllow, message.Action);
        Assert.Equal("Review it.", message.SuggestedAction);
    }

    /// <summary>
    /// Verifies the MVP tray sink records only messages that should be visible to the user.
    /// </summary>
    [Fact]
    public async Task TrayNotificationService_RecordsOnlyVisibleMessages()
    {
        var service = new InMemoryTrayNotificationService();
        var visible = new NotificationMessage("AccessWatch", "Review this port.", RiskLevel.High, NotificationAction.AskBeforeAllow, "Review it.");
        var silent = new NotificationMessage("AccessWatch", "Local-only port.", RiskLevel.Low, NotificationAction.SilentLog, "No action needed.");

        await service.ShowAsync(visible, CancellationToken.None);
        await service.ShowAsync(silent, CancellationToken.None);

        Assert.Equal(visible, Assert.Single(service.DeliveredNotifications));
    }

    /// <summary>
    /// Verifies dashboard shell pages include the MVP areas.
    /// </summary>
    [Fact]
    public void DashboardShellViewModel_ContainsMvpPages()
    {
        var model = new DashboardShellViewModel();

        Assert.Equal(["Overview", "Devices", "Applications", "Ports", "Incidents", "Settings"], model.Pages.Select(page => page.Name));
        Assert.All(model.Pages, page => Assert.False(string.IsNullOrWhiteSpace(page.Summary)));
    }

    /// <summary>
    /// Verifies the dashboard reports when no repository is connected.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsyncWithoutRepository_ShowsDisconnectedState()
    {
        var model = new DashboardShellViewModel();

        await model.LoadAsync(CancellationToken.None);

        Assert.Equal("Dashboard data is not connected yet.", model.StatusMessage);
        Assert.Empty(model.Metrics);
    }

    /// <summary>
    /// Verifies the dashboard loads counts and recent network events.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_LoadsRepositoryData()
    {
        var repository = new FakeRepository
        {
            Devices = [new NetworkDevice { IpAddress = "192.168.1.1" }],
            Applications = [new AppIdentity { DisplayName = "Plex", ProcessName = "plex" }],
            Ports = [new ListeningPort { PortNumber = 32400, LocalAddress = "0.0.0.0" }],
            Events =
            [
                new NetworkEvent
                {
                    EventType = "NewListeningPort",
                    DestinationIp = "0.0.0.0",
                    DestinationPort = 32400,
                    RiskLevel = RiskLevel.Medium,
                    Summary = "Plex opened a port."
                }
            ]
        };
        var model = new DashboardShellViewModel(repository);
        var changed = new List<string?>();
        model.PropertyChanged += (_, args) => changed.Add(args.PropertyName);

        await model.LoadAsync(CancellationToken.None);

        Assert.True(repository.WasInitialized);
        Assert.Equal(["Devices", "Apps", "Ports", "Events"], model.Metrics.Select(metric => metric.Name));
        Assert.Equal([1, 1, 1, 1], model.Metrics.Select(metric => metric.Count));
        var activity = Assert.Single(model.RecentActivity);
        Assert.Equal("Medium", activity.Kind);
        Assert.Contains("Plex opened", activity.Summary);
        Assert.Contains("0.0.0.0:32400", activity.Detail);
        Assert.Contains("Loaded 1 events, 1 ports, and 1 devices.", model.StatusMessage);
        Assert.Contains(nameof(DashboardShellViewModel.IsLoading), changed);
        Assert.Contains(nameof(DashboardShellViewModel.StatusMessage), changed);
        Assert.False(model.IsLoading);
    }

    /// <summary>
    /// Verifies event activity explains the owning application and the reason AccessWatch flagged it.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_ExplainsEventApplicationAndReason()
    {
        var repository = new FakeRepository
        {
            Applications =
            [
                new AppIdentity
                {
                    ApplicationId = 42,
                    DisplayName = "Windows Service Host",
                    ProcessName = "svchost",
                    Publisher = "Microsoft Windows",
                    SignatureStatus = SignatureStatus.TrustedSigned
                }
            ],
            Events =
            [
                new NetworkEvent
                {
                    ApplicationId = 42,
                    EventType = "NewListeningPort",
                    DestinationIp = "0.0.0.0",
                    DestinationPort = 49667,
                    RiskLevel = RiskLevel.High,
                    Summary = "svchost opened a network-reachable port.",
                    DetailsJson = "{ \"whatHappened\": \"A new listening TCP port appeared.\", \"app\": \"svchost\", \"processName\": \"svchost\", \"reachability\": \"NetworkReachable\", \"whyItMatters\": \"Other devices on your network may be able to connect to this service.\", \"suggestedAction\": \"Confirm the app is expected before trusting it.\" }"
                }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        var activity = Assert.Single(model.RecentActivity);
        Assert.Equal("Windows Service Host", activity.ApplicationName);
        Assert.Contains("Signed by Microsoft Windows", activity.ApplicationIdentity);
        Assert.Contains("A new listening TCP port appeared.", activity.Detail);
        Assert.Contains("NetworkReachable", activity.Detail);
        Assert.Equal("Other devices on your network may be able to connect to this service.", activity.WhyItMatters);
        Assert.Equal("Confirm the app is expected before trusting it.", activity.SuggestedAction);
    }
    /// <summary>
    /// Verifies event activity remains useful when stored detail JSON is missing or malformed.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_ExplainsEventsWithMissingDetails()
    {
        var repository = new FakeRepository
        {
            Events =
            [
                new NetworkEvent
                {
                    EventType = "UnexpectedTraffic",
                    Protocol = "TCP",
                    RiskLevel = RiskLevel.Low,
                    Summary = "AccessWatch recorded an event.",
                    DetailsJson = "{not-json"
                },
                new NetworkEvent
                {
                    EventType = "ListeningPortApplicationChanged",
                    DestinationIp = "127.0.0.1",
                    DestinationPort = 7000,
                    RiskLevel = RiskLevel.Medium,
                    Summary = "A port changed owners.",
                    DetailsJson = "{ \"app\": \"Helper Process\", \"processName\": \"helper\" }"
                }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        Assert.Collection(
            model.RecentActivity,
            first =>
            {
                Assert.Equal("Unknown application", first.ApplicationName);
                Assert.Equal("Application identity unavailable", first.ApplicationIdentity);
                Assert.Contains("AccessWatch recorded network activity.", first.Detail);
                Assert.Equal("AccessWatch logged this for your activity history.", first.WhyItMatters);
                Assert.Equal("No action needed.", first.SuggestedAction);
            },
            second =>
            {
                Assert.Equal("Helper Process", second.ApplicationName);
                Assert.Contains("Process helper", second.ApplicationIdentity);
                Assert.Contains("stored app identity unavailable", second.ApplicationIdentity);
                Assert.Contains("changed owning application", second.Detail);
                Assert.Equal("This activity is visible enough to keep on your radar.", second.WhyItMatters);
                Assert.Equal("No action needed if you recognize the application.", second.SuggestedAction);
            });
    }

    /// <summary>
    /// Verifies event activity exposes application signature and publisher context.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_ExplainsApplicationIdentityVariants()
    {
        var repository = new FakeRepository
        {
            Applications =
            [
                new AppIdentity { ApplicationId = 1, DisplayName = "Trusted", ProcessName = "trusted", SignatureStatus = SignatureStatus.TrustedSigned, FilePath = "C:\\Apps\\trusted.exe" },
                new AppIdentity { ApplicationId = 2, DisplayName = "Signed", ProcessName = "signed", SignatureStatus = SignatureStatus.SignedUnknown },
                new AppIdentity { ApplicationId = 3, DisplayName = "Unsigned", ProcessName = "unsigned", SignatureStatus = SignatureStatus.Unsigned },
                new AppIdentity { ApplicationId = 4, DisplayName = "Invalid", ProcessName = "invalid", SignatureStatus = SignatureStatus.InvalidSignature },
                new AppIdentity { ApplicationId = 5, DisplayName = "Unknown", ProcessName = "unknown", SignatureStatus = SignatureStatus.Unknown },
                new AppIdentity { ApplicationId = 6, DisplayName = "Publisher Only", ProcessName = "publisher", Publisher = "Example Corp", SignatureStatus = SignatureStatus.Unsigned },
                new AppIdentity { ApplicationId = 7, DisplayName = "Blank Process", ProcessName = string.Empty, SignatureStatus = SignatureStatus.Unknown }
            ],
            Events =
            [
                NewIdentityEvent(1, RiskLevel.High),
                NewIdentityEvent(2, RiskLevel.High),
                NewIdentityEvent(3, RiskLevel.High),
                NewIdentityEvent(4, RiskLevel.High),
                NewIdentityEvent(5, RiskLevel.High),
                NewIdentityEvent(6, RiskLevel.High),
                NewIdentityEvent(7, RiskLevel.High) with { DetailsJson = string.Empty }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        Assert.Contains(model.RecentActivity, activity => activity.ApplicationIdentity.Contains("Trusted signature") && activity.ApplicationIdentity.Contains("C:\\Apps\\trusted.exe"));
        Assert.Contains(model.RecentActivity, activity => activity.ApplicationIdentity.Contains("Signed; publisher trust unknown"));
        Assert.Contains(model.RecentActivity, activity => activity.ApplicationIdentity.Contains("Unsigned executable"));
        Assert.Contains(model.RecentActivity, activity => activity.ApplicationIdentity.Contains("Invalid signature"));
        Assert.Contains(model.RecentActivity, activity => activity.ApplicationIdentity.Contains("Signature status unknown"));
        Assert.Contains(model.RecentActivity, activity => activity.ApplicationIdentity.Contains("Publisher Example Corp"));
        Assert.Contains(model.RecentActivity, activity => activity.ApplicationName == "Blank Process" && activity.ApplicationIdentity == "Signature status unknown; Executable path unavailable");
        Assert.All(model.RecentActivity, activity => Assert.Equal("Confirm the application and port are expected before trusting it.", activity.SuggestedAction));
    }

    private static NetworkEvent NewIdentityEvent(long applicationId, RiskLevel riskLevel)
    {
        return new NetworkEvent
        {
            ApplicationId = applicationId,
            EventType = "NewListeningPort",
            DestinationIp = "0.0.0.0",
            DestinationPort = 5000 + (int)applicationId,
            RiskLevel = riskLevel,
            Summary = $"Application {applicationId} opened a port.",
            DetailsJson = "{ \"app\": 7 }"
        };
    }
    /// <summary>
    /// Verifies the dashboard falls back to port rows when no events exist.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_UsesPortFallbackActivity()
    {
        var repository = new FakeRepository
        {
            Ports =
            [
                new ListeningPort
                {
                    PortNumber = 8080,
                    LocalAddress = "127.0.0.1",
                    RiskStatus = RiskStatus.Normal,
                    Application = new AppIdentity { DisplayName = "Dev server", ProcessName = "dev" }
                }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        var activity = Assert.Single(model.RecentActivity);
        Assert.Equal("Normal", activity.Kind);
        Assert.Contains("Port 8080", activity.Summary);
        Assert.Equal("Dev server", activity.ApplicationName);
        Assert.Contains("TCP 127.0.0.1:8080", activity.Detail);
    }

    /// <summary>
    /// Verifies port fallback rows handle incomplete app identity records.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_UsesUnknownApplicationForIncompletePortIdentity()
    {
        var repository = new FakeRepository
        {
            Ports =
            [
                new ListeningPort
                {
                    PortNumber = 7777,
                    LocalAddress = "0.0.0.0",
                    Reachability = PortReachability.NetworkReachable,
                    Application = new AppIdentity { DisplayName = null!, ProcessName = "mystery" }
                }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        var activity = Assert.Single(model.RecentActivity);
        Assert.Equal("Unknown application", activity.ApplicationName);
        Assert.Contains("Other devices", activity.WhyItMatters);
    }
    /// <summary>
    /// Verifies the dashboard falls back to device rows when no events or ports exist.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_UsesDeviceFallbackActivity()
    {
        var repository = new FakeRepository
        {
            Devices = [new NetworkDevice { IpAddress = "192.168.1.10", MacAddress = "AA:BB:CC:DD:EE:FF" }]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        var activity = Assert.Single(model.RecentActivity);
        Assert.Equal("Unknown", activity.Kind);
        Assert.Contains("192.168.1.10", activity.Summary);
        Assert.Equal("AA:BB:CC:DD:EE:FF", activity.Detail);
    }

    /// <summary>
    /// Verifies the dashboard explains an empty repository clearly.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_ShowsEmptyState()
    {
        var model = new DashboardShellViewModel(new FakeRepository());

        await model.LoadAsync(CancellationToken.None);

        Assert.All(model.Metrics, metric => Assert.Equal(0, metric.Count));
        Assert.Empty(model.RecentActivity);
        Assert.Contains("No stored activity yet", model.StatusMessage);
    }

    /// <summary>
    /// Verifies repository failures are shown as dashboard status instead of crashing the window.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_ShowsRepositoryFailure()
    {
        var model = new DashboardShellViewModel(new FakeRepository { Failure = new InvalidOperationException("database offline") });

        await model.LoadAsync(CancellationToken.None);

        Assert.Contains("database offline", model.StatusMessage);
        Assert.False(model.IsLoading);
    }


    /// <summary>
    /// Verifies recent activity uses readable fallback text when optional fields are missing.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_UsesFallbackDisplayText()
    {
        var eventModel = new DashboardShellViewModel(new FakeRepository
        {
            Events = [new NetworkEvent { EventType = "NewListeningPort", RiskLevel = RiskLevel.Low, Summary = "Local service opened." }]
        });
        await eventModel.LoadAsync(CancellationToken.None);
        Assert.Contains("local:n/a", Assert.Single(eventModel.RecentActivity).Detail);

        var portModel = new DashboardShellViewModel(new FakeRepository
        {
            Ports = [new ListeningPort { PortNumber = 9000, LocalAddress = "127.0.0.1" }]
        });
        await portModel.LoadAsync(CancellationToken.None);
        var portActivity = Assert.Single(portModel.RecentActivity);
        Assert.Equal("Unknown application", portActivity.ApplicationName);
        Assert.Contains("TCP 127.0.0.1:9000", portActivity.Detail);

        var deviceModel = new DashboardShellViewModel(new FakeRepository
        {
            Devices = [new NetworkDevice { IpAddress = "192.168.1.11" }]
        });
        await deviceModel.LoadAsync(CancellationToken.None);
        Assert.Equal("MAC address unavailable", Assert.Single(deviceModel.RecentActivity).Detail);
    }

    /// <summary>
    /// Verifies scan requests report when no scan function is connected.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_RunScanAsyncWithoutScanner_ShowsDisconnectedState()
    {
        var model = new DashboardShellViewModel(new FakeRepository());

        await model.RunScanAsync(CancellationToken.None);

        Assert.Equal("Dashboard scan is not connected yet.", model.StatusMessage);
    }

    /// <summary>
    /// Verifies scan requests run the scan and reload dashboard data.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_RunScanAsync_ReloadsData()
    {
        var repository = new FakeRepository
        {
            Events = [new NetworkEvent { EventType = "NewListeningPort", RiskLevel = RiskLevel.High, Summary = "SSH opened.", DestinationPort = 22 }]
        };
        var scanCount = 0;
        var model = new DashboardShellViewModel(repository, _ =>
        {
            scanCount++;
            return Task.FromResult(3);
        });

        await model.RunScanAsync(CancellationToken.None);

        Assert.Equal(1, scanCount);
        Assert.Single(model.RecentActivity);
        Assert.Equal("Scan completed. Created 3 new events.", model.StatusMessage);
        Assert.False(model.IsLoading);
    }

    /// <summary>
    /// Verifies scan failures are shown as dashboard status instead of crashing the window.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_RunScanAsync_ShowsScanFailure()
    {
        var model = new DashboardShellViewModel(new FakeRepository(), _ => throw new InvalidOperationException("scan failed"));

        await model.RunScanAsync(CancellationToken.None);

        Assert.Contains("scan failed", model.StatusMessage);
        Assert.False(model.IsLoading);
    }
    /// <summary>
    /// Verifies tray quick actions include opening the dashboard.
    /// </summary>
    [Fact]
    public void TrayQuickActionsViewModel_ContainsDashboardAction()
    {
        var model = new TrayQuickActionsViewModel();

        Assert.Contains(model.Actions, action => action.Command == "OpenDashboard" && action.Name == "Open dashboard");
    }

    private sealed class FakeRepository : IAccessWatchRepository
    {
        public IReadOnlyList<NetworkDevice> Devices { get; init; } = [];

        public IReadOnlyList<AppIdentity> Applications { get; init; } = [];

        public IReadOnlyList<ListeningPort> Ports { get; init; } = [];

        public IReadOnlyList<NetworkEvent> Events { get; init; } = [];

        public IReadOnlyList<Incident> Incidents { get; init; } = [];

        public IReadOnlyList<AccessWatchRule> Rules { get; init; } = [];

        public Exception? Failure { get; init; }

        public bool WasInitialized { get; private set; }

        public Task InitializeAsync(CancellationToken cancellationToken)
        {
            if (Failure is not null)
            {
                throw Failure;
            }

            WasInitialized = true;
            return Task.CompletedTask;
        }

        public Task<long> UpsertDeviceAsync(NetworkDevice device, CancellationToken cancellationToken)
        {
            return Task.FromResult(1L);
        }

        public Task<IReadOnlyList<NetworkDevice>> ListRecentDevicesAsync(int limit, CancellationToken cancellationToken)
        {
            return Task.FromResult(Devices);
        }

        public Task<long> UpsertApplicationAsync(AppIdentity application, CancellationToken cancellationToken)
        {
            return Task.FromResult(1L);
        }

        public Task<long?> GetListeningPortApplicationIdAsync(ListeningPort port, CancellationToken cancellationToken)
        {
            return Task.FromResult<long?>(null);
        }

        public Task<bool> UpsertPortAsync(ListeningPort port, long? applicationId, CancellationToken cancellationToken)
        {
            return Task.FromResult(true);
        }

        public Task AddNetworkEventAsync(NetworkEvent networkEvent, CancellationToken cancellationToken)
        {
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
            return Task.FromResult(Incidents);
        }

        public Task<IReadOnlyList<AccessWatchRule>> ListRulesAsync(bool includeDisabled, CancellationToken cancellationToken)
        {
            return Task.FromResult(Rules);
        }

        public Task<IReadOnlyList<AppIdentity>> ListRecentApplicationsAsync(int limit, CancellationToken cancellationToken)
        {
            return Task.FromResult(Applications);
        }

        public Task<IReadOnlyList<ListeningPort>> ListRecentPortsAsync(int limit, CancellationToken cancellationToken)
        {
            return Task.FromResult(Ports);
        }

        public Task<IReadOnlyList<NetworkEvent>> ListRecentNetworkEventsAsync(int limit, CancellationToken cancellationToken)
        {
            return Task.FromResult(Events);
        }
    }
}
