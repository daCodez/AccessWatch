using System.Text.Json;
using AccessWatch.App.ViewModels;
using AccessWatch.AI;
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
    /// Verifies the dashboard shell binds sidebar selection to the active page.
    /// </summary>
    [Fact]
    public void DashboardShellXaml_BindsSidebarSelectionToSelectedPage()
    {
        var xaml = File.ReadAllText(FindMainWindowXaml());

        Assert.Contains("SelectedItem=\"{Binding SelectedPage, Mode=TwoWay}\"", xaml);
        Assert.DoesNotContain("SelectedIndex=\"0\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedPageTitle}\"", xaml);
        Assert.DoesNotContain("Text=\"Overview\" FontSize=\"26\"", xaml);
        Assert.Contains("Height=\"760\" Width=\"1280\" MinHeight=\"680\" MinWidth=\"1120\"", xaml);
        Assert.Contains("<ColumnDefinition Width=\"200\" />", xaml);
        Assert.Contains("<Grid Grid.Column=\"1\" Margin=\"18\">", xaml);
        Assert.Contains("Content=\"{Binding ScanButtonText}\"", xaml);
        Assert.Contains("Content=\"{Binding SimulateButtonText}\"", xaml);
        Assert.Contains("Content=\"{Binding RefreshButtonText}\"", xaml);
        Assert.Contains("IsEnabled=\"{Binding CanRunActions}\"", xaml);
        Assert.Contains("Visibility=\"{Binding LoadingVisibility}\"", xaml);
        Assert.Contains("IsIndeterminate=\"True\"", xaml);
        Assert.Contains("Text=\"{Binding ProgressMessage}\"", xaml);
        Assert.Contains("Click=\"OnSimulateEventClick\"", xaml);
        Assert.Contains("Visibility=\"{Binding PortsVisibility}\"", xaml);
        Assert.Contains("Visibility=\"{Binding IncidentsVisibility}\"", xaml);
        Assert.Contains("ItemsSource=\"{Binding Ports}\"", xaml);
        Assert.Contains("SelectedItem=\"{Binding SelectedPort, Mode=TwoWay}\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedPortDetail}\"", xaml);
        Assert.Contains("Header=\"Meaning\"", xaml);
        Assert.Contains("Header=\"Next step\"", xaml);
        Assert.Contains("Content=\"{Binding PortInvestigationButtonText}\"", xaml);
        Assert.Contains("Click=\"OnInvestigatePortClick\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedPortInvestigation, Mode=OneWay}\"", xaml);
        Assert.Contains("ItemsSource=\"{Binding Incidents}\"", xaml);
        Assert.Contains("Visibility=\"{Binding SettingsVisibility}\"", xaml);
        Assert.Contains("ItemsSource=\"{Binding ProtectionModeOptions}\"", xaml);
        Assert.Contains("SelectedValue=\"{Binding SelectedProtectionMode, Mode=TwoWay}\"", xaml);
        Assert.Contains("ItemsSource=\"{Binding AiModeOptions}\"", xaml);
        Assert.Contains("SelectedValue=\"{Binding SelectedAiMode, Mode=TwoWay}\"", xaml);
        Assert.Contains("Click=\"OnApplySettingsClick\"", xaml);
        Assert.Contains("Click=\"OnResetSettingsClick\"", xaml);
        Assert.Contains("SelectedItem=\"{Binding SelectedDevice, Mode=TwoWay}\"", xaml);
        Assert.Contains("Header=\"Name source\"", xaml);
        Assert.Contains("Header=\"State\"", xaml);
        Assert.Contains("Header=\"First seen\"", xaml);
        Assert.Contains("Header=\"Confirmed\"", xaml);
        Assert.Contains("Header=\"Next step\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedDeviceDetail}\"", xaml);
        Assert.Contains("SelectedItem=\"{Binding SelectedApplication, Mode=TwoWay}\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedApplicationDetail}\"", xaml);
        Assert.Contains("Content=\"Trust device\"", xaml);
        Assert.Contains("Content=\"Watch device\"", xaml);
        Assert.Contains("Content=\"Guest device\"", xaml);
        Assert.Contains("Content=\"Block device\"", xaml);
        Assert.Contains("Content=\"Trust app\"", xaml);
        Assert.Contains("Content=\"Watch app\"", xaml);
        Assert.Contains("Content=\"Block app\"", xaml);
        Assert.Contains("Click=\"OnTrustDeviceClick\"", xaml);
        Assert.Contains("Click=\"OnGuestDeviceClick\"", xaml);
        Assert.Contains("Click=\"OnBlockApplicationClick\"", xaml);
        Assert.Contains("SelectedItem=\"{Binding SelectedIncident, Mode=TwoWay}\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedIncidentDetail}\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedIncidentExplanation, Mode=OneWay}\"", xaml);
        Assert.Contains("Content=\"Resolve\"", xaml);
        Assert.Contains("Content=\"Watch\"", xaml);
        Assert.Contains("Content=\"Escalate\"", xaml);
        Assert.Contains("Content=\"Create rule\"", xaml);
        Assert.Contains("Content=\"Review with AI\"", xaml);
        Assert.Contains("Content=\"Copy for ChatGPT\"", xaml);
        Assert.Contains("Click=\"OnResolveIncidentClick\"", xaml);
        Assert.Contains("Click=\"OnWatchIncidentClick\"", xaml);
        Assert.Contains("Click=\"OnEscalateIncidentClick\"", xaml);
        Assert.Contains("Click=\"OnCreateIncidentRuleClick\"", xaml);
        Assert.Contains("Click=\"OnReviewIncidentWithAiClick\"", xaml);
        Assert.Contains("Click=\"OnCopyIncidentForChatGptClick\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedIncidentAiReview, Mode=OneWay}\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedIncidentRuleSuggestion, Mode=OneWay}\"", xaml);
    }

    /// <summary>
    /// Verifies sidebar selection drives the main dashboard content.
    /// </summary>
    [Fact]
    public void DashboardShellViewModel_SelectedPage_UpdatesVisibleSection()
    {
        var model = new DashboardShellViewModel();
        var changed = new List<string?>();
        model.PropertyChanged += (_, args) => changed.Add(args.PropertyName);

        Assert.Equal("Overview", model.SelectedPageTitle);
        Assert.Equal("Recent risk posture and service status.", model.SelectedPageSummary);
        Assert.True(model.IsOverviewSelected);
        Assert.False(model.IsDevicesSelected);
        Assert.False(model.IsApplicationsSelected);
        Assert.False(model.IsPortsSelected);
        Assert.False(model.IsIncidentsSelected);
        Assert.False(model.IsSettingsSelected);
        Assert.False(model.IsPlaceholderSelected);
        Assert.Equal("Visible", model.OverviewVisibility);
        Assert.Equal("Collapsed", model.DevicesVisibility);
        Assert.Equal("Collapsed", model.ApplicationsVisibility);
        Assert.Equal("Collapsed", model.PortsVisibility);
        Assert.Equal("Collapsed", model.IncidentsVisibility);
        Assert.Equal("Collapsed", model.SettingsVisibility);
        Assert.Equal("Collapsed", model.PlaceholderVisibility);

        model.SelectedPage = model.Pages.Single(page => page.Name == "Devices");

        Assert.Equal("Devices", model.SelectedPageTitle);
        Assert.False(model.IsOverviewSelected);
        Assert.True(model.IsDevicesSelected);
        Assert.False(model.IsApplicationsSelected);
        Assert.False(model.IsPlaceholderSelected);
        Assert.Equal("Collapsed", model.OverviewVisibility);
        Assert.Equal("Visible", model.DevicesVisibility);
        Assert.Equal("Collapsed", model.ApplicationsVisibility);
        Assert.Equal("Collapsed", model.PlaceholderVisibility);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedPage), changed);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedPageTitle), changed);
        Assert.Contains(nameof(DashboardShellViewModel.IsDevicesSelected), changed);
        Assert.Contains(nameof(DashboardShellViewModel.DevicesVisibility), changed);

        changed.Clear();
        model.SelectedPage = model.SelectedPage;
        Assert.Empty(changed);

        model.SelectedPage = model.Pages.Single(page => page.Name == "Applications");

        Assert.Equal("Applications", model.SelectedPageTitle);
        Assert.False(model.IsOverviewSelected);
        Assert.False(model.IsDevicesSelected);
        Assert.True(model.IsApplicationsSelected);
        Assert.False(model.IsPlaceholderSelected);
        Assert.Equal("Collapsed", model.OverviewVisibility);
        Assert.Equal("Collapsed", model.DevicesVisibility);
        Assert.Equal("Visible", model.ApplicationsVisibility);
        Assert.Equal("Collapsed", model.PlaceholderVisibility);

        model.SelectedPage = model.Pages.Single(page => page.Name == "Ports");

        Assert.Equal("Ports", model.SelectedPageTitle);
        Assert.False(model.IsOverviewSelected);
        Assert.False(model.IsDevicesSelected);
        Assert.False(model.IsApplicationsSelected);
        Assert.True(model.IsPortsSelected);
        Assert.False(model.IsIncidentsSelected);
        Assert.False(model.IsSettingsSelected);
        Assert.False(model.IsPlaceholderSelected);
        Assert.Equal("Collapsed", model.OverviewVisibility);
        Assert.Equal("Collapsed", model.DevicesVisibility);
        Assert.Equal("Collapsed", model.ApplicationsVisibility);
        Assert.Equal("Visible", model.PortsVisibility);
        Assert.Equal("Collapsed", model.IncidentsVisibility);
        Assert.Equal("Collapsed", model.SettingsVisibility);
        Assert.Equal("Collapsed", model.PlaceholderVisibility);
        Assert.Contains(nameof(DashboardShellViewModel.IsPortsSelected), changed);
        Assert.Contains(nameof(DashboardShellViewModel.PortsVisibility), changed);

        model.SelectedPage = model.Pages.Single(page => page.Name == "Incidents");

        Assert.Equal("Incidents", model.SelectedPageTitle);
        Assert.False(model.IsOverviewSelected);
        Assert.False(model.IsDevicesSelected);
        Assert.False(model.IsApplicationsSelected);
        Assert.False(model.IsPortsSelected);
        Assert.True(model.IsIncidentsSelected);
        Assert.False(model.IsPlaceholderSelected);
        Assert.Equal("Collapsed", model.OverviewVisibility);
        Assert.Equal("Collapsed", model.DevicesVisibility);
        Assert.Equal("Collapsed", model.ApplicationsVisibility);
        Assert.Equal("Collapsed", model.PortsVisibility);
        Assert.Equal("Visible", model.IncidentsVisibility);
        Assert.Equal("Collapsed", model.PlaceholderVisibility);

        model.SelectedPage = model.Pages.Single(page => page.Name == "Settings");

        Assert.Equal("Settings", model.SelectedPageTitle);
        Assert.False(model.IsOverviewSelected);
        Assert.False(model.IsDevicesSelected);
        Assert.False(model.IsApplicationsSelected);
        Assert.False(model.IsPortsSelected);
        Assert.False(model.IsIncidentsSelected);
        Assert.True(model.IsSettingsSelected);
        Assert.False(model.IsPlaceholderSelected);
        Assert.Equal("Collapsed", model.OverviewVisibility);
        Assert.Equal("Collapsed", model.DevicesVisibility);
        Assert.Equal("Collapsed", model.ApplicationsVisibility);
        Assert.Equal("Collapsed", model.PortsVisibility);
        Assert.Equal("Collapsed", model.IncidentsVisibility);
        Assert.Equal("Visible", model.SettingsVisibility);
        Assert.Equal("Collapsed", model.PlaceholderVisibility);

        model.SelectedPage = null;

        Assert.Equal("Overview", model.SelectedPageTitle);
        Assert.True(model.IsOverviewSelected);
    }
    /// <summary>
    /// Verifies refresh work exposes button and progress state while loading.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_ShowsRefreshProgressState()
    {
        var releaseLoad = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var repository = new FakeRepository { InitializeGate = releaseLoad };
        var model = new DashboardShellViewModel(repository);
        var changed = new List<string?>();
        model.PropertyChanged += (_, args) => changed.Add(args.PropertyName);

        var loadTask = model.LoadAsync(CancellationToken.None);

        Assert.True(model.IsLoading);
        Assert.False(model.CanRunActions);
        Assert.Equal("Visible", model.LoadingVisibility);
        Assert.Equal("Scan now", model.ScanButtonText);
        Assert.Equal("Simulate event", model.SimulateButtonText);
        Assert.Equal("Refreshing...", model.RefreshButtonText);
        Assert.Equal("Refreshing dashboard data...", model.ProgressMessage);
        Assert.Equal("Refreshing dashboard data...", model.StatusMessage);
        Assert.Contains(nameof(DashboardShellViewModel.CanRunActions), changed);
        Assert.Contains(nameof(DashboardShellViewModel.LoadingVisibility), changed);

        releaseLoad.SetResult();
        await loadTask;

        Assert.False(model.IsLoading);
        Assert.True(model.CanRunActions);
        Assert.Equal("Collapsed", model.LoadingVisibility);
        Assert.Equal("Refresh", model.RefreshButtonText);
    }

    /// <summary>
    /// Verifies scan work exposes button and progress state while searching.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_RunScanAsync_ShowsScanProgressState()
    {
        var releaseScan = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var repository = new FakeRepository();
        var model = new DashboardShellViewModel(repository, async _ =>
        {
            await releaseScan.Task;
            return 2;
        });

        var scanTask = model.RunScanAsync(CancellationToken.None);

        Assert.True(model.IsLoading);
        Assert.False(model.CanRunActions);
        Assert.Equal("Visible", model.LoadingVisibility);
        Assert.Equal("Scanning...", model.ScanButtonText);
        Assert.Equal("Simulate event", model.SimulateButtonText);
        Assert.Equal("Refresh", model.RefreshButtonText);
        Assert.Equal("Searching network devices and listening ports...", model.ProgressMessage);
        Assert.Equal("Scanning network devices and listening ports...", model.StatusMessage);

        releaseScan.SetResult();
        await scanTask;

        Assert.False(model.IsLoading);
        Assert.True(model.CanRunActions);
        Assert.Equal("Collapsed", model.LoadingVisibility);
        Assert.Equal("Scan now", model.ScanButtonText);
        Assert.Equal("Scan completed. Created 2 new events.", model.StatusMessage);
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
        Assert.Contains("Loaded 1 events, 1 ports, 0 incidents, and 1 devices.", model.StatusMessage);
        Assert.Contains(nameof(DashboardShellViewModel.IsLoading), changed);
        Assert.Contains(nameof(DashboardShellViewModel.StatusMessage), changed);
        Assert.False(model.IsLoading);
    }

    /// <summary>
    /// Verifies stale broadcast and multicast rows already stored in the database are hidden from Devices.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_HidesStoredNoiseDevices()
    {
        var repository = new FakeRepository
        {
            Devices =
            [
                new NetworkDevice { IpAddress = "172.31.191.255", MacAddress = "FF:FF:FF:FF:FF:FF" },
                new NetworkDevice { IpAddress = "224.0.0.251", MacAddress = "01:00:5E:00:00:FB" },
                new NetworkDevice { Hostname = "office-laptop", IpAddress = "192.168.1.25", MacAddress = "02:AC:CE:55:20:25" }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        var device = Assert.Single(model.Devices);
        Assert.Equal("office-laptop", device.Name);
        Assert.Equal("192.168.1.25", device.IpAddress);
        Assert.Equal("Loaded 0 events, 0 ports, 0 incidents, and 1 devices.", model.StatusMessage);
    }

    /// <summary>
    /// Verifies dashboard device filtering preserves usable rows before and after stored noise rows.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_FiltersNoiseDevicesAfterUsableRows()
    {
        var repository = new FakeRepository
        {
            Devices =
            [
                new NetworkDevice { DeviceId = 1, Hostname = "office-laptop", IpAddress = "192.168.1.25", MacAddress = "02:AC:CE:55:20:25", DeviceTypeGuess = "Windows workstation", Notes = "Owned laptop" },
                new NetworkDevice { IpAddress = "224.0.0.251", MacAddress = "01:00:5E:00:00:FB" },
                new NetworkDevice { Hostname = "office-printer", IpAddress = "192.168.1.44", MacAddress = "02:AC:CE:55:44:44", Notes = "Shared printer" }
            ],
            Applications = [new AppIdentity { ApplicationId = 88, DisplayName = "Visual Studio", ProcessName = "devenv" }],
            Incidents =
            [
                new Incident { IncidentId = 88, Title = "Application-only event", MainApplicationId = 88, RiskLevel = RiskLevel.Medium, Status = IncidentStatus.Open },
                new Incident { IncidentId = 89, Title = "Device-only event", MainDeviceId = 1, RiskLevel = RiskLevel.Medium, Status = IncidentStatus.Open }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        Assert.Collection(
            model.Devices,
            device =>
            {
                Assert.Equal("office-laptop", device.Name);
                Assert.Equal("Windows workstation; Owned laptop", device.Detail);
            },
            device =>
            {
                Assert.Equal("office-printer", device.Name);
                Assert.Equal("Shared printer", device.Detail);
            });
        Assert.Collection(
            model.Incidents,
            incident => Assert.Equal("Visual Studio", incident.MainTarget),
            incident => Assert.Equal("office-laptop", incident.MainTarget));
        Assert.Equal("Loaded 0 events, 0 ports, 2 incidents, and 2 devices.", model.StatusMessage);
    }
    /// <summary>
    /// Verifies devices and applications are exposed as first-class dashboard inventories.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_LoadsDeviceAndApplicationInventories()
    {
        var repository = new FakeRepository
        {
            Devices =
            [
                new NetworkDevice
                {
                    Hostname = "living-room-tv",
                    IpAddress = "192.168.1.50",
                    MacAddress = "AA:BB:CC:DD:EE:50",
                    Vendor = "Example Devices",
                    DeviceTypeGuess = "Smart TV",
                    Notes = "Allowed media device",
                    TrustStatus = TrustStatus.Trusted,
                    RiskStatus = RiskStatus.Normal,
                    LastSeenUtc = new DateTimeOffset(2026, 6, 29, 12, 0, 0, TimeSpan.Zero)
                },
                new NetworkDevice { IpAddress = "192.168.1.77" }
            ],
            Applications =
            [
                new AppIdentity
                {
                    DisplayName = "Plex Media Server",
                    ProcessName = "plex",
                    Publisher = "Plex Inc.",
                    FilePath = "C:\\Program Files\\Plex\\plex.exe",
                    SignatureStatus = SignatureStatus.TrustedSigned,
                    TrustStatus = TrustStatus.Trusted,
                    LastSeenUtc = new DateTimeOffset(2026, 6, 29, 12, 30, 0, TimeSpan.Zero)
                },
                new AppIdentity
                {
                    DisplayName = string.Empty,
                    ProcessName = "worker",
                    SignatureStatus = SignatureStatus.Unsigned,
                    TrustStatus = TrustStatus.KnownWatched
                },
                new AppIdentity
                {
                    DisplayName = string.Empty,
                    ProcessName = string.Empty,
                    SignatureStatus = SignatureStatus.Unknown
                }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        Assert.Collection(
            model.Devices,
            device =>
            {
                Assert.Equal("living-room-tv", device.Name);
                Assert.Equal("192.168.1.50", device.IpAddress);
                Assert.Equal("AA:BB:CC:DD:EE:50", device.MacAddress);
                Assert.Equal("Example Devices", device.Vendor);
                Assert.Equal("Hostname", device.NameSource);
                Assert.Equal("Trusted", device.TrustStatus);
                Assert.Equal("Normal", device.RiskStatus);
                Assert.NotEqual("Not recorded", device.LastSeen);
                Assert.Equal("Smart TV; Allowed media device", device.Detail);
            },
            device =>
            {
                Assert.Equal("Device at 192.168.1.77", device.Name);
                Assert.Equal("IP address fallback", device.NameSource);
                Assert.Equal("MAC address unavailable", device.MacAddress);
                Assert.Equal("Vendor unavailable", device.Vendor);
                Assert.Equal("Not recorded", device.LastSeen);
                Assert.Equal("No extra device details recorded yet.", device.Detail);
            });
        Assert.Collection(
            model.Applications,
            application =>
            {
                Assert.Equal("Plex Media Server", application.Name);
                Assert.Equal("plex", application.ProcessName);
                Assert.Equal("Plex Inc.", application.Publisher);
                Assert.Equal("Trusted signature", application.SignatureStatus);
                Assert.Equal("Trusted", application.TrustStatus);
                Assert.NotEqual("Not recorded", application.LastSeen);
                Assert.Contains("Signed by Plex Inc.", application.Detail);
                Assert.Contains("C:\\Program Files\\Plex\\plex.exe", application.Detail);
            },
            application =>
            {
                Assert.Equal("worker", application.Name);
                Assert.Equal("worker", application.ProcessName);
                Assert.Equal("Publisher unavailable", application.Publisher);
                Assert.Equal("Unsigned executable", application.SignatureStatus);
                Assert.Equal("KnownWatched", application.TrustStatus);
                Assert.Equal("Not recorded", application.LastSeen);
            },
            application =>
            {
                Assert.Equal("Unknown application", application.Name);
                Assert.Equal("Process unavailable", application.ProcessName);
                Assert.Equal("Publisher unavailable", application.Publisher);
                Assert.Equal("Signature status unknown", application.SignatureStatus);
            });
    }

    /// <summary>
    /// Verifies device inventory rows explain state and recommended next action.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_LabelsDeviceInventoryStatesAndActions()
    {
        var repository = new FakeRepository
        {
            Devices =
            [
                new NetworkDevice
                {
                    Hostname = "trusted-tv",
                    IpAddress = "192.168.1.50",
                    TrustStatus = TrustStatus.Trusted,
                    FirstSeenUtc = DateTimeOffset.UtcNow.AddDays(-30),
                    LastConfirmedUtc = DateTimeOffset.UtcNow.AddMinutes(-30)
                },
                new NetworkDevice
                {
                    IpAddress = "192.168.1.77",
                    FirstSeenUtc = DateTimeOffset.UtcNow.AddDays(-30),
                    LastConfirmedUtc = null
                },
                new NetworkDevice
                {
                    Hostname = "guest-phone",
                    IpAddress = "192.168.1.78",
                    TrustStatus = TrustStatus.Guest,
                    FirstSeenUtc = DateTimeOffset.UtcNow.AddHours(-1),
                    LastConfirmedUtc = DateTimeOffset.UtcNow.AddMinutes(-5)
                },
                new NetworkDevice
                {
                    Hostname = "watched-camera",
                    IpAddress = "192.168.1.79",
                    TrustStatus = TrustStatus.KnownWatched,
                    FirstSeenUtc = DateTimeOffset.UtcNow.AddDays(-30),
                    LastConfirmedUtc = DateTimeOffset.UtcNow.AddDays(-8)
                },
                new NetworkDevice
                {
                    Hostname = "blocked-device",
                    IpAddress = "192.168.1.80",
                    TrustStatus = TrustStatus.Blocked,
                    FirstSeenUtc = DateTimeOffset.UtcNow.AddDays(-30),
                    LastConfirmedUtc = DateTimeOffset.UtcNow.AddDays(-2)
                }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        Assert.Collection(
            model.Devices,
            device =>
            {
                Assert.Equal("trusted-tv", device.Name);
                Assert.Equal("Recently confirmed", device.InventoryState);
                Assert.Equal("No action needed unless the device identity changes.", device.RecommendedAction);
                Assert.NotEqual("Not recorded", device.FirstSeen);
                Assert.NotEqual("Not confirmed", device.LastConfirmed);
            },
            device =>
            {
                Assert.Equal("Device at 192.168.1.77", device.Name);
                Assert.Equal("Unconfirmed", device.InventoryState);
                Assert.Equal("Assign an alias, then trust, watch, guest-mark, or block this device.", device.RecommendedAction);
                Assert.Equal("Not confirmed", device.LastConfirmed);
            },
            device =>
            {
                Assert.Equal("guest-phone", device.Name);
                Assert.Equal("New device", device.InventoryState);
                Assert.Equal("Keep guest access limited and review if it exposes services.", device.RecommendedAction);
            },
            device =>
            {
                Assert.Equal("watched-camera", device.Name);
                Assert.Equal("Not seen lately", device.InventoryState);
                Assert.Equal("Keep watching for repeated or unexpected activity.", device.RecommendedAction);
            },
            device =>
            {
                Assert.Equal("blocked-device", device.Name);
                Assert.Equal("Recently confirmed", device.InventoryState);
                Assert.Equal("Keep blocked; investigate if it reappears.", device.RecommendedAction);
            });
    }

    /// <summary>
    /// Verifies selected inventory rows expose a plain-English detail panel.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_SelectedInventoryRows_UpdateDetailPanels()
    {
        var repository = new FakeRepository
        {
            Devices =
            [
                new NetworkDevice
                {
                    Hostname = "office-laptop",
                    IpAddress = "192.168.1.25",
                    MacAddress = "02:AC:CE:55:20:25",
                    Vendor = "AccessWatch Lab",
                    DeviceTypeGuess = "Windows workstation",
                    TrustStatus = TrustStatus.KnownWatched,
                    RiskStatus = RiskStatus.Suspicious
                }
            ],
            Applications =
            [
                new AppIdentity
                {
                    DisplayName = "Visual Studio",
                    ProcessName = "devenv",
                    Publisher = "Microsoft Corporation",
                    SignatureStatus = SignatureStatus.TrustedSigned,
                    FilePath = @"C:\Program Files\Microsoft Visual Studio\Common7\IDE\devenv.exe",
                    TrustStatus = TrustStatus.Unknown
                }
            ]
        };
        var model = new DashboardShellViewModel(repository);
        var changed = new List<string?>();
        model.PropertyChanged += (_, args) => changed.Add(args.PropertyName);

        await model.LoadAsync(CancellationToken.None);
        model.SelectedDevice = Assert.Single(model.Devices);
        model.SelectedApplication = Assert.Single(model.Applications);

        Assert.Equal("office-laptop", model.SelectedDevice?.Name);
        Assert.Equal("Visual Studio", model.SelectedApplication?.Name);
        Assert.True(model.CanApplyDeviceTrustDecision);
        Assert.True(model.CanApplyApplicationTrustDecision);
        Assert.Contains("office-laptop", model.SelectedDeviceDetail);
        Assert.Contains("192.168.1.25", model.SelectedDeviceDetail);
        Assert.Contains("Visual Studio", model.SelectedApplicationDetail);
        Assert.Contains("Microsoft Corporation", model.SelectedApplicationDetail);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedDeviceDetail), changed);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedApplicationDetail), changed);

        changed.Clear();
        model.SelectedDevice = null;
        model.SelectedApplication = null;

        Assert.Contains("Select a device", model.SelectedDeviceDetail);
        Assert.Contains("Select an application", model.SelectedApplicationDetail);
        Assert.False(model.CanApplyDeviceTrustDecision);
        Assert.False(model.CanApplyApplicationTrustDecision);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedDeviceDetail), changed);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedApplicationDetail), changed);
    }

    /// <summary>
    /// Verifies device and application action buttons persist trust decisions and update the selected row.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_ApplyTrustDecision_UpdatesInventories()
    {
        var repository = new FakeRepository
        {
            Devices = [new NetworkDevice { DeviceId = 42, Hostname = "office-laptop", IpAddress = "192.168.1.25", MacAddress = "02:AC:CE:55:20:25" }],
            Applications = [new AppIdentity { ApplicationId = 84, DisplayName = "Visual Studio", ProcessName = "devenv" }]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);
        await model.ApplySelectedDeviceTrustDecisionAsync(TrustStatus.Trusted, CancellationToken.None);
        await model.ApplySelectedApplicationTrustDecisionAsync(TrustStatus.Blocked, CancellationToken.None);

        Assert.Equal("Trusted", Assert.Single(model.Devices).TrustStatus);
        Assert.Equal("Trusted", model.SelectedDevice?.TrustStatus);
        Assert.Equal("Blocked", Assert.Single(model.Applications).TrustStatus);
        Assert.Equal("Blocked", model.SelectedApplication?.TrustStatus);
        Assert.Contains("Blocked Visual Studio", model.StatusMessage);
        Assert.Collection(
            repository.TrustDecisions,
            decision =>
            {
                Assert.Equal("Device", decision.TargetType);
                Assert.Equal(42, decision.TargetId);
                Assert.Equal(TrustStatus.Trusted, decision.Decision);
            },
            decision =>
            {
                Assert.Equal("Application", decision.TargetType);
                Assert.Equal(84, decision.TargetId);
                Assert.Equal(TrustStatus.Blocked, decision.Decision);
            });
    }

    /// <summary>
    /// Verifies device aliases are saved, shown as the device name, and can be cleared back to the discovered name.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_SaveSelectedDeviceAliasAsync_SavesAndClearsAlias()
    {
        var repository = new FakeRepository
        {
            Devices = [new NetworkDevice { DeviceId = 100, Hostname = "printer-den", IpAddress = "192.168.1.44", MacAddress = "02:AC:CE:55:44:44" }]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);
        model.SelectedDeviceAlias = null!;
        Assert.Equal(string.Empty, model.SelectedDeviceAlias);

        model.SelectedDeviceAlias = "  Office Printer  ";
        await model.SaveSelectedDeviceAliasAsync(CancellationToken.None);

        Assert.Equal("Office Printer", model.SelectedDeviceAlias);
        Assert.Equal("Office Printer", model.SelectedDevice?.Name);
        Assert.Equal("Office Printer", Assert.Single(model.Devices).UserAlias);
        Assert.Equal((100L, "Office Printer"), Assert.Single(repository.AliasUpdates));
        Assert.Equal("Saved alias Office Printer for 192.168.1.44.", model.StatusMessage);

        await model.ClearSelectedDeviceAliasAsync(CancellationToken.None);

        Assert.Equal(string.Empty, model.SelectedDeviceAlias);
        Assert.Equal("printer-den", model.SelectedDevice?.Name);
        Assert.Equal(string.Empty, Assert.Single(model.Devices).UserAlias);
        Assert.Equal((100L, null), repository.AliasUpdates[1]);
        Assert.Equal("Cleared alias for 192.168.1.44.", model.StatusMessage);
    }

    /// <summary>
    /// Verifies clearing an alias falls back to an honest IP-based label when discovery only found an IP address.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_ClearSelectedDeviceAliasAsync_UsesIpFallbackWhenNoResolvedName()
    {
        var repository = new FakeRepository
        {
            Devices =
            [
                new NetworkDevice
                {
                    DeviceId = 101,
                    UserAlias = "Temporary Laptop",
                    Hostname = "192.168.1.88",
                    IpAddress = "192.168.1.88",
                    MacAddress = "02:AC:CE:55:88:88"
                }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        Assert.Equal("Temporary Laptop", model.SelectedDevice?.Name);
        Assert.Equal("User alias", model.SelectedDevice?.NameSource);

        await model.ClearSelectedDeviceAliasAsync(CancellationToken.None);

        Assert.Equal("Device at 192.168.1.88", model.SelectedDevice?.Name);
        Assert.Equal("IP address fallback", model.SelectedDevice?.NameSource);
        Assert.Equal((101L, null), Assert.Single(repository.AliasUpdates));
    }
    /// <summary>
    /// Verifies alias saves require a selected device.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_SaveSelectedDeviceAliasAsync_RequiresSelection()
    {
        var model = new DashboardShellViewModel(new FakeRepository());

        await model.SaveSelectedDeviceAliasAsync(CancellationToken.None);

        Assert.Equal("Select a device before saving an alias.", model.StatusMessage);
    }

    /// <summary>
    /// Verifies watch and reset trust decisions update the dashboard status text.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_ApplyTrustDecision_UsesDecisionStatusText()
    {
        var repository = new FakeRepository
        {
            Devices = [new NetworkDevice { DeviceId = 43, Hostname = "office-laptop", IpAddress = "192.168.1.25", MacAddress = "02:AC:CE:55:20:25" }],
            Applications = [new AppIdentity { ApplicationId = 85, DisplayName = "Visual Studio", ProcessName = "devenv" }]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);
        await model.ApplySelectedDeviceTrustDecisionAsync(TrustStatus.KnownWatched, CancellationToken.None);

        Assert.Contains("Watching office-laptop", model.StatusMessage);

        await model.ApplySelectedDeviceTrustDecisionAsync(TrustStatus.Guest, CancellationToken.None);

        Assert.Contains("Marked guest office-laptop", model.StatusMessage);

        await model.ApplySelectedApplicationTrustDecisionAsync(TrustStatus.Unknown, CancellationToken.None);

        Assert.Contains("Updated Visual Studio", model.StatusMessage);
    }

    /// <summary>
    /// Verifies action requests explain when there is no selected row to update.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_ApplyTrustDecision_RequiresSelection()
    {
        var model = new DashboardShellViewModel(new FakeRepository());

        await model.ApplySelectedDeviceTrustDecisionAsync(TrustStatus.Trusted, CancellationToken.None);
        Assert.Equal("Select a device before applying a trust decision.", model.StatusMessage);

        await model.ApplySelectedApplicationTrustDecisionAsync(TrustStatus.Trusted, CancellationToken.None);
        Assert.Equal("Select an application before applying a trust decision.", model.StatusMessage);
    }

    /// <summary>
    /// Verifies weak device-name values are not presented as real device names.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_HidesWeakDeviceNames()
    {
        var repository = new FakeRepository
        {
            Devices =
            [
                new NetworkDevice { Hostname = "192.168.1.30", IpAddress = "192.168.1.30", MacAddress = "02:AC:CE:55:30:30", DeviceTypeGuess = "Phone" },
                new NetworkDevice { Hostname = "printer:raw", IpAddress = "192.168.1.31", MacAddress = "02:AC:CE:55:30:31", Vendor = "Contoso" },
                new NetworkDevice { Hostname = "printer-den", IpAddress = "192.168.1.32", MacAddress = "02:AC:CE:55:30:32" },
                new NetworkDevice { UserAlias = "Kitchen speaker", Hostname = "192.168.1.33", IpAddress = "192.168.1.33", MacAddress = "02:AC:CE:55:30:33" }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        Assert.Collection(
            model.Devices,
            device =>
            {
                Assert.Equal("Phone at 192.168.1.30", device.Name);
                Assert.Equal("Device type", device.NameSource);
            },
            device =>
            {
                Assert.Equal("Contoso device at 192.168.1.31", device.Name);
                Assert.Equal("Vendor", device.NameSource);
            },
            device =>
            {
                Assert.Equal("printer-den", device.Name);
                Assert.Equal("Hostname", device.NameSource);
            },
            device =>
            {
                Assert.Equal("Kitchen speaker", device.Name);
                Assert.Equal("User alias", device.NameSource);
            });
    }

    /// <summary>
    /// Verifies Settings exposes the running protection and AI review configuration.
    /// </summary>
    [Fact]
    public void DashboardShellViewModel_Settings_AppliesRunningConfiguration()
    {
        var settings = new AccessWatchSettings
        {
            ProtectionMode = ProtectionMode.Strict,
            AiMode = AiMode.Off
        };
        var model = new DashboardShellViewModel(new FakeRepository(), settings: settings);
        var changed = new List<string?>();
        model.PropertyChanged += (_, args) => changed.Add(args.PropertyName);

        Assert.Equal("Strict", model.SelectedProtectionMode);
        Assert.Equal("Off", model.SelectedAiMode);
        Assert.Equal("Strict", model.CurrentProtectionMode);
        Assert.Equal("Off", model.CurrentAiMode);
        Assert.Equal("Settings match the running configuration.", model.SettingsStatus);
        Assert.Equal(["Quiet", "Balanced", "Strict", "Lockdown"], model.ProtectionModeOptions.Select(option => option.Value));
        Assert.Equal(["Off", "ManualChatGptCopy", "LocalAi", "OpenAiApi"], model.AiModeOptions.Select(option => option.Value));

        model.SelectedProtectionMode = "Lockdown";
        model.SelectedAiMode = "OpenAiApi";
        model.ApplySettings();

        Assert.Equal(ProtectionMode.Lockdown, settings.ProtectionMode);
        Assert.Equal(AiMode.OpenAiApi, settings.AiMode);
        Assert.Equal("Lockdown", model.CurrentProtectionMode);
        Assert.Equal("OpenAiApi", model.CurrentAiMode);
        Assert.Contains("Settings applied", model.SettingsStatus);
        Assert.Contains(nameof(DashboardShellViewModel.CurrentProtectionMode), changed);
        Assert.Contains(nameof(DashboardShellViewModel.CurrentAiMode), changed);

        changed.Clear();
        model.SelectedProtectionMode = null!;
        model.SelectedAiMode = null!;

        Assert.Equal("Lockdown", model.SelectedProtectionMode);
        Assert.Equal("OpenAiApi", model.SelectedAiMode);

        model.SelectedProtectionMode = "Strict";
        model.SelectedAiMode = "Off";
        model.ResetSettingsSelections();

        Assert.Equal("Lockdown", model.SelectedProtectionMode);
        Assert.Equal("OpenAiApi", model.SelectedAiMode);
        Assert.Contains("match the running configuration", model.SettingsStatus);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedProtectionMode), changed);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedAiMode), changed);
    }


    /// <summary>
    /// Verifies ports and incidents are exposed as first-class dashboard inventories.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_LoadsPortAndIncidentInventories()
    {
        var application = new AppIdentity
        {
            ApplicationId = 7,
            DisplayName = "Visual Studio",
            ProcessName = "devenv",
            Publisher = "Microsoft",
            SignatureStatus = SignatureStatus.TrustedSigned,
            FilePath = "C:\\Program Files\\Microsoft Visual Studio\\devenv.exe"
        };
        var repository = new FakeRepository
        {
            Devices = [new NetworkDevice { DeviceId = 5, Hostname = "office-laptop", IpAddress = "192.168.1.25" }],
            Applications = [application],
            Ports =
            [
                new ListeningPort
                {
                    PortNumber = 9443,
                    Protocol = "TCP",
                    LocalAddress = "0.0.0.0",
                    Reachability = PortReachability.NetworkReachable,
                    RiskStatus = RiskStatus.HighRisk,
                    TrustStatus = TrustStatus.Unknown,
                    FirstSeenUtc = new DateTimeOffset(2026, 6, 29, 11, 0, 0, TimeSpan.Zero),
                    LastSeenUtc = new DateTimeOffset(2026, 6, 29, 11, 15, 0, TimeSpan.Zero),
                    Application = application
                },
                new ListeningPort
                {
                    PortNumber = 65535,
                    Protocol = "UDP",
                    LocalAddress = "127.0.0.1",
                    Reachability = PortReachability.LocalOnly,
                    RiskStatus = RiskStatus.Normal
                },
                new ListeningPort
                {
                    PortNumber = 139,
                    Protocol = "TCP",
                    LocalAddress = "172.22.96.1",
                    Reachability = PortReachability.NetworkReachable,
                    RiskStatus = RiskStatus.HighRisk
                },
                new ListeningPort
                {
                    PortNumber = 80,
                    Protocol = "TCP",
                    LocalAddress = "127.0.0.1",
                    Reachability = PortReachability.LocalOnly,
                    RiskStatus = RiskStatus.Normal,
                    Application = application
                }
            ],
            Incidents =
            [
                new Incident
                {
                    IncidentId = 11,
                    Title = "Camera activated",
                    Summary = "Visual Studio activated a camera-related capability on 192.168.1.25 from AA:BB:CC:DD:EE:FF.",
                    MainDeviceId = 5,
                    MainApplicationId = 7,
                    RiskLevel = RiskLevel.High,
                    Status = IncidentStatus.Open,
                    EventCount = 2,
                    StartedUtc = new DateTimeOffset(2026, 6, 29, 11, 2, 0, TimeSpan.Zero),
                    LastUpdatedUtc = new DateTimeOffset(2026, 6, 29, 11, 5, 0, TimeSpan.Zero)
                },
                new Incident { RiskLevel = RiskLevel.Medium, Status = IncidentStatus.Watching }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        Assert.Collection(
            model.Ports,
            port =>
            {
                Assert.Equal("TCP 0.0.0.0:9443", port.Endpoint);
                Assert.Equal("Visual Studio", port.ApplicationName);
                Assert.Equal("NetworkReachable", port.Reachability);
                Assert.Equal("HighRisk", port.RiskStatus);
                Assert.Equal("Unknown", port.TrustStatus);
                Assert.NotEqual("Not recorded", port.FirstSeen);
                Assert.NotEqual("Not recorded", port.LastSeen);
                Assert.Contains("Signed by Microsoft", port.Detail);
                Assert.Equal(9443, port.PortNumber);
                Assert.Equal("0.0.0.0", port.LocalAddress);
                Assert.Contains("Alternate HTTPS", port.Meaning);
                Assert.Contains("all network adapters", port.Exposure);
                Assert.Contains("Confirm this application", port.SuggestedAction);
                Assert.Contains("Next step:", port.Investigation);
            },
            port =>
            {
                Assert.Equal("UDP 127.0.0.1:65535", port.Endpoint);
                Assert.Equal("Unknown application", port.ApplicationName);
                Assert.Equal("LocalOnly", port.Reachability);
                Assert.Equal("Not recorded", port.FirstSeen);
                Assert.Equal("Application identity unavailable", port.Detail);
                Assert.Contains("No common profile", port.Meaning);
                Assert.Contains("Local-only listener", port.Exposure);
                Assert.Contains("Run a fresh scan", port.SuggestedAction);
            },
            port =>
            {
                Assert.Equal("TCP 172.22.96.1:139", port.Endpoint);
                Assert.Contains("NetBIOS", port.Meaning);
                Assert.Contains("private address 172.22.96.1", port.Exposure);
                Assert.Contains("Run a fresh scan", port.SuggestedAction);
            },
            port =>
            {
                Assert.Equal("TCP 127.0.0.1:80", port.Endpoint);
                Assert.Contains("HTTP web service", port.Meaning);
                Assert.Contains("Local-only listener", port.Exposure);
                Assert.Contains("No action needed", port.SuggestedAction);
            });
        Assert.Same(model.Ports[0], model.SelectedPort);
        Assert.Contains("TCP 0.0.0.0:9443", model.SelectedPortDetail);
        Assert.Contains("Visual Studio", model.SelectedPortDetail);
        Assert.True(model.CanInvestigateSelectedPort);
        Assert.Equal("Investigate port", model.PortInvestigationButtonText);
        Assert.Contains("Click Investigate port", model.SelectedPortInvestigation);
        Assert.Collection(
            model.Incidents,
            incident =>
            {
                Assert.Equal("Camera activated", incident.Title);
                Assert.Equal("High", incident.RiskLevel);
                Assert.Equal("Open", incident.Status);
                Assert.Equal(2, incident.EventCount);
                Assert.Equal("Visual Studio on office-laptop", incident.MainTarget);
                Assert.NotEqual("Not recorded", incident.Started);
                Assert.NotEqual("Not recorded", incident.LastUpdated);
                Assert.Equal(11, incident.IncidentId);
                Assert.Equal(5, incident.MainDeviceId);
                Assert.Equal(7, incident.MainApplicationId);
                Assert.Equal(RiskLevel.High, incident.RawRiskLevel);
                Assert.Equal(IncidentStatus.Open, incident.RawStatus);
                Assert.Equal("Visual Studio activated a camera-related capability on 192.168.1.25 from AA:BB:CC:DD:EE:FF.", incident.Summary);
            },
            incident =>
            {
                Assert.Equal("Untitled incident", incident.Title);
                Assert.Equal("Target unavailable", incident.MainTarget);
                Assert.Equal("No incident summary recorded yet.", incident.Summary);
            });
        Assert.Same(model.Incidents[0], model.SelectedIncident);
        Assert.Contains("Camera activated", model.SelectedIncidentDetail);
        Assert.Contains("Why:", model.SelectedIncidentExplanation);
        Assert.Contains("Visual Studio on office-laptop", model.SelectedIncidentExplanation);
        Assert.True(model.CanApplyIncidentAction);
        Assert.False(model.CanReviewIncidentWithAi);
        Assert.False(model.HasIncidentAiReview);
        Assert.Contains("Loaded 0 events, 4 ports, 2 incidents, and 1 devices.", model.StatusMessage);

        model.InvestigateSelectedPort();
        Assert.Contains("Investigation ready for TCP 0.0.0.0:9443", model.StatusMessage);
        Assert.Equal("Refresh investigation", model.PortInvestigationButtonText);
        Assert.Contains("Investigation report", model.SelectedPortInvestigation);
        Assert.Contains("Endpoint: TCP 0.0.0.0:9443", model.SelectedPortInvestigation);
        Assert.Contains("What to check:", model.SelectedPortInvestigation);
        Assert.Contains("Recommended decision: Confirm this application", model.SelectedPortInvestigation);

        model.SelectedPort = model.Ports[1];
        Assert.Equal("Investigate port", model.PortInvestigationButtonText);
        Assert.Contains("Click Investigate port", model.SelectedPortInvestigation);
    }

    /// <summary>
    /// Verifies port investigation guidance explains the empty-selection state.
    /// </summary>
    [Fact]
    public void DashboardShellViewModel_InvestigateSelectedPortWithoutSelection_ShowsSelectionPrompt()
    {
        var model = new DashboardShellViewModel();

        Assert.False(model.CanInvestigateSelectedPort);
        Assert.Equal("Investigate port", model.PortInvestigationButtonText);
        Assert.Contains("Select a port", model.SelectedPortInvestigation);

        model.InvestigateSelectedPort();

        Assert.Equal("Investigate port", model.PortInvestigationButtonText);
        Assert.Contains("Select a port before investigating it.", model.StatusMessage);
    }
    /// <summary>
    /// Verifies selected incident actions persist state and create rule suggestions.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_IncidentActions_PersistStatusAndRuleSuggestion()
    {
        var repository = new FakeRepository
        {
            Incidents =
            [
                new Incident
                {
                    IncidentId = 55,
                    Title = "Microphone activated",
                    Summary = "Skype accessed the microphone.",
                    MainDeviceId = 4,
                    MainApplicationId = 9,
                    RiskLevel = RiskLevel.Medium,
                    Status = IncidentStatus.Open,
                    EventCount = 4,
                    StartedUtc = new DateTimeOffset(2026, 6, 29, 13, 0, 0, TimeSpan.Zero),
                    LastUpdatedUtc = new DateTimeOffset(2026, 6, 29, 13, 5, 0, TimeSpan.Zero)
                }
            ]
        };
        var model = new DashboardShellViewModel(repository);
        var changed = new List<string?>();
        model.PropertyChanged += (_, args) => changed.Add(args.PropertyName);

        await model.LoadAsync(CancellationToken.None);

        Assert.True(model.CanApplyIncidentAction);
        Assert.False(model.HasIncidentRuleSuggestion);

        await model.CreateRuleFromSelectedIncidentAsync(CancellationToken.None);

        var mediumRule = Assert.Single(repository.RuleUpserts);
        Assert.False(mediumRule.Enabled);
        Assert.Equal(NotificationAction.SoftNotify, mediumRule.Action);
        Assert.Contains("Skype accessed the microphone", mediumRule.Description);
        Assert.True(model.HasIncidentRuleSuggestion);
        Assert.Contains("IncidentSuggestion", model.SelectedIncidentRuleSuggestion);
        using (var document = JsonDocument.Parse(model.SelectedIncidentRuleSuggestion))
        {
            Assert.Equal(55, document.RootElement.GetProperty("incidentId").GetInt64());
            Assert.Equal(9, document.RootElement.GetProperty("mainApplicationId").GetInt64());
            Assert.Equal("Medium", document.RootElement.GetProperty("riskLevel").GetString());
        }

        await model.WatchSelectedIncidentAsync(CancellationToken.None);

        Assert.Equal(IncidentStatus.Watching, repository.IncidentUpserts[0].Status);
        Assert.Equal("Watching", model.SelectedIncident!.Status);
        Assert.Contains("Watching incident Microphone activated", model.StatusMessage);

        await model.ResolveSelectedIncidentAsync(CancellationToken.None);

        Assert.Equal(IncidentStatus.Resolved, repository.IncidentUpserts[1].Status);
        Assert.NotNull(repository.IncidentUpserts[1].ResolvedUtc);
        Assert.Equal("Resolved", model.SelectedIncident!.Status);
        Assert.Contains("marked resolved", model.SelectedIncidentExplanation);

        await model.EscalateSelectedIncidentAsync(CancellationToken.None);

        Assert.Equal(RiskLevel.Critical, repository.IncidentUpserts[2].RiskLevel);
        Assert.Equal(IncidentStatus.Open, repository.IncidentUpserts[2].Status);
        Assert.Equal("Critical", model.SelectedIncident!.RiskLevel);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedIncidentRuleSuggestion), changed);
        Assert.Contains(nameof(DashboardShellViewModel.HasIncidentRuleSuggestion), changed);

        await model.CreateRuleFromSelectedIncidentAsync(CancellationToken.None);

        Assert.Equal(2, repository.RuleUpserts.Count);
        Assert.Equal(NotificationAction.AskBeforeAllow, repository.RuleUpserts[1].Action);
        Assert.Contains("Critical", model.SelectedIncidentRuleSuggestion);
    }

    /// <summary>
    /// Verifies selected incidents can produce privacy-safe ChatGPT subscription review briefs.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_CreateSelectedIncidentAiReview_BuildsRedactedChatGptBrief()
    {
        var repository = new FakeRepository
        {
            Incidents =
            [
                new Incident
                {
                    IncidentId = 55,
                    Title = "Microphone activated",
                    Summary = "Skype accessed the microphone from 10.0.0.50 with MAC 02:AC:CE:55:10:01.",
                    MainDeviceId = 4,
                    MainApplicationId = 9,
                    RiskLevel = RiskLevel.Medium,
                    Status = IncidentStatus.Watching,
                    EventCount = 4
                }
            ]
        };
        var model = new DashboardShellViewModel(repository, aiHandoffService: new ManualAiHandoffService());
        var changed = new List<string?>();
        model.PropertyChanged += (_, args) => changed.Add(args.PropertyName);

        await model.LoadAsync(CancellationToken.None);
        model.CreateSelectedIncidentAiReview();

        Assert.True(model.HasIncidentAiReview);
        Assert.DoesNotContain("10.0.0.50", model.SelectedIncidentAiReview);
        Assert.DoesNotContain("02:AC:CE:55:10:01", model.SelectedIncidentAiReview);
        Assert.Contains("AccessWatch AI review workspace", model.SelectedIncidentAiReview);
        Assert.Contains("Recommended AccessWatch action: Watch", model.SelectedIncidentAiReview);
        Assert.Contains("Evidence checklist:", model.SelectedIncidentAiReview);
        Assert.Contains("Action shortcuts in AccessWatch:", model.SelectedIncidentAiReview);
        Assert.Contains("ChatGPT prompt:", model.SelectedIncidentAiReview);
        Assert.Contains("Redacted incident context:", model.SelectedIncidentAiReview);
        Assert.Contains("Microphone activated", model.SelectedIncidentAiReview);
        Assert.Contains("[ip-address]", model.SelectedIncidentAiReview);
        Assert.Contains("[mac-address]", model.SelectedIncidentAiReview);
        Assert.Contains("Prepared AI review brief", model.StatusMessage);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedIncidentAiReview), changed);
        Assert.Contains(nameof(DashboardShellViewModel.HasIncidentAiReview), changed);

        model.MarkIncidentChatGptCopied();
        Assert.Equal("Copied the redacted review brief. Paste it into ChatGPT when you are ready.", model.StatusMessage);
    }

    /// <summary>
    /// Verifies the AI review workspace recommends the matching AccessWatch action for each incident state.
    /// </summary>
    [Theory]
    [InlineData(RiskLevel.Critical, IncidentStatus.Open, "Target unavailable", "Recommended AccessWatch action: Escalate", "Identify the app or device")]
    [InlineData(RiskLevel.High, IncidentStatus.Open, "Visual Studio on office-laptop", "Recommended AccessWatch action: Escalate", "Confirm Visual Studio on office-laptop")]
    [InlineData(RiskLevel.Medium, IncidentStatus.Open, "Visual Studio on office-laptop", "Recommended AccessWatch action: Watch", "Confirm Visual Studio on office-laptop")]
    [InlineData(RiskLevel.Low, IncidentStatus.Open, "Visual Studio on office-laptop", "Recommended AccessWatch action: Resolve or Watch", "Confirm Visual Studio on office-laptop")]
    [InlineData(RiskLevel.Critical, IncidentStatus.Resolved, "Visual Studio on office-laptop", "Recommended AccessWatch action: Resolve", "Confirm Visual Studio on office-laptop")]
    public void DashboardShellViewModel_CreateSelectedIncidentAiReview_RecommendsAccessWatchAction(
        RiskLevel riskLevel,
        IncidentStatus status,
        string target,
        string expectedAction,
        string expectedChecklist)
    {
        var model = new DashboardShellViewModel(new FakeRepository(), aiHandoffService: new ManualAiHandoffService())
        {
            SelectedIncident = new DashboardIncidentItemViewModel(
                500,
                null,
                null,
                riskLevel,
                status,
                DateTimeOffset.UnixEpoch,
                DateTimeOffset.UnixEpoch,
                "Review candidate",
                riskLevel.ToString(),
                status.ToString(),
                2,
                target,
                "Not recorded",
                "Not recorded",
                "Safe summary.")
        };

        model.CreateSelectedIncidentAiReview();

        Assert.Contains(expectedAction, model.SelectedIncidentAiReview);
        Assert.Contains(expectedChecklist, model.SelectedIncidentAiReview);
        Assert.Contains("Use Resolve when confirmed expected", model.SelectedIncidentAiReview);
        Assert.Contains("recommend Resolve/Watch/Escalate/Create rule", model.SelectedIncidentAiReview);
    }
    /// <summary>
    /// Verifies AI review gives actionable status when no incident or AI mode is available.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_CreateSelectedIncidentAiReview_ExplainsUnavailableStates()
    {
        var model = new DashboardShellViewModel(new FakeRepository(), aiHandoffService: new ManualAiHandoffService());

        model.CreateSelectedIncidentAiReview();

        Assert.Equal("Select an incident to see its target, timeline, and AI review context.", model.SelectedIncidentDetail);
        Assert.Equal("Select an incident to see why AccessWatch grouped it and what to verify next.", model.SelectedIncidentExplanation);
        Assert.Equal("Select a port to see the owning application, reachability, risk, and timing context.", model.SelectedPortDetail);
        Assert.False(model.CanApplyIncidentAction);
        Assert.False(model.CanReviewIncidentWithAi);
        await model.ResolveSelectedIncidentAsync(CancellationToken.None);
        Assert.Equal("Select an incident before applying an incident action.", model.StatusMessage);
        await model.CreateRuleFromSelectedIncidentAsync(CancellationToken.None);
        Assert.Equal("Select an incident before creating a rule suggestion.", model.StatusMessage);
        model.CreateSelectedIncidentAiReview();
        Assert.Equal("Select an incident before starting AI review.", model.StatusMessage);
        model.MarkIncidentChatGptCopied();
        Assert.Equal("Review the incident with AI before copying it for ChatGPT.", model.StatusMessage);

        var noServiceModel = new DashboardShellViewModel();
        noServiceModel.SelectedIncident = new DashboardIncidentItemViewModel(
            2,
            null,
            null,
            RiskLevel.Low,
            IncidentStatus.Open,
            DateTimeOffset.UnixEpoch,
            DateTimeOffset.UnixEpoch,
            "Port opened",
            "Low",
            "Open",
            1,
            "Target unavailable",
            "Not recorded",
            "Not recorded",
            "No sensitive details.");

        Assert.False(noServiceModel.CanApplyIncidentAction);
        Assert.False(noServiceModel.CanReviewIncidentWithAi);
        await noServiceModel.ResolveSelectedIncidentAsync(CancellationToken.None);
        Assert.Equal("Incident actions are not connected for this dashboard session.", noServiceModel.StatusMessage);
        await noServiceModel.CreateRuleFromSelectedIncidentAsync(CancellationToken.None);
        Assert.Equal("Rule suggestions are not connected for this dashboard session.", noServiceModel.StatusMessage);
        noServiceModel.CreateSelectedIncidentAiReview();
        Assert.Equal("AI review is not connected for this dashboard session.", noServiceModel.StatusMessage);

        var disabledSettings = new AccessWatchSettings { AiMode = AiMode.Off };
        var disabledModel = new DashboardShellViewModel(new FakeRepository(), settings: disabledSettings, aiHandoffService: new ManualAiHandoffService());
        disabledModel.SelectedIncident = new DashboardIncidentItemViewModel(
            1,
            null,
            null,
            RiskLevel.Low,
            IncidentStatus.Open,
            DateTimeOffset.UnixEpoch,
            DateTimeOffset.UnixEpoch,
            "Port opened",
            "Low",
            "Open",
            1,
            "Target unavailable",
            "Not recorded",
            "Not recorded",
            "No sensitive details.");

        Assert.Contains("worth watching", disabledModel.SelectedIncidentExplanation);
        Assert.Contains("Verify which app or device", disabledModel.SelectedIncidentExplanation);
        Assert.False(disabledModel.CanReviewIncidentWithAi);
        disabledModel.CreateSelectedIncidentAiReview();

        Assert.Equal("Turn on AI review in Settings before reviewing with ChatGPT.", disabledModel.StatusMessage);
    }

    /// <summary>
    /// Verifies event activity explains the owning application and the reason AccessWatch flagged it.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_ExplainsEventApplicationAndReason()
    {
        var repository = new FakeRepository
        {
            Devices = [new NetworkDevice { DeviceId = 7, Hostname = "office-printer", IpAddress = "192.168.1.44" }],
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
                    SourceDeviceId = 7,
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
        Assert.Contains("Device office-printer", activity.Detail);
        Assert.Contains("NetworkReachable", activity.Detail);
        Assert.Equal("Other devices on your network may be able to connect to this service.", activity.WhyItMatters);
        Assert.Equal("Confirm the app is expected before trusting it.", activity.SuggestedAction);
    }
    /// <summary>
    /// Verifies event detail device names are shown when the stored device row is not available.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_UsesEventDetailDeviceNameWhenDeviceJoinIsMissing()
    {
        var repository = new FakeRepository
        {
            Applications = [new AppIdentity { ApplicationId = 12, DisplayName = "Visual Studio", ProcessName = "devenv" }],
            Events =
            [
                new NetworkEvent
                {
                    ApplicationId = 12,
                    EventType = "CameraActivated",
                    Protocol = "Local",
                    Direction = "SensorAccess",
                    RiskLevel = RiskLevel.High,
                    Summary = "Visual Studio started using the camera.",
                    DetailsJson = "{ \"whatHappened\": \"Visual Studio activated the camera.\", \"app\": \"Visual Studio\", \"processName\": \"devenv\", \"deviceName\": \"office-laptop\", \"reachability\": \"Local sensor access\", \"whyItMatters\": \"Camera activation is sensitive.\", \"suggestedAction\": \"Confirm this was expected.\" }"
                }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        var activity = Assert.Single(model.RecentActivity);
        Assert.Contains("Device office-laptop", activity.Detail);
        Assert.Contains("Visual Studio activated the camera.", activity.Detail);
    }
    /// <summary>
    /// Verifies sensor events describe the app and device without showing a fake network endpoint.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_ExplainsSensorEventsWithoutEndpoint()
    {
        var repository = new FakeRepository
        {
            Devices = [new NetworkDevice { DeviceId = 9, Hostname = "office-laptop", IpAddress = "192.168.1.25" }],
            Applications = [new AppIdentity { ApplicationId = 12, DisplayName = "Visual Studio", ProcessName = "devenv" }],
            Events =
            [
                new NetworkEvent
                {
                    ApplicationId = 12,
                    SourceDeviceId = 9,
                    EventType = "CameraActivated",
                    Protocol = "Local",
                    Direction = "SensorAccess",
                    RiskLevel = RiskLevel.High,
                    Summary = "Visual Studio started using the camera.",
                    DetailsJson = "{ \"whatHappened\": \"Visual Studio activated the camera.\", \"app\": \"Visual Studio\", \"processName\": \"devenv\", \"reachability\": \"Local sensor access\", \"whyItMatters\": \"Camera activation is sensitive.\", \"suggestedAction\": \"Confirm this was expected.\" }"
                }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        var activity = Assert.Single(model.RecentActivity);
        Assert.Equal("Visual Studio", activity.ApplicationName);
        Assert.Contains("Device office-laptop", activity.Detail);
        Assert.Contains("Visual Studio activated the camera.", activity.Detail);
        Assert.Contains("Local sensor access", activity.Detail);
        Assert.DoesNotContain("local:n/a", activity.Detail);
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
        Assert.Equal("Device at 192.168.1.10", activity.ApplicationName);
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
        var missingEndpointActivity = Assert.Single(eventModel.RecentActivity);
        Assert.Contains("A new listening TCP port appeared.", missingEndpointActivity.Detail);
        Assert.DoesNotContain("local:n/a", missingEndpointActivity.Detail);

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
    /// Verifies simulator requests report when no simulator function is connected.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_RunSimulationAsyncWithoutSimulator_ShowsDisconnectedState()
    {
        var model = new DashboardShellViewModel(new FakeRepository());

        await model.RunSimulationAsync(CancellationToken.None);

        Assert.Equal("Event simulator is not connected yet.", model.StatusMessage);
    }

    /// <summary>
    /// Verifies simulator work exposes button and progress state while generating an event.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_RunSimulationAsync_ShowsSimulationProgressState()
    {
        var releaseSimulation = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var repository = new FakeRepository();
        var model = new DashboardShellViewModel(
            repository,
            null,
            async _ =>
            {
                await releaseSimulation.Task;
                return 1;
            });

        var simulationTask = model.RunSimulationAsync(CancellationToken.None);

        Assert.True(model.IsLoading);
        Assert.False(model.CanRunActions);
        Assert.Equal("Visible", model.LoadingVisibility);
        Assert.Equal("Scan now", model.ScanButtonText);
        Assert.Equal("Simulating...", model.SimulateButtonText);
        Assert.Equal("Refresh", model.RefreshButtonText);
        Assert.Equal("Creating a simulated network event...", model.ProgressMessage);
        Assert.Equal("Creating a simulated network event...", model.StatusMessage);

        releaseSimulation.SetResult();
        await simulationTask;

        Assert.False(model.IsLoading);
        Assert.True(model.CanRunActions);
        Assert.Equal("Collapsed", model.LoadingVisibility);
        Assert.Equal("Simulate event", model.SimulateButtonText);
        Assert.Equal("Simulation completed. Created 1 event.", model.StatusMessage);
    }

    /// <summary>
    /// Verifies simulator requests reload dashboard data after creating an event.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_RunSimulationAsync_ReloadsData()
    {
        var repository = new FakeRepository
        {
            Events = [new NetworkEvent { EventType = "NewListeningPort", RiskLevel = RiskLevel.High, Summary = "Simulated event.", DestinationPort = 9443 }]
        };
        var simulationCount = 0;
        var model = new DashboardShellViewModel(
            repository,
            null,
            _ =>
            {
                simulationCount++;
                return Task.FromResult(1);
            });

        await model.RunSimulationAsync(CancellationToken.None);

        Assert.Equal(1, simulationCount);
        Assert.Single(model.RecentActivity);
        Assert.Equal("Simulation completed. Created 1 event.", model.StatusMessage);
        Assert.False(model.IsLoading);
    }

    /// <summary>
    /// Verifies simulator failures are shown as dashboard status instead of crashing the window.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_RunSimulationAsync_ShowsSimulationFailure()
    {
        var model = new DashboardShellViewModel(new FakeRepository(), null, _ => throw new InvalidOperationException("simulator failed"));

        await model.RunSimulationAsync(CancellationToken.None);

        Assert.Contains("simulator failed", model.StatusMessage);
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

    private static string FindMainWindowXaml()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "src", "AccessWatch.App", "MainWindow.xaml");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException("Could not locate src/AccessWatch.App/MainWindow.xaml from the test output folder.");
    }

    private sealed class FakeRepository : IAccessWatchRepository
    {
        public IReadOnlyList<NetworkDevice> Devices { get; init; } = [];

        public IReadOnlyList<AppIdentity> Applications { get; init; } = [];

        public IReadOnlyList<ListeningPort> Ports { get; init; } = [];

        public IReadOnlyList<NetworkEvent> Events { get; init; } = [];

        public IReadOnlyList<Incident> Incidents { get; init; } = [];

        public IReadOnlyList<AccessWatchRule> Rules { get; init; } = [];

        public List<TrustDecision> TrustDecisions { get; } = [];

        public List<Incident> IncidentUpserts { get; } = [];

        public List<AccessWatchRule> RuleUpserts { get; } = [];

        public List<(long DeviceId, string? UserAlias)> AliasUpdates { get; } = [];

        public Exception? Failure { get; init; }

        public TaskCompletionSource? InitializeGate { get; init; }

        public bool WasInitialized { get; private set; }

        public async Task InitializeAsync(CancellationToken cancellationToken)
        {
            if (Failure is not null)
            {
                throw Failure;
            }

            if (InitializeGate is not null)
            {
                await InitializeGate.Task.WaitAsync(cancellationToken);
            }

            WasInitialized = true;
        }

        public Task<long> UpsertDeviceAsync(NetworkDevice device, CancellationToken cancellationToken)
        {
            return Task.FromResult(1L);
        }

        public Task<IReadOnlyList<NetworkDevice>> ListRecentDevicesAsync(int limit, CancellationToken cancellationToken)
        {
            return Task.FromResult(Devices);
        }

        public Task UpdateDeviceAliasAsync(long deviceId, string? userAlias, CancellationToken cancellationToken)
        {
            AliasUpdates.Add((deviceId, userAlias));
            return Task.CompletedTask;
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
            TrustDecisions.Add(trustDecision with { TrustDecisionId = TrustDecisions.Count + 1 });
            return Task.FromResult((long)TrustDecisions.Count);
        }

        public Task<TrustStatus?> GetActiveTrustDecisionAsync(string targetType, long targetId, CancellationToken cancellationToken)
        {
            return Task.FromResult<TrustStatus?>(null);
        }

        public Task<long> UpsertIncidentAsync(Incident incident, CancellationToken cancellationToken)
        {
            IncidentUpserts.Add(incident with { IncidentId = incident.IncidentId > 0 ? incident.IncidentId : IncidentUpserts.Count + 1 });
            return Task.FromResult(IncidentUpserts[^1].IncidentId);
        }

        public Task<long> UpsertRuleAsync(AccessWatchRule rule, CancellationToken cancellationToken)
        {
            RuleUpserts.Add(rule with { RuleId = RuleUpserts.Count + 1 });
            return Task.FromResult((long)RuleUpserts.Count);
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
