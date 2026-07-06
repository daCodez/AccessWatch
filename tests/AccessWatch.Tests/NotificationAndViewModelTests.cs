using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using AccessWatch.App.ViewModels;
using AccessWatch.AI;
using AccessWatch.Core;
using AccessWatch.Enforcement;
using AccessWatch.Notifications;
using AccessWatch.Tray;
using Microsoft.Extensions.Logging;
using AppIdentity = AccessWatch.Core.ApplicationIdentity;

namespace AccessWatch.Tests;

/// <summary>
/// Tests notification and shell view-model behavior.
/// </summary>
public sealed class NotificationAndViewModelTests
{
    /// <summary>
    /// Verifies notification messages use plain warning language instead of technical details.
    /// </summary>
    [Theory]
    [InlineData(RiskLevel.High, NotificationAction.AskBeforeAllow, "Visual Studio started using the camera.", "Camera activation is sensitive.", "AccessWatch warning", "Someone is trying to use your camera.", "Open AccessWatch to block, allow, or watch it.")]
    [InlineData(RiskLevel.High, NotificationAction.AskBeforeAllow, "Skype started using the microphone.", "Microphone activation is sensitive.", "AccessWatch warning", "Someone is trying to use your microphone.", "Open AccessWatch to block, allow, or watch it.")]
    [InlineData(RiskLevel.High, NotificationAction.AskBeforeAllow, "Unknown app opened a port.", "It is network-reachable.", "AccessWatch warning", "Someone is trying to connect to your PC.", "Open AccessWatch to block, allow, or watch it.")]
    [InlineData(RiskLevel.Medium, NotificationAction.SoftNotify, "Kitchen tablet joined the network.", "A new device should be reviewed.", "AccessWatch notice", "A new device joined your network.", "Trace this device in AccessWatch.")]
    [InlineData(RiskLevel.Low, NotificationAction.SilentLog, "Background check completed.", "No sensitive activity.", "AccessWatch notice", "AccessWatch noticed something unusual.", "No action is needed right now.")]
    [InlineData(RiskLevel.Critical, NotificationAction.AutoBlock, "Unknown listener appeared.", "A listener can accept connections.", "AccessWatch warning", "Someone is trying to connect to your PC.", "AccessWatch is prepared to block it.")]
    public void NotificationMessageFactory_CreatesPlainToastAlert(
        RiskLevel riskLevel,
        NotificationAction action,
        string summary,
        string whyItMatters,
        string expectedTitle,
        string expectedBody,
        string expectedSuggestedAction)
    {
        var factory = new NotificationMessageFactory();
        var assessment = new PortRiskAssessment(
            riskLevel,
            RiskStatus.HighRisk,
            action,
            summary,
            whyItMatters,
            "Review it.");

        var message = factory.Create(assessment);

        Assert.Equal(expectedTitle, message.Title);
        Assert.Equal(expectedBody, message.Body);
        Assert.Equal(riskLevel, message.RiskLevel);
        Assert.Equal(action, message.Action);
        Assert.Equal(expectedSuggestedAction, message.SuggestedAction);
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

        Assert.Equal(["Safety Center", "Devices", "Applications", "Ports", "Incidents", "Rules", "Settings"], model.Pages.Select(page => page.Name));
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
        Assert.Contains("<ColumnDefinition Width=\"250\" />", xaml);
        Assert.Contains("ScrollViewer.HorizontalScrollBarVisibility=\"Disabled\"", xaml);
        Assert.Contains("HorizontalContentAlignment=\"Stretch\"", xaml);
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
        Assert.Contains("Header=\"Zone\"", xaml);
        Assert.Contains("Header=\"Confidence\"", xaml);
        Assert.Contains("Text=\"Port details\"", xaml);
        Assert.Contains("Header=\"Next step\"", xaml);
        Assert.Contains("Content=\"{Binding PortInvestigationButtonText}\"", xaml);
        Assert.Contains("Click=\"OnInvestigatePortClick\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedPortInvestigation, Mode=OneWay}\"", xaml);
        Assert.Contains("ItemsSource=\"{Binding Incidents}\"", xaml);
        Assert.Contains("Visibility=\"{Binding RulesVisibility}\"", xaml);
        Assert.Contains("ItemsSource=\"{Binding Rules}\"", xaml);
        Assert.Contains("SelectedItem=\"{Binding SelectedRule, Mode=TwoWay}\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedRuleDetail}\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedRuleDetail}\" Foreground=\"#57606A\" FontSize=\"12\" TextWrapping=\"Wrap\" Margin=\"0,0,0,10\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedRulePreview, Mode=OneWay}\"", xaml);
        Assert.Contains("Click=\"OnPreviewRuleClick\"", xaml);
        Assert.Contains("Click=\"OnEnableRuleClick\"", xaml);
        Assert.Contains("Click=\"OnDisableRuleClick\"", xaml);
        Assert.Contains("Visibility=\"{Binding SettingsVisibility}\"", xaml);
        Assert.Contains("ItemsSource=\"{Binding ProtectionModeOptions}\"", xaml);
        Assert.Contains("SelectedValue=\"{Binding SelectedProtectionMode, Mode=TwoWay}\"", xaml);
        Assert.Contains("ItemsSource=\"{Binding AiModeOptions}\"", xaml);
        Assert.Contains("SelectedValue=\"{Binding SelectedAiMode, Mode=TwoWay}\"", xaml);
        Assert.Contains("ItemsSource=\"{Binding QuietHoursOptions}\"", xaml);
        Assert.Contains("SelectedValue=\"{Binding SelectedQuietHours, Mode=TwoWay}\"", xaml);
        Assert.Contains("ItemsSource=\"{Binding NetworkProfileOptions}\"", xaml);
        Assert.Contains("SelectedValue=\"{Binding SelectedNetworkProfile, Mode=TwoWay}\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedSupportBridgeEndpoint, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}\"", xaml);
        Assert.Contains("Click=\"OnApplySettingsClick\"", xaml);
        Assert.Contains("Click=\"OnResetSettingsClick\"", xaml);
        Assert.Contains("SelectedItem=\"{Binding SelectedDevice, Mode=TwoWay}\"", xaml);
        Assert.Contains("Header=\"Name source\"", xaml);
        Assert.Contains("Header=\"State\"", xaml);
        Assert.Contains("Header=\"First seen\"", xaml);
        Assert.Contains("Header=\"Confirmed\"", xaml);
        Assert.Contains("Header=\"Next step\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedDeviceDetail}\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedDeviceDetail}\" Foreground=\"#57606A\" FontSize=\"12\" TextWrapping=\"Wrap\" Margin=\"0,0,0,10\"", xaml);
        Assert.Contains("<WrapPanel Grid.Row=\"1\" HorizontalAlignment=\"Right\" VerticalAlignment=\"Top\">", xaml);
        Assert.Contains("SelectedItem=\"{Binding SelectedApplication, Mode=TwoWay}\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedApplicationDetail}\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedApplicationDetail}\" Foreground=\"#57606A\" FontSize=\"12\" TextWrapping=\"Wrap\" Margin=\"0,0,0,10\"", xaml);
        Assert.Contains("Content=\"This is OK\"", xaml);
        Assert.Contains("Content=\"Keep watching\"", xaml);
        Assert.Contains("Content=\"Mark as guest\"", xaml);
        Assert.Contains("Content=\"Block it\"", xaml);
        Assert.Contains("Content=\"This is OK\"", xaml);
        Assert.Contains("Content=\"Keep watching\"", xaml);
        Assert.Contains("Content=\"Block it\"", xaml);
        Assert.Contains("Click=\"OnTrustDeviceClick\"", xaml);
        Assert.Contains("Click=\"OnGuestDeviceClick\"", xaml);
        Assert.Contains("Click=\"OnBlockApplicationClick\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedEnforcementPlan, Mode=OneWay}\"", xaml);
        Assert.Contains("Content=\"Apply protection\"", xaml);
        Assert.Contains("IsEnabled=\"{Binding CanApplyEnforcementPlan}\"", xaml);
        Assert.Contains("SelectedItem=\"{Binding SelectedIncident, Mode=TwoWay}\"", xaml);
        Assert.Contains("MinHeight=\"220\"", xaml);
        Assert.Contains("<RowDefinition Height=\"260\" />", xaml);
        Assert.Contains("<UniformGrid Columns=\"6\" Margin=\"0,0,0,10\">", xaml);
        Assert.Contains("Text=\"{Binding SelectedIncident.Title}\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedIncident.MainTarget}\"", xaml);
        Assert.Contains("Text=\"Next step\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedIncident.RecommendedAction}\"", xaml);
        Assert.Contains("<WrapPanel Grid.Row=\"2\" HorizontalAlignment=\"Right\" VerticalAlignment=\"Top\">", xaml);
        Assert.DoesNotContain("<DockPanel Grid.Row=\"1\" LastChildFill=\"True\">", xaml);
        Assert.DoesNotContain("<StackPanel Grid.Column=\"1\" Orientation=\"Horizontal\" VerticalAlignment=\"Top\">", xaml);
        Assert.DoesNotContain("Margin=\"0,0,16,0\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedIncidentExplanation, Mode=OneWay}\"", xaml);
        Assert.Contains("Text=\"{Binding IncidentSearchText, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}\"", xaml);
        Assert.Contains("SelectedItem=\"{Binding SelectedIncidentStatusFilter, Mode=TwoWay}\"", xaml);
        Assert.Contains("Header=\"Group\"", xaml);
        Assert.Contains("Header=\"Severity\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedIncidentTimeline, Mode=OneWay}\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedIncidentEvidence, Mode=OneWay}\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedIncidentNotes, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedIncidentExport, Mode=OneWay}\"", xaml);
        Assert.Contains("Text=\"{Binding SelectedIncidentRuleWizard, Mode=OneWay}\"", xaml);
        Assert.Contains("Content=\"This is OK\"", xaml);
        Assert.Contains("Content=\"Keep watching\"", xaml);
        Assert.Contains("Content=\"Act now\"", xaml);
        Assert.Contains("Content=\"Make automatic\"", xaml);
        Assert.Contains("Content=\"Save notes\"", xaml);
        Assert.Contains("Content=\"Export\"", xaml);
        Assert.Contains("Content=\"Review with AI\"", xaml);
        Assert.Contains("Content=\"Copy for ChatGPT\"", xaml);
        Assert.Contains("Click=\"OnResolveIncidentClick\"", xaml);
        Assert.Contains("Click=\"OnWatchIncidentClick\"", xaml);
        Assert.Contains("Click=\"OnEscalateIncidentClick\"", xaml);
        Assert.Contains("Click=\"OnCreateIncidentRuleClick\"", xaml);
        Assert.Contains("Click=\"OnSaveIncidentNotesClick\"", xaml);
        Assert.Contains("Click=\"OnExportIncidentClick\"", xaml);
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

        Assert.Equal("Safety Center", model.SelectedPageTitle);
        Assert.Equal("Plain-language protection status and next steps.", model.SelectedPageSummary);
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

        model.SelectedPage = model.Pages.Single(page => page.Name == "Rules");

        Assert.Equal("Rules", model.SelectedPageTitle);
        Assert.False(model.IsOverviewSelected);
        Assert.False(model.IsDevicesSelected);
        Assert.False(model.IsApplicationsSelected);
        Assert.False(model.IsPortsSelected);
        Assert.False(model.IsIncidentsSelected);
        Assert.True(model.IsRulesSelected);
        Assert.False(model.IsSettingsSelected);
        Assert.False(model.IsPlaceholderSelected);
        Assert.Equal("Collapsed", model.OverviewVisibility);
        Assert.Equal("Collapsed", model.DevicesVisibility);
        Assert.Equal("Collapsed", model.ApplicationsVisibility);
        Assert.Equal("Collapsed", model.PortsVisibility);
        Assert.Equal("Collapsed", model.IncidentsVisibility);
        Assert.Equal("Visible", model.RulesVisibility);
        Assert.Equal("Collapsed", model.SettingsVisibility);
        Assert.Equal("Collapsed", model.PlaceholderVisibility);
        Assert.Contains(nameof(DashboardShellViewModel.IsRulesSelected), changed);
        Assert.Contains(nameof(DashboardShellViewModel.RulesVisibility), changed);

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

        Assert.Equal("Safety Center", model.SelectedPageTitle);
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
    /// <summary>
    /// Verifies the Safety Center gives a calm empty state when nothing needs action.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_ShowsSimpleSafeState()
    {
        var model = new DashboardShellViewModel(new FakeRepository());

        await model.LoadAsync(CancellationToken.None);

        Assert.Equal("You look safe right now", model.SafetyHeadline);
        Assert.Contains("No urgent camera", model.SafetyExplanation);
        Assert.Contains("leave AccessWatch running", model.SafetyRecommendation);
        Assert.Equal("Visible", model.SafetyEmptyVisibility);
        Assert.Equal("Collapsed", model.SafetyItemsVisibility);
        Assert.Empty(model.SafetyItems);
    }

    /// <summary>
    /// Verifies high-risk activity becomes plain-language Safety Center action items.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_BuildsSimpleSafetyItems()
    {
        var repository = new FakeRepository
        {
            Applications = [new AppIdentity { ApplicationId = 7, DisplayName = "Video Chat", ProcessName = "videochat" }],
            Devices = [new NetworkDevice { DeviceId = 9, IpAddress = "192.168.1.45", Hostname = "new-phone", TrustStatus = TrustStatus.Unknown, RiskStatus = RiskStatus.Suspicious }],
            Events =
            [
                new NetworkEvent
                {
                    EventType = "CameraActivated",
                    ApplicationId = 7,
                    RiskLevel = RiskLevel.High,
                    DetailsJson = "{\"app\":\"Video Chat\"}",
                    CreatedUtc = DateTimeOffset.UtcNow
                },
                new NetworkEvent
                {
                    EventType = "NewDeviceObserved",
                    SourceDeviceId = 9,
                    RiskLevel = RiskLevel.Medium,
                    DetailsJson = "{\"deviceName\":\"new-phone\"}",
                    CreatedUtc = DateTimeOffset.UtcNow
                }
            ],
            Ports =
            [
                new ListeningPort
                {
                    PortNumber = 9443,
                    LocalAddress = "0.0.0.0",
                    Protocol = "TCP",
                    Reachability = PortReachability.NetworkReachable,
                    RiskStatus = RiskStatus.HighRisk,
                    Application = new AppIdentity { DisplayName = "Remote Tool", ProcessName = "remote" }
                }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        Assert.Equal("3 things need your attention", model.SafetyHeadline);
        Assert.Contains("may affect privacy", model.SafetyExplanation);
        Assert.Contains("Start with the first item", model.SafetyRecommendation);
        Assert.Equal("Collapsed", model.SafetyEmptyVisibility);
        Assert.Equal("Visible", model.SafetyItemsVisibility);
        Assert.Collection(
            model.SafetyItems,
            camera =>
            {
                Assert.Equal("Act now", camera.Urgency);
                Assert.Equal("Someone may be using your camera", camera.Headline);
                Assert.Equal("Video Chat", camera.Target);
                Assert.Equal("Block it", camera.PrimaryAction);
                Assert.Equal("This is OK", camera.SecondaryAction);
            },
            device =>
            {
                Assert.Equal("Needs review", device.Urgency);
                Assert.Equal("A new device joined your network", device.Headline);
                Assert.Equal("Trace device", device.PrimaryAction);
            },
            port =>
            {
                Assert.Equal("Someone may be able to connect to this PC", port.Headline);
                Assert.Equal("Remote Tool", port.Target);
                Assert.Equal("Investigate", port.PrimaryAction);
            });
    }

    /// <summary>
    /// Verifies the Safety Center handles a single microphone alert without plural wording.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_BuildsSingleMicrophoneSafetyItem()
    {
        var model = new DashboardShellViewModel(new FakeRepository
        {
            Events =
            [
                new NetworkEvent
                {
                    EventType = "MicrophoneActivated",
                    RiskLevel = RiskLevel.High,
                    DetailsJson = "{\"app\":\"Meeting App\"}",
                    CreatedUtc = DateTimeOffset.UtcNow
                }
            ]
        });

        await model.LoadAsync(CancellationToken.None);

        Assert.Equal("1 thing needs your attention", model.SafetyHeadline);
        var item = Assert.Single(model.SafetyItems);
        Assert.Equal("Someone may be using your microphone", item.Headline);
        Assert.Equal("Meeting App", item.Target);
    }

    /// <summary>
    /// Verifies critical connection and unusual events still get simple Safety Center wording.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_BuildsConnectionAndFallbackSafetyItems()
    {
        var model = new DashboardShellViewModel(new FakeRepository
        {
            Events =
            [
                new NetworkEvent
                {
                    EventType = "NewListeningPort",
                    RiskLevel = RiskLevel.Critical,
                    ApplicationId = 4,
                    DetailsJson = "{\"app\":\"Remote Admin\"}",
                    CreatedUtc = DateTimeOffset.UtcNow
                },
                new NetworkEvent
                {
                    EventType = "UnusualActivity",
                    RiskLevel = RiskLevel.High,
                    Summary = "Something unusual happened",
                    DetailsJson = "{\"whatHappened\":\"A sensitive setting changed.\",\"suggestedAction\":\"Review this change.\"}",
                    CreatedUtc = DateTimeOffset.UtcNow
                },
                new NetworkEvent
                {
                    EventType = "NewDeviceObserved",
                    RiskLevel = RiskLevel.Medium,
                    DetailsJson = "{\"deviceName\":\"living-room-tv\"}",
                    CreatedUtc = DateTimeOffset.UtcNow
                }
            ]
        });

        await model.LoadAsync(CancellationToken.None);

        Assert.Collection(
            model.SafetyItems,
            connection =>
            {
                Assert.Equal("Act now", connection.Urgency);
                Assert.Equal("Someone may be able to connect to this PC", connection.Headline);
                Assert.Equal("Remote Admin", connection.Target);
            },
            fallback =>
            {
                Assert.Equal("Needs review", fallback.Urgency);
                Assert.Equal("Something unusual happened", fallback.Headline);
                Assert.Equal("A sensitive setting changed.", fallback.WhatHappened);
                Assert.Equal("Review this change.", fallback.RecommendedAction);
            },
            device =>
            {
                Assert.Equal("A new device joined your network", device.Headline);
                Assert.Equal("living-room-tv", device.Target);
            });
    }

    /// <summary>
    /// Verifies incident and device fallback sources can populate the Safety Center.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_BuildsFallbackSafetyItems()
    {
        var model = new DashboardShellViewModel(new FakeRepository
        {
            Incidents = [new Incident { IncidentId = 8, Title = "Critical remote access", Summary = "Remote access needs review.", RiskLevel = RiskLevel.Critical, Status = IncidentStatus.Open, EventCount = 2, StartedUtc = DateTimeOffset.UtcNow, LastUpdatedUtc = DateTimeOffset.UtcNow }],
            Devices = [new NetworkDevice { DeviceId = 5, IpAddress = "192.168.1.88", Hostname = "unknown-tablet", TrustStatus = TrustStatus.Unknown, RiskStatus = RiskStatus.Suspicious }]
        });

        await model.LoadAsync(CancellationToken.None);

        Assert.Collection(
            model.SafetyItems,
            incident =>
            {
                Assert.Equal("Act now", incident.Urgency);
                Assert.Equal("Critical remote access", incident.Headline);
                Assert.Equal("Act now", incident.PrimaryAction);
            },
            device =>
            {
                Assert.Equal("A device needs your attention", device.Headline);
                Assert.Equal("Trace device", device.PrimaryAction);
            });
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
        Assert.Equal("Possible outside connection path detected.", activity.Summary);
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
                Assert.Equal("Click Trace device. If AccessWatch still cannot identify it, leave it watched or block it instead of naming it.", device.RecommendedAction);
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
        Assert.True(model.CanTraceSelectedDevice);
        Assert.True(model.CanApplyApplicationTrustDecision);
        Assert.Contains("office-laptop", model.SelectedDeviceDetail);
        Assert.Contains("Click Trace device", model.SelectedDeviceTrace);
        Assert.Contains("192.168.1.25", model.SelectedDeviceDetail);
        Assert.Contains("Visual Studio", model.SelectedApplicationDetail);
        Assert.Contains("Microsoft Corporation", model.SelectedApplicationDetail);

        model.TraceSelectedDevice();

        Assert.Contains("Trace report: office-laptop", model.SelectedDeviceTrace);
        Assert.Contains("Network address: 192.168.1.25", model.SelectedDeviceTrace);
        Assert.Contains("Hardware ID: 02:AC:CE:55:20:25", model.SelectedDeviceTrace);
        Assert.Contains("AccessWatch guess: Likely PC or laptop.", model.SelectedDeviceTrace);
        Assert.Contains("Clues AccessWatch found:", model.SelectedDeviceTrace);
        Assert.Contains("Next step:", model.SelectedDeviceTrace);
        Assert.Contains("Trace ready for office-laptop", model.StatusMessage);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedDeviceTrace), changed);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedDeviceDetail), changed);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedApplicationDetail), changed);

        changed.Clear();
        model.SelectedDevice = null;
        model.SelectedApplication = null;

        Assert.Contains("Select a device", model.SelectedDeviceDetail);
        Assert.Contains("Select an application", model.SelectedApplicationDetail);
        Assert.False(model.CanApplyDeviceTrustDecision);
        Assert.False(model.CanTraceSelectedDevice);
        Assert.False(model.CanApplyApplicationTrustDecision);
        Assert.Contains("Select a device", model.SelectedDeviceTrace);

        model.TraceSelectedDevice();

        Assert.Contains("Select a device before tracing it", model.StatusMessage);
        Assert.Contains("Select a device", model.SelectedDeviceTrace);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedDeviceDetail), changed);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedDeviceTrace), changed);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedApplicationDetail), changed);
    }

    /// <summary>
    /// Verifies device trace reports give a plain identity guess instead of asking the user to interpret raw clues.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_TraceSelectedDevice_GuessesCommonDeviceTypes()
    {
        var repository = new FakeRepository
        {
            Devices =
            [
                new NetworkDevice { Hostname = "home-gateway", IpAddress = "192.168.1.1", DeviceTypeGuess = "Router" },
                new NetworkDevice { Hostname = "johns-phone", IpAddress = "192.168.1.30", DeviceTypeGuess = "Phone" },
                new NetworkDevice { Hostname = "office-laptop", IpAddress = "192.168.1.40", DeviceTypeGuess = "Windows workstation" },
                new NetworkDevice { IpAddress = "192.168.1.77" }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        model.SelectedDevice = model.Devices[0];
        model.TraceSelectedDevice();
        Assert.Contains("AccessWatch guess: Likely router or gateway.", model.SelectedDeviceTrace);

        model.SelectedDevice = model.Devices[1];
        model.TraceSelectedDevice();
        Assert.Contains("AccessWatch guess: Likely phone or tablet.", model.SelectedDeviceTrace);

        model.SelectedDevice = model.Devices[2];
        model.TraceSelectedDevice();
        Assert.Contains("AccessWatch guess: Likely PC or laptop.", model.SelectedDeviceTrace);

        model.SelectedDevice = model.Devices[3];
        model.TraceSelectedDevice();
        Assert.Contains("AccessWatch guess: Unknown device; keep it watched until AccessWatch sees a clearer name or you recognize it.", model.SelectedDeviceTrace);
        Assert.Contains("Next step: Click Trace device. If AccessWatch still cannot identify it, leave it watched or block it instead of naming it.", model.SelectedDeviceTrace);
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
    /// Verifies blocked inventory decisions prepare reviewed firewall protection plans.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_BlockTrustDecision_PreparesFirewallPlan()
    {
        var repository = new FakeRepository
        {
            Devices = [new NetworkDevice { DeviceId = 42, Hostname = "guest-phone", IpAddress = "192.168.1.55", MacAddress = "02:AC:CE:55:20:25" }],
            Applications =
            [
                new AppIdentity
                {
                    ApplicationId = 84,
                    DisplayName = "Visual Studio",
                    ProcessName = "devenv",
                    FilePath = "C:\\Program Files\\Microsoft Visual Studio\\devenv.exe"
                }
            ]
        };
        var model = new DashboardShellViewModel(
            repository,
            firewallEnforcementPlanner: new WindowsFirewallEnforcementPlanner());

        await model.LoadAsync(CancellationToken.None);
        await model.ApplySelectedDeviceTrustDecisionAsync(TrustStatus.Blocked, CancellationToken.None);

        Assert.Contains("protection plan prepared", model.StatusMessage);
        Assert.Contains("Block all traffic to and from guest-phone", model.SelectedEnforcementPlan);
        Assert.Contains("New-NetFirewallRule", model.SelectedEnforcementPlan);
        Assert.Contains("-RemoteAddress '192.168.1.55'", model.SelectedEnforcementPlan);
        Assert.True(model.HasEnforcementPlan);

        await model.ApplySelectedApplicationTrustDecisionAsync(TrustStatus.Blocked, CancellationToken.None);

        Assert.Contains("protection plan prepared", model.StatusMessage);
        Assert.Contains("Block network traffic for Visual Studio", model.SelectedEnforcementPlan);
        Assert.Contains("-Program 'C:\\Program Files\\Microsoft Visual Studio\\devenv.exe'", model.SelectedEnforcementPlan);
    }

    /// <summary>
    /// Verifies non-block decisions reset the reviewed firewall protection plan.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_NonBlockTrustDecision_ResetsFirewallPlan()
    {
        var repository = new FakeRepository
        {
            Devices = [new NetworkDevice { DeviceId = 43, Hostname = "office-laptop", IpAddress = "192.168.1.25" }]
        };
        var model = new DashboardShellViewModel(
            repository,
            firewallEnforcementPlanner: new WindowsFirewallEnforcementPlanner());

        await model.LoadAsync(CancellationToken.None);
        await model.ApplySelectedDeviceTrustDecisionAsync(TrustStatus.Blocked, CancellationToken.None);
        await model.ApplySelectedDeviceTrustDecisionAsync(TrustStatus.Trusted, CancellationToken.None);

        Assert.Contains("Block a device or app", model.SelectedEnforcementPlan);
        Assert.Equal("Trusted office-laptop.", model.StatusMessage);
    }
    /// <summary>
    /// Verifies blocked device decisions explain when firewall protection planning is not connected.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_BlockDeviceTrustDecisionWithoutPlanner_ExplainsMissingProtectionPlanning()
    {
        var repository = new FakeRepository
        {
            Devices = [new NetworkDevice { DeviceId = 44, Hostname = "guest-tablet", IpAddress = "192.168.1.56" }]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);
        await model.ApplySelectedDeviceTrustDecisionAsync(TrustStatus.Blocked, CancellationToken.None);

        Assert.Equal("Firewall protection planning is not connected for this dashboard session.", model.SelectedEnforcementPlan);
        Assert.Equal("Blocked guest-tablet.", model.StatusMessage);
        Assert.True(model.HasEnforcementPlan);
    }

    /// <summary>
    /// Verifies protection plans can explain a review-only action without administrator commands.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_BlockDeviceTrustDecisionWithReviewOnlyPlan_ShowsNoAdminCopy()
    {
        var repository = new FakeRepository
        {
            Devices = [new NetworkDevice { DeviceId = 45, Hostname = "lab-sensor", IpAddress = "192.168.1.57" }]
        };
        var model = new DashboardShellViewModel(
            repository,
            firewallEnforcementPlanner: new ReviewOnlyFirewallPlanner());

        await model.LoadAsync(CancellationToken.None);
        await model.ApplySelectedDeviceTrustDecisionAsync(TrustStatus.Blocked, CancellationToken.None);

        Assert.Contains("Does not require administrator approval.", model.SelectedEnforcementPlan);
        Assert.Contains("No firewall command is ready yet.", model.SelectedEnforcementPlan);
    }

    /// <summary>
    /// Verifies failed firewall apply results keep the reviewed plan available.
    /// </summary>
    [Fact]
    public void FirewallEnforcementPlanReviewViewModel_ShowApplyFailure_KeepsPlanAvailable()
    {
        var plan = new FirewallEnforcementPlan(
            "Device",
            "guest-phone",
            "Block guest-phone",
            "Review first",
            ["New-NetFirewallRule inbound"],
            true);
        var review = new FirewallEnforcementPlanReviewViewModel();
        review.SetPlan(plan);

        review.ShowApplyResult(plan, new FirewallEnforcementResult(false, "Could not apply protection.", "Firewall rejected the rule.", []));

        Assert.Same(plan, review.SelectedPlan);
        Assert.True(review.CanApply(false));
        Assert.Contains("Last apply result:", review.Text);
        Assert.Contains("Firewall rejected the rule.", review.Text);
    }

    /// <summary>
    /// Verifies the apply protection button state follows the reviewed firewall plan.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_BlockTrustDecision_EnablesApplyProtectionForReadyPlan()
    {
        var repository = new FakeRepository
        {
            Devices = [new NetworkDevice { DeviceId = 46, Hostname = "guest-phone", IpAddress = "192.168.1.55" }]
        };
        var model = new DashboardShellViewModel(
            repository,
            firewallEnforcementPlanner: new WindowsFirewallEnforcementPlanner());

        await model.LoadAsync(CancellationToken.None);
        Assert.False(model.CanApplyEnforcementPlan);

        await model.ApplySelectedDeviceTrustDecisionAsync(TrustStatus.Blocked, CancellationToken.None);

        Assert.True(model.CanApplyEnforcementPlan);
    }

    /// <summary>
    /// Verifies applying protection explains when execution is not connected.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_ApplySelectedEnforcementPlanWithoutExecutor_ExplainsMissingApplicationService()
    {
        var repository = new FakeRepository
        {
            Devices = [new NetworkDevice { DeviceId = 47, Hostname = "guest-phone", IpAddress = "192.168.1.55" }]
        };
        var model = new DashboardShellViewModel(
            repository,
            firewallEnforcementPlanner: new WindowsFirewallEnforcementPlanner());

        await model.LoadAsync(CancellationToken.None);
        await model.ApplySelectedDeviceTrustDecisionAsync(TrustStatus.Blocked, CancellationToken.None);
        await model.ApplySelectedEnforcementPlanAsync(CancellationToken.None);

        Assert.Equal("Firewall protection application is not connected for this dashboard session.", model.StatusMessage);
        Assert.True(model.CanApplyEnforcementPlan);
    }

    /// <summary>
    /// Verifies successful protection application records the result and disables repeat apply.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_ApplySelectedEnforcementPlan_ShowsSuccessAndDisablesRepeatApply()
    {
        var repository = new FakeRepository
        {
            Devices = [new NetworkDevice { DeviceId = 48, Hostname = "guest-phone", IpAddress = "192.168.1.55" }]
        };
        var model = new DashboardShellViewModel(
            repository,
            firewallEnforcementPlanner: new WindowsFirewallEnforcementPlanner(),
            firewallEnforcementExecutor: new FakeFirewallExecutor(true));

        await model.LoadAsync(CancellationToken.None);
        await model.ApplySelectedDeviceTrustDecisionAsync(TrustStatus.Blocked, CancellationToken.None);
        await model.ApplySelectedEnforcementPlanAsync(CancellationToken.None);

        Assert.Equal("Applied firewall protection for guest-phone.", model.StatusMessage);
        Assert.Contains("Last apply result:", model.SelectedEnforcementPlan);
        Assert.Contains("AccessWatch applied 2 Windows Firewall rule(s).", model.SelectedEnforcementPlan);
        Assert.False(model.CanApplyEnforcementPlan);
    }

    /// <summary>
    /// Verifies apply protection requires a reviewed plan first.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_ApplySelectedEnforcementPlanRequiresPlan()
    {
        var model = new DashboardShellViewModel(new FakeRepository(), firewallEnforcementExecutor: new FakeFirewallExecutor(true));

        await model.ApplySelectedEnforcementPlanAsync(CancellationToken.None);

        Assert.Equal("Block a device or app before applying protection.", model.StatusMessage);
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
        Assert.Equal(settings.SupportBridgeEndpoint, model.SelectedSupportBridgeEndpoint);
        Assert.Equal("Settings match the running configuration.", model.SettingsStatus);
        Assert.Equal(["Quiet", "Balanced", "Strict", "Lockdown"], model.ProtectionModeOptions.Select(option => option.Value));
        Assert.Equal(["Off", "ManualChatGptCopy", "SupportBridge", "LocalAi", "OpenAiApi"], model.AiModeOptions.Select(option => option.Value));

        model.SelectedProtectionMode = "Lockdown";
        model.SelectedAiMode = "OpenAiApi";
        model.SelectedSupportBridgeEndpoint = " http://localhost:8123/accesswatch ";
        model.ApplySettings();

        Assert.Equal(ProtectionMode.Lockdown, settings.ProtectionMode);
        Assert.Equal(AiMode.OpenAiApi, settings.AiMode);
        Assert.Equal("http://localhost:8123/accesswatch", settings.SupportBridgeEndpoint);
        Assert.Equal("http://localhost:8123/accesswatch", model.SelectedSupportBridgeEndpoint);
        Assert.Equal("Lockdown", model.CurrentProtectionMode);
        Assert.Equal("OpenAiApi", model.CurrentAiMode);
        Assert.Contains("Settings applied", model.SettingsStatus);
        Assert.Contains(nameof(DashboardShellViewModel.CurrentProtectionMode), changed);
        Assert.Contains(nameof(DashboardShellViewModel.CurrentAiMode), changed);

        changed.Clear();
        model.SelectedProtectionMode = null!;
        model.SelectedAiMode = null!;
        model.SelectedSupportBridgeEndpoint = null!;

        Assert.Equal("Lockdown", model.SelectedProtectionMode);
        Assert.Equal("OpenAiApi", model.SelectedAiMode);
        Assert.Equal("http://localhost:8123/accesswatch", model.SelectedSupportBridgeEndpoint);

        model.SelectedProtectionMode = "Strict";
        model.SelectedAiMode = "Off";
        model.SelectedSupportBridgeEndpoint = "http://localhost:9999/other";
        model.ResetSettingsSelections();

        Assert.Equal("Lockdown", model.SelectedProtectionMode);
        Assert.Equal("OpenAiApi", model.SelectedAiMode);
        Assert.Equal("http://localhost:8123/accesswatch", model.SelectedSupportBridgeEndpoint);
        Assert.Contains("match the running configuration", model.SettingsStatus);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedProtectionMode), changed);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedAiMode), changed);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedSupportBridgeEndpoint), changed);

        model.SelectedSupportBridgeEndpoint = " ";
        model.ApplySettings();
        Assert.Equal(new AccessWatchSettings().SupportBridgeEndpoint, settings.SupportBridgeEndpoint);
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
                Assert.Equal("All network adapters", port.NetworkAdapter);
                Assert.Equal("All adapters", port.NetworkZone);
                Assert.Contains("another device may be able to connect", port.ReachabilityTest);
                Assert.Contains("Previously seen", port.HistoryStatus);
                Assert.Contains("High-risk network exposure", port.ExposureChange);
                Assert.Contains("High (90%)", port.AppConfidence);
                Assert.Contains("Confirm this application", port.SuggestedAction);
                Assert.Contains("Application confidence:", port.Investigation);
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
                Assert.Equal("Loopback adapter on this PC", port.NetworkAdapter);
                Assert.Equal("Loopback", port.NetworkZone);
                Assert.Contains("bound to this PC only", port.ReachabilityTest);
                Assert.Contains("No history yet", port.HistoryStatus);
                Assert.Contains("No high-risk", port.ExposureChange);
                Assert.Contains("Low (20%)", port.AppConfidence);
                Assert.Contains("Run a fresh scan", port.SuggestedAction);
            },
            port =>
            {
                Assert.Equal("TCP 172.22.96.1:139", port.Endpoint);
                Assert.Contains("NetBIOS", port.Meaning);
                Assert.Contains("private or virtual address 172.22.96.1", port.Exposure);
                Assert.Equal("WSL or Hyper-V", port.NetworkZone);
                Assert.Contains("WSL or Hyper-V virtual adapter", port.NetworkAdapter);
                Assert.Contains("forwarded ports", port.ReachabilityTest);
                Assert.Contains("High-risk network exposure", port.ExposureChange);
                Assert.Contains("Run a fresh scan", port.SuggestedAction);
            },
            port =>
            {
                Assert.Equal("TCP 127.0.0.1:80", port.Endpoint);
                Assert.Contains("HTTP web service", port.Meaning);
                Assert.Contains("Local-only listener", port.Exposure);
                Assert.Equal("Loopback", port.NetworkZone);
                Assert.Contains("No high-risk", port.ExposureChange);
                Assert.Contains("High (90%)", port.AppConfidence);
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
        Assert.Contains("Protection focus:", model.SelectedIncidentExplanation);
        Assert.Contains("Camera use was detected", model.SelectedIncidentExplanation);
        Assert.Contains("Outside sources usually reach the camera", model.SelectedIncidentExplanation);
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
        Assert.Contains("Likely adapter: All network adapters", model.SelectedPortInvestigation);
        Assert.Contains("Application confidence: High (90%)", model.SelectedPortInvestigation);
        Assert.Contains("Recommended decision: Confirm this application", model.SelectedPortInvestigation);

        model.SelectedPort = model.Ports[1];
        Assert.Equal("Investigate port", model.PortInvestigationButtonText);
        Assert.Contains("Click Investigate port", model.SelectedPortInvestigation);
    }

    /// <summary>
    /// Verifies port rows call out adapter zones, history, exposure changes, and confidence.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_ExplainsPortZonesHistoryAndConfidence()
    {
        var openssh = new AppIdentity { DisplayName = "OpenSSH Server", ProcessName = "sshd" };
        var incompleteApplication = new AppIdentity { DisplayName = string.Empty, ProcessName = string.Empty };
        var repository = new FakeRepository
        {
            Ports =
            [
                new ListeningPort
                {
                    PortNumber = 22,
                    Protocol = "TCP",
                    LocalAddress = "192.168.1.25",
                    Reachability = PortReachability.NetworkReachable,
                    RiskStatus = RiskStatus.HighRisk,
                    Application = openssh
                },
                new ListeningPort
                {
                    PortNumber = 445,
                    Protocol = "TCP",
                    LocalAddress = "172.17.0.2",
                    Reachability = PortReachability.NetworkReachable,
                    RiskStatus = RiskStatus.Critical,
                    Application = openssh
                },
                new ListeningPort
                {
                    PortNumber = 53,
                    Protocol = "UDP",
                    LocalAddress = "172.31.2.4",
                    Reachability = PortReachability.Unknown,
                    RiskStatus = RiskStatus.Normal,
                    FirstSeenUtc = DateTimeOffset.UnixEpoch,
                    LastSeenUtc = DateTimeOffset.UnixEpoch,
                    Application = incompleteApplication
                },
                new ListeningPort
                {
                    PortNumber = 5900,
                    Protocol = "TCP",
                    LocalAddress = "169.254.1.8",
                    Reachability = PortReachability.NetworkReachable,
                    RiskStatus = RiskStatus.HighRisk
                },
                new ListeningPort
                {
                    PortNumber = 8080,
                    Protocol = "TCP",
                    LocalAddress = "203.0.113.10",
                    Reachability = PortReachability.NetworkReachable,
                    RiskStatus = RiskStatus.Normal,
                    Application = openssh
                },
                new ListeningPort
                {
                    PortNumber = 25,
                    Protocol = "TCP",
                    LocalAddress = "10.0.0.9",
                    Reachability = PortReachability.NetworkReachable,
                    RiskStatus = RiskStatus.Normal,
                    Application = openssh
                }
            ],
            Events =
            [
                new NetworkEvent { EventType = "NewListeningPort", DestinationPort = 22, DestinationIp = "192.168.1.25", Protocol = "UDP", CreatedUtc = DateTimeOffset.UnixEpoch.AddSeconds(1) },
                new NetworkEvent { EventType = "NewListeningPort", DestinationPort = 22, DestinationIp = "192.168.1.25", Protocol = "TCP", CreatedUtc = DateTimeOffset.UnixEpoch.AddSeconds(2) },
                new NetworkEvent { EventType = "ListeningPortApplicationChanged", DestinationPort = 445, DestinationIp = "172.17.0.2", Protocol = "TCP", CreatedUtc = DateTimeOffset.UnixEpoch.AddSeconds(3) },
                new NetworkEvent { EventType = "NewListeningPort", DestinationPort = 3389, DestinationIp = "192.168.1.25", Protocol = "TCP", CreatedUtc = DateTimeOffset.UnixEpoch.AddSeconds(4) },
                new NetworkEvent { EventType = "NewListeningPort", DestinationPort = 8080, DestinationIp = "203.0.113.11", Protocol = "TCP", CreatedUtc = DateTimeOffset.UnixEpoch.AddSeconds(5) },
                new NetworkEvent { EventType = "NewListeningPort", DestinationPort = 8080, Protocol = string.Empty, CreatedUtc = DateTimeOffset.UnixEpoch.AddSeconds(6) }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        Assert.Collection(
            model.Ports,
            ssh =>
            {
                Assert.Contains("SSH remote shell", ssh.Meaning);
                Assert.Equal("LAN", ssh.NetworkZone);
                Assert.Contains("LAN adapter", ssh.NetworkAdapter);
                Assert.Contains("network address", ssh.ReachabilityTest);
                Assert.Contains("Newly opened", ssh.HistoryStatus);
                Assert.Contains("New high-risk exposure", ssh.ExposureChange);
                Assert.Contains("Medium (60%)", ssh.AppConfidence);
                Assert.Contains("Treat this as new exposure", ssh.SuggestedAction);
            },
            smb =>
            {
                Assert.Contains("SMB file sharing", smb.Meaning);
                Assert.Equal("Docker", smb.NetworkZone);
                Assert.Contains("Docker virtual adapter", smb.NetworkAdapter);
                Assert.Contains("forwarded ports", smb.ReachabilityTest);
                Assert.Contains("Owning application changed", smb.HistoryStatus);
                Assert.Contains("High-risk port changed", smb.ExposureChange);
            },
            dns =>
            {
                Assert.Contains("DNS service", dns.Meaning);
                Assert.Equal("VPN or private virtual network", dns.NetworkZone);
                Assert.Contains("Unknown from this scan", dns.ReachabilityTest);
                Assert.Contains("Opened once", dns.HistoryStatus);
                Assert.Contains("Low (20%) - application identity is incomplete", dns.AppConfidence);
            },
            vnc =>
            {
                Assert.Contains("VNC remote screen sharing", vnc.Meaning);
                Assert.Equal("Link-local", vnc.NetworkZone);
                Assert.Contains("Link-local adapter", vnc.NetworkAdapter);
                Assert.Contains("High-risk network exposure", vnc.ExposureChange);
            },
            web =>
            {
                Assert.Contains("Alternate HTTP", web.Meaning);
                Assert.Equal("Public or unknown network", web.NetworkZone);
                Assert.Contains("Possibly reachable", web.ReachabilityTest);
                Assert.Contains("Newly opened", web.HistoryStatus);
            },
            smtp =>
            {
                Assert.Contains("SMTP mail service", smtp.Meaning);
                Assert.Equal("LAN", smtp.NetworkZone);
                Assert.Contains("LAN adapter", smtp.NetworkAdapter);
            });
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
    /// Verifies incident grouping, timelines, evidence, notes, filtering, export, and rule wizard text.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_AddsIncidentWorkflowDetailsAndFilters()
    {
        var repository = new FakeRepository
        {
            Devices = [new NetworkDevice { DeviceId = 4, Hostname = "office-laptop", IpAddress = "192.168.1.25" }],
            Applications = [new AppIdentity { ApplicationId = 9, DisplayName = "Skype", ProcessName = "Skype" }],
            Incidents =
            [
                new Incident
                {
                    IncidentId = 101,
                    Title = "Camera opened",
                    Summary = "Skype activated the camera.",
                    MainDeviceId = 4,
                    MainApplicationId = 9,
                    RiskLevel = RiskLevel.Critical,
                    Status = IncidentStatus.Open,
                    EventCount = 2,
                    StartedUtc = new DateTimeOffset(2026, 6, 29, 13, 0, 0, TimeSpan.Zero),
                    LastUpdatedUtc = new DateTimeOffset(2026, 6, 29, 13, 5, 0, TimeSpan.Zero),
                    UserNotes = "User was in a call."
                },
                new Incident
                {
                    IncidentId = 102,
                    Title = "Port opened",
                    Summary = "Remote service opened.",
                    MainApplicationId = 9,
                    RiskLevel = RiskLevel.High,
                    Status = IncidentStatus.Open,
                    EventCount = 1
                },
                new Incident
                {
                    IncidentId = 103,
                    Title = "Device joined",
                    Summary = "Known tablet joined.",
                    MainDeviceId = 4,
                    RiskLevel = RiskLevel.Medium,
                    Status = IncidentStatus.Watching,
                    EventCount = 3
                },
                new Incident
                {
                    IncidentId = 104,
                    Title = "History item",
                    Summary = "Old low-risk event.",
                    RiskLevel = RiskLevel.Low,
                    Status = IncidentStatus.Resolved,
                    EventCount = 1,
                    ResolvedUtc = new DateTimeOffset(2026, 6, 29, 14, 0, 0, TimeSpan.Zero)
                }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        Assert.Equal("All", model.SelectedIncidentStatusFilter);
        Assert.Contains("Open", model.IncidentStatusFilterOptions);
        Assert.Equal("Select an incident to see when it started, changed, and last updated.", model.SelectedIncidentTimeline);
        Assert.Equal("Select an incident to see the evidence AccessWatch used.", model.SelectedIncidentEvidence);
        Assert.Equal("Select an incident to see why this severity was assigned.", model.SelectedIncidentSeverityExplanation);
        Assert.Equal("Select an incident to prepare an export.", model.SelectedIncidentExport);
        Assert.Equal("Select an incident to see a rule wizard preview.", model.SelectedIncidentRuleWizard);
        Assert.False(model.CanSaveIncidentNotes);
        Assert.False(model.CanExportIncident);
        model.PrepareSelectedIncidentExport();
        Assert.Equal("Select an incident before preparing an export.", model.StatusMessage);
        await model.SaveSelectedIncidentNotesAsync(CancellationToken.None);
        Assert.Equal("Select an incident before saving notes.", model.StatusMessage);

        await model.LoadAsync(CancellationToken.None);

        Assert.Equal(4, model.Incidents.Count);
        var critical = model.Incidents[0];
        Assert.Contains("app/device", critical.GroupKey);
        Assert.Contains("Grouped by app/device", critical.Grouping);
        Assert.Contains("Critical because 2 related events", critical.SeverityExplanation);
        Assert.Contains("Started:", critical.Timeline);
        Assert.Contains("Resolved: not resolved", critical.Timeline);
        Assert.Contains("User was in a call.", critical.Evidence);
        Assert.Contains("Escalate if unexpected; repeated high-risk", critical.RecommendedAction);
        Assert.Contains("AccessWatch incident export", critical.ExportText);
        Assert.Equal("User was in a call.", model.SelectedIncidentNotes);
        Assert.True(model.CanSaveIncidentNotes);
        Assert.True(model.CanExportIncident);
        Assert.Contains("Rule creation wizard", model.SelectedIncidentRuleWizard);
        Assert.Contains("No rule has been created yet", model.SelectedIncidentRuleWizard);
        Assert.Contains("Camera opened", model.SelectedIncidentExport);

        model.IncidentSearchText = "tablet";
        Assert.Single(model.Incidents);
        Assert.Equal("Device joined", model.SelectedIncident!.Title);
        Assert.Contains("Medium because 3 related events", model.SelectedIncidentSeverityExplanation);
        Assert.Contains("Watching: leave grouped", model.SelectedIncidentRecommendedAction);
        model.IncidentSearchText = "tablet";
        Assert.Single(model.Incidents);
        model.SelectedIncidentStatusFilter = "Open";
        Assert.Empty(model.Incidents);
        model.SelectedIncidentStatusFilter = null!;
        Assert.Single(model.Incidents);
        model.IncidentSearchText = null!;
        Assert.Equal(4, model.Incidents.Count);

        model.SelectedIncident = model.Incidents.Single(incident => incident.Title == "Port opened");
        Assert.Contains("Grouped by app", model.SelectedIncident!.Grouping);
        Assert.Contains("High because single event", model.SelectedIncidentSeverityExplanation);
        Assert.Contains("Escalate if unexpected, or Watch", model.SelectedIncidentRecommendedAction);
        model.SelectedIncidentNotes = "Confirmed expected remote tool.";
        await model.SaveSelectedIncidentNotesAsync(CancellationToken.None);
        Assert.Equal("Confirmed expected remote tool.", repository.IncidentUpserts[^1].UserNotes);
        Assert.Contains("Saved notes", model.StatusMessage);

        model.PrepareSelectedIncidentExport();
        Assert.Contains("Prepared export", model.StatusMessage);
        await model.CreateRuleFromSelectedIncidentAsync(CancellationToken.None);
        Assert.Contains("groupKey", model.SelectedIncidentRuleSuggestion);
        Assert.Contains("Disabled rule suggestion created", model.SelectedIncidentRuleWizard);

        model.SelectedIncident = model.Incidents.Single(incident => incident.Title == "Device joined");
        Assert.Contains("Grouped by device", model.SelectedIncident.Grouping);
        model.SelectedIncident = model.Incidents.Single(incident => incident.Title == "History item");
        Assert.Contains("Grouped by event", model.SelectedIncident.Grouping);
        Assert.Contains("Low because AccessWatch recorded single event", model.SelectedIncidentSeverityExplanation);
        Assert.Contains("Resolved: keep for history", model.SelectedIncidentRecommendedAction);
        Assert.Contains("Resolved:", model.SelectedIncidentTimeline);
        Assert.Contains("No analyst notes yet", model.SelectedIncidentEvidence);
    }
    /// <summary>
    /// Verifies incident workflow edge states remain friendly and safe.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_IncidentWorkflowEdges_HandleMissingSelectionAndDetachedRows()
    {
        var disconnected = new DashboardShellViewModel();

        Assert.Equal(string.Empty, disconnected.IncidentSearchText);
        disconnected.IncidentSearchText = null!;
        Assert.Equal(string.Empty, disconnected.IncidentSearchText);
        Assert.Equal("Select an incident to see whether Resolve, Watch, Escalate, or a rule is appropriate.", disconnected.SelectedIncidentRecommendedAction);
        disconnected.SelectedIncidentNotes = null!;
        Assert.Equal(string.Empty, disconnected.SelectedIncidentNotes);
        disconnected.SelectedIncidentStatusFilter = disconnected.SelectedIncidentStatusFilter;
        Assert.Equal("All", disconnected.SelectedIncidentStatusFilter);
        disconnected.SelectedIncident = CreateIncidentRow("Detached", "Detached summary.");
        await disconnected.SaveSelectedIncidentNotesAsync(CancellationToken.None);
        Assert.Equal("Incident notes are not connected for this dashboard session.", disconnected.StatusMessage);

        var repository = new FakeRepository();
        var detached = new DashboardShellViewModel(repository)
        {
            SelectedIncident = CreateIncidentRow("Detached", "Detached summary.")
        };
        detached.SelectedIncidentNotes = " Detached note ";

        await detached.SaveSelectedIncidentNotesAsync(CancellationToken.None);

        Assert.Equal("Detached note", Assert.Single(repository.IncidentUpserts).UserNotes);
        Assert.Contains("Saved notes", detached.StatusMessage);
    }
    /// <summary>
    /// Verifies stored rules can be previewed, enabled, disabled, and explained.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_Rules_LoadPreviewAndToggleActions()
    {
        var repository = new FakeRepository
        {
            Rules =
            [
                new AccessWatchRule
                {
                    RuleId = 7,
                    Name = "Watch remote admin",
                    Description = "Watch remote admin on office laptop.",
                    ConditionJson = JsonSerializer.Serialize(new
                    {
                        source = "IncidentSuggestion",
                        app = "Visual Studio",
                        device = "office-laptop",
                        port = 9443.5,
                        network = "Work",
                        signature = "TrustedSigned",
                        path = @"C:\\Tools\\remote.exe",
                        durationHours = 24,
                        groupKey = "app/device"
                    }),
                    RiskLevel = RiskLevel.High,
                    Action = NotificationAction.AskBeforeAllow,
                    Enabled = false,
                    CreatedUtc = new DateTimeOffset(2026, 6, 29, 12, 0, 0, TimeSpan.Zero),
                    UpdatedUtc = new DateTimeOffset(2026, 6, 29, 12, 5, 0, TimeSpan.Zero)
                },
                new AccessWatchRule
                {
                    RuleId = 8,
                    Name = "Device watch",
                    Description = "Watch the tablet briefly.",
                    ConditionJson = JsonSerializer.Serialize(new
                    {
                        mainDeviceId = 42,
                        expiresUtc = "2026-06-30T12:00:00Z",
                        recommendedAction = "Watch"
                    }),
                    RiskLevel = RiskLevel.Medium,
                    Action = NotificationAction.SoftNotify,
                    Enabled = true
                },
                new AccessWatchRule
                {
                    RuleId = 9,
                    Name = string.Empty,
                    Description = string.Empty,
                    ConditionJson = "{bad json",
                    RiskLevel = RiskLevel.Low,
                    Action = NotificationAction.SilentLog,
                    Enabled = true
                },
                new AccessWatchRule
                {
                    RuleId = 10,
                    Name = "Boolean path rule",
                    Description = "Exercises non-string rule condition values.",
                    ConditionJson = JsonSerializer.Serialize(new
                    {
                        signature = true,
                        path = new { folder = "Temp" }
                    }),
                    RiskLevel = RiskLevel.Low,
                    Action = NotificationAction.SilentLog,
                    Enabled = false
                },
                new AccessWatchRule
                {
                    RuleId = 11,
                    Name = "App only rule",
                    Description = "Exercises app-only change detection.",
                    ConditionJson = JsonSerializer.Serialize(new
                    {
                        app = "Skype"
                    }),
                    RiskLevel = RiskLevel.Medium,
                    Action = NotificationAction.SoftNotify,
                    Enabled = true
                },
                new AccessWatchRule
                {
                    RuleId = 12,
                    Name = "No condition rule",
                    Description = "Exercises empty and null condition values.",
                    ConditionJson = JsonSerializer.Serialize(new
                    {
                        app = (string?)null
                    }),
                    RiskLevel = RiskLevel.Low,
                    Action = NotificationAction.SilentLog,
                    Enabled = true
                },
                new AccessWatchRule
                {
                    RuleId = 13,
                    Name = "False signature rule",
                    Description = "Exercises false boolean condition values.",
                    ConditionJson = JsonSerializer.Serialize(new
                    {
                        signature = false
                    }),
                    RiskLevel = RiskLevel.Low,
                    Action = NotificationAction.SilentLog,
                    Enabled = false
                },
                new AccessWatchRule
                {
                    RuleId = 14,
                    Name = "Empty condition rule",
                    Description = "Exercises empty condition JSON.",
                    ConditionJson = string.Empty,
                    RiskLevel = RiskLevel.Low,
                    Action = NotificationAction.SilentLog,
                    Enabled = false
                }
            ]
        };
        var logger = new CapturingLogger<DashboardShellViewModel>();
        var model = new DashboardShellViewModel(repository, logger: logger);
        var changed = new List<string?>();
        model.PropertyChanged += (_, args) => changed.Add(args.PropertyName);

        Assert.Equal("Visible", model.RulesEmptyVisibility);

        model.PreviewSelectedRule();
        Assert.Equal("Select a rule before previewing it.", model.StatusMessage);
        await model.EnableSelectedRuleAsync(CancellationToken.None);
        Assert.Equal("Select a rule before enabling it.", model.StatusMessage);
        await model.DisableSelectedRuleAsync(CancellationToken.None);
        Assert.Equal("Select a rule before disabling it.", model.StatusMessage);
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Warning && entry.Message == "Rule preview requested without a selected rule.");
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Warning && entry.Message == "Rule enable requested without a selected rule.");
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Warning && entry.Message == "Rule disable requested without a selected rule.");

        await model.LoadAsync(CancellationToken.None);

        Assert.Equal(8, model.Rules.Count);
        Assert.Equal("Collapsed", model.RulesEmptyVisibility);
        Assert.True(model.CanApplyRuleAction);
        Assert.Contains("Rule: Watch remote admin", model.SelectedRuleDetail);
        Assert.Contains("App: Visual Studio", model.SelectedRule!.Conditions);
        Assert.Contains("Port: 9443.5", model.SelectedRule.Conditions);
        Assert.Contains("Temporary: watch for 24 hours", model.SelectedRule.Duration);
        Assert.Contains("quiet hours off", model.SelectedRule.QuietHours);
        Assert.Contains("Home network profile", model.SelectedRule.NetworkProfile);
        Assert.Contains("Review if the app signature", model.SelectedRule.ChangeDetection);
        Assert.Contains("In-app investigation summary", model.SelectedRule.AiSummary);
        Assert.Contains("disabled until you turn it on", model.SelectedRulePreview);
        Assert.Contains("Watch remote admin", model.SelectedRule.DetailText);
        Assert.Contains("2026", model.SelectedRule.Created);
        Assert.Contains("2026", model.SelectedRule.Updated);
        Assert.Contains(nameof(DashboardShellViewModel.SelectedRule), changed);
        Assert.Contains(nameof(DashboardShellViewModel.CanApplyRuleAction), changed);

        model.PreviewSelectedRule();
        Assert.Contains("Previewed rule Watch remote admin", model.StatusMessage);
        Assert.Contains("Action: AskBeforeAllow", model.SelectedRulePreview);
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Information && entry.Message == "Previewed rule 7.");

        await model.EnableSelectedRuleAsync(CancellationToken.None);
        Assert.True(repository.RuleUpserts[^1].Enabled);
        Assert.True(model.SelectedRule!.IsEnabled);
        Assert.Contains("Enabled rule", model.StatusMessage);
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Information && entry.Message == "Set rule 1 enabled state to True.");

        model.SelectedRule = model.Rules.Single(rule => rule.Name == "Device watch");
        Assert.Contains("Temporary until 2026-06-30T12:00:00Z", model.SelectedRule.Duration);
        Assert.Contains("Review if this trusted app or device changes identity", model.SelectedRule.ChangeDetection);

        model.SelectedRule = model.Rules.Single(rule => rule.Name == "Unnamed rule");
        Assert.Contains("Review matches before trusting", model.SelectedRule.ChangeDetection);
        Assert.Contains("Permanent until disabled", model.SelectedRule.Duration);

        model.SelectedRule = model.Rules.Single(rule => rule.Name == "Boolean path rule");
        Assert.Contains("Signature: true", model.SelectedRule.Conditions);
        Assert.Contains("Path: {", model.SelectedRule.Conditions);

        model.SelectedRule = model.Rules.Single(rule => rule.Name == "App only rule");
        Assert.Contains("Review if this trusted app or device changes identity", model.SelectedRule.ChangeDetection);

        model.SelectedRule = model.Rules.Single(rule => rule.Name == "No condition rule");
        Assert.Contains("No specific conditions stored yet", model.SelectedRule.Conditions);
        Assert.Contains("Review matches before trusting", model.SelectedRule.ChangeDetection);

        model.SelectedRule = model.Rules.Single(rule => rule.Name == "False signature rule");
        Assert.Contains("Signature: false", model.SelectedRule.Conditions);

        model.SelectedRule = model.Rules[0];
        model.ApplySettings();
        Assert.Equal(model.Rules[0].RuleId, model.SelectedRule!.RuleId);

        model.SelectedRule = null;
        model.SelectedQuietHours = "22-7";
        model.SelectedNetworkProfile = "Work";
        model.ApplySettings();
        Assert.Equal("22-7", model.CurrentQuietHours);
        Assert.Equal("Work", model.CurrentNetworkProfile);
        Assert.Contains("10 PM to 7 AM", model.Rules[0].QuietHours);
        Assert.NotNull(model.SelectedRule);
        Assert.Contains("Work network profile", model.Rules[0].NetworkProfile);

        model.SelectedRule = model.Rules[0] with { RuleId = 999 };
        model.SelectedQuietHours = "23-6";
        model.SelectedNetworkProfile = "Public";
        model.ApplySettings();
        Assert.Contains("11 PM to 6 AM", model.Rules[0].QuietHours);
        Assert.Contains("Public Wi-Fi profile", model.Rules[0].NetworkProfile);
        Assert.Contains("Public network rules", model.SettingsStatus);

        model.SelectedQuietHours = null!;
        model.SelectedNetworkProfile = null!;
        Assert.Equal("23-6", model.SelectedQuietHours);
        Assert.Equal("Public", model.SelectedNetworkProfile);

        model.SelectedRule = model.Rules[0] with { RiskLevel = "NotARisk", Action = "NotAnAction", ConditionJson = string.Empty };
        model.Rules.Clear();
        repository.NextRuleUpsertId = 0;
        await model.DisableSelectedRuleAsync(CancellationToken.None);
        Assert.False(repository.RuleUpserts[^1].Enabled);
        Assert.Single(model.Rules);
        Assert.Contains("Disabled rule", model.StatusMessage);

        model.SelectedRule = null;
        Assert.False(model.CanApplyRuleAction);
        Assert.Equal("Select a rule to see its conditions, action, duration, and safety notes.", model.SelectedRuleDetail);
        Assert.Equal("Select a rule to preview what it would affect.", model.SelectedRulePreview);

        var detachedLogger = new CapturingLogger<DashboardShellViewModel>();
        var detached = new DashboardShellViewModel(logger: detachedLogger)
        {
            SelectedRule = model.Rules[0]
        };
        await detached.EnableSelectedRuleAsync(CancellationToken.None);
        Assert.Equal("Rule actions are not connected for this dashboard session.", detached.StatusMessage);
        await detached.DisableSelectedRuleAsync(CancellationToken.None);
        Assert.Equal("Rule actions are not connected for this dashboard session.", detached.StatusMessage);
        Assert.Contains(detachedLogger.Entries, entry => entry.Level == LogLevel.Warning && entry.Message == "Rule enable requested without a connected repository.");
        Assert.Contains(detachedLogger.Entries, entry => entry.Level == LogLevel.Warning && entry.Message == "Rule disable requested without a connected repository.");
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
        var logger = new CapturingLogger<DashboardShellViewModel>();
        var model = new DashboardShellViewModel(repository, logger: logger);
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
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Information && entry.Message == "Created disabled rule suggestion 1 from incident 55.");
        using (var document = JsonDocument.Parse(model.SelectedIncidentRuleSuggestion))
        {
            Assert.Equal(55, document.RootElement.GetProperty("incidentId").GetInt64());
            Assert.Equal(9, document.RootElement.GetProperty("mainApplicationId").GetInt64());
            Assert.Equal("Medium", document.RootElement.GetProperty("riskLevel").GetString());
        }

        await model.WatchSelectedIncidentAsync(CancellationToken.None);

        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Information && entry.Message.Contains("Applied incident action Watching to incident 55; status Watching, risk Medium."));
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
    /// Verifies Support bridge mode sends redacted incident context and displays the in-app result.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_CreateSelectedIncidentAiReview_WithSupportBridge_DisplaysBridgeResult()
    {
        var settings = new AccessWatchSettings { AiMode = AiMode.SupportBridge };
        var bridge = new FakeAiInvestigationBridge(new AiInvestigationResult(
            true,
            "Support Bridge",
            "The listener appears local-only but still needs process identity confirmation.",
            "Watch until the owning process is confirmed.",
            "Medium",
            "{}"));
        var model = new DashboardShellViewModel(
            new FakeRepository(),
            settings: settings,
            aiHandoffService: new ManualAiHandoffService(),
            aiInvestigationBridge: bridge)
        {
            SelectedIncident = new DashboardIncidentItemViewModel(
                77,
                null,
                null,
                RiskLevel.High,
                IncidentStatus.Open,
                DateTimeOffset.UnixEpoch,
                DateTimeOffset.UnixEpoch,
                "Network port opened",
                "High",
                "Open",
                1,
                "Visual Studio on workstation",
                "Not recorded",
                "Not recorded",
                "Visual Studio opened TCP 127.0.0.1:23196 from 10.0.0.50 with MAC 02:AC:CE:55:10:01.")
        };

        await model.CreateSelectedIncidentAiReviewAsync(CancellationToken.None);

        Assert.True(model.HasIncidentAiReview);
        Assert.Equal("Support bridge review ready for Network port opened.", model.StatusMessage);
        Assert.Contains("AccessWatch support bridge review", model.SelectedIncidentAiReview);
        Assert.Contains("Provider: Support Bridge", model.SelectedIncidentAiReview);
        Assert.Contains("Watch until the owning process is confirmed.", model.SelectedIncidentAiReview);
        Assert.DoesNotContain("10.0.0.50", bridge.Request!.ContextJson);
        Assert.DoesNotContain("02:AC:CE:55:10:01", bridge.Request.ContextJson);
        Assert.Contains("[ip-address]", bridge.Request.ContextJson);
        Assert.Contains("[mac-address]", bridge.Request.ContextJson);
    }


    /// <summary>
    /// Verifies unavailable Support bridge results stay visible as unavailable in the app.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_CreateSelectedIncidentAiReview_WithUnavailableSupportBridge_DisplaysUnavailableResult()
    {
        var settings = new AccessWatchSettings { AiMode = AiMode.SupportBridge };
        var bridge = new FakeAiInvestigationBridge(AiInvestigationResult.Unavailable("Support Bridge", "Bridge is not running."));
        var model = new DashboardShellViewModel(
            new FakeRepository(),
            settings: settings,
            aiHandoffService: new ManualAiHandoffService(),
            aiInvestigationBridge: bridge)
        {
            SelectedIncident = new DashboardIncidentItemViewModel(
                79,
                null,
                null,
                RiskLevel.High,
                IncidentStatus.Open,
                DateTimeOffset.UnixEpoch,
                DateTimeOffset.UnixEpoch,
                "Network port opened",
                "High",
                "Open",
                1,
                "Target unavailable",
                "Not recorded",
                "Not recorded",
                "No sensitive details.")
        };

        await model.CreateSelectedIncidentAiReviewAsync(CancellationToken.None);

        Assert.Equal("Support bridge review unavailable for Network port opened.", model.StatusMessage);
        Assert.Contains("Status: Unavailable", model.SelectedIncidentAiReview);
        Assert.Contains("Bridge is not running.", model.SelectedIncidentAiReview);
    }

    /// <summary>
    /// Verifies Support bridge mode still requires the redaction handoff service.
    /// </summary>
    [Fact]
    public void DashboardShellViewModel_CanReviewIncidentWithAi_WithSupportBridgeWithoutRedactionService_IsFalse()
    {
        var model = new DashboardShellViewModel(
            new FakeRepository(),
            settings: new AccessWatchSettings { AiMode = AiMode.SupportBridge },
            aiInvestigationBridge: new FakeAiInvestigationBridge(AiInvestigationResult.Unavailable("Support Bridge", "Not used")))
        {
            SelectedIncident = new DashboardIncidentItemViewModel(
                80,
                null,
                null,
                RiskLevel.Low,
                IncidentStatus.Open,
                DateTimeOffset.UnixEpoch,
                DateTimeOffset.UnixEpoch,
                "Network port opened",
                "Low",
                "Open",
                1,
                "Target unavailable",
                "Not recorded",
                "Not recorded",
                "No sensitive details.")
        };

        Assert.False(model.CanReviewIncidentWithAi);
    }

    /// <summary>
    /// Verifies Support bridge mode explains when the bridge dependency is missing.
    /// </summary>
    [Fact]
    public void DashboardShellViewModel_CreateSelectedIncidentAiReview_WithSupportBridgeWithoutBridge_ExplainsMissingBridge()
    {
        var model = new DashboardShellViewModel(
            new FakeRepository(),
            settings: new AccessWatchSettings { AiMode = AiMode.SupportBridge },
            aiHandoffService: new ManualAiHandoffService())
        {
            SelectedIncident = new DashboardIncidentItemViewModel(
                78,
                null,
                null,
                RiskLevel.High,
                IncidentStatus.Open,
                DateTimeOffset.UnixEpoch,
                DateTimeOffset.UnixEpoch,
                "Network port opened",
                "High",
                "Open",
                1,
                "Target unavailable",
                "Not recorded",
                "Not recorded",
                "No sensitive details.")
        };

        Assert.False(model.CanReviewIncidentWithAi);
        model.CreateSelectedIncidentAiReview();

        Assert.Equal("Support bridge is not connected for this dashboard session.", model.StatusMessage);
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

        Assert.Equal("Turn on AI review in Settings before reviewing with AI.", disabledModel.StatusMessage);
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
        Assert.Equal("Possible outside connection path detected.", activity.Summary);
        Assert.Contains("Other devices may be able to connect to Windows Service Host on this PC.", activity.Detail);
        Assert.Contains("Evidence: Device office-printer", activity.Detail);
        Assert.Contains("A new listening TCP port appeared.", activity.Detail);
        Assert.Contains("NetworkReachable", activity.Detail);
        Assert.Equal("Open network services can let other devices try to reach this PC.", activity.WhyItMatters);
        Assert.Equal("If you do not recognize this app or port, watch it or block it.", activity.SuggestedAction);
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
        Assert.Equal("Camera access detected.", activity.Summary);
        Assert.Contains("Visual Studio is using the camera", activity.Detail);
        Assert.Contains("Outside sources usually reach the camera", activity.Detail);
        Assert.Contains("Evidence: Device office-laptop", activity.Detail);
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
        Assert.Equal("Camera access detected.", activity.Summary);
        Assert.Contains("Visual Studio is using the camera", activity.Detail);
        Assert.Contains("Outside sources usually reach the camera", activity.Detail);
        Assert.Contains("Evidence: Device office-laptop", activity.Detail);
        Assert.Contains("Visual Studio activated the camera.", activity.Detail);
        Assert.Contains("Local sensor access", activity.Detail);
        Assert.DoesNotContain("local:n/a", activity.Detail);
    }
    /// <summary>
    /// Verifies privacy-related recent activity leads with the protection concern instead of raw telemetry.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_UsesProtectionFirstPrivacyActivity()
    {
        var repository = new FakeRepository
        {
            Applications = [new AppIdentity { ApplicationId = 12, DisplayName = "Skype", ProcessName = "Skype" }],
            Events =
            [
                new NetworkEvent
                {
                    ApplicationId = 12,
                    EventType = "MicrophoneActivated",
                    Protocol = "Local",
                    Direction = "SensorAccess",
                    RiskLevel = RiskLevel.High,
                    Summary = "Skype started using the microphone.",
                    DetailsJson = "{ \"whatHappened\": \"Skype activated the microphone.\", \"app\": \"Skype\", \"processName\": \"Skype\", \"deviceName\": \"office-laptop\", \"reachability\": \"Local sensor access\" }"
                },
                new NetworkEvent
                {
                    EventType = "NewDeviceObserved",
                    Protocol = "ARP",
                    Direction = "NetworkObservation",
                    RiskLevel = RiskLevel.Medium,
                    Summary = "Unknown tablet joined the network.",
                    DetailsJson = "{ \"whatHappened\": \"Unknown tablet joined the local network.\", \"deviceName\": \"unknown-tablet\" }"
                }
            ]
        };
        var model = new DashboardShellViewModel(repository);

        await model.LoadAsync(CancellationToken.None);

        Assert.Collection(
            model.RecentActivity,
            microphone =>
            {
                Assert.Equal("Microphone access detected.", microphone.Summary);
                Assert.Contains("Skype is using the microphone", microphone.Detail);
                Assert.Contains("Outside sources usually reach the microphone", microphone.Detail);
                Assert.Equal("Microphone access can expose nearby conversations.", microphone.WhyItMatters);
                Assert.Equal("If you did not start this, close the app and watch or block it in AccessWatch.", microphone.SuggestedAction);
            },
            device =>
            {
                Assert.Equal("New network device detected.", device.Summary);
                Assert.Contains("A device appeared on your network.", device.Detail);
                Assert.Equal("Unknown devices can be harmless, but they should stay visible until recognized.", device.WhyItMatters);
                Assert.Equal("Trace the device before trusting or naming it.", device.SuggestedAction);
            });
    }

    /// <summary>
    /// Verifies incident explanations name the privacy or outside-access concern first.
    /// </summary>
    [Fact]
    public void DashboardShellViewModel_SelectedIncidentExplanation_UsesProtectionFocus()
    {
        var model = new DashboardShellViewModel();

        model.SelectedIncident = CreateIncidentRow("Microphone access", "Skype used the microphone.");
        Assert.Contains("Microphone use was detected", model.SelectedIncidentExplanation);

        model.SelectedIncident = CreateIncidentRow("Listening service", "A listening service opened.");
        Assert.Contains("possible outside connection path", model.SelectedIncidentExplanation);

        model.SelectedIncident = CreateIncidentRow("Remote service", "Remote access may be available.");
        Assert.Contains("possible outside connection path", model.SelectedIncidentExplanation);

        model.SelectedIncident = CreateIncidentRow("New device observed", "A new device joined.");
        Assert.Contains("A new network device was detected", model.SelectedIncidentExplanation);

        model.SelectedIncident = CreateIncidentRow("Unusual activity", "Something changed.");
        Assert.Contains("privacy, remote access, or network exposure", model.SelectedIncidentExplanation);
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
                Assert.Equal("Open network services can let other devices try to reach this PC.", second.WhyItMatters);
                Assert.Equal("If you do not recognize this app or port, watch it or block it.", second.SuggestedAction);
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
        Assert.All(model.RecentActivity, activity => Assert.Equal("If you do not recognize this app or port, watch it or block it.", activity.SuggestedAction));
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
    /// Verifies dashboard loads emit useful structured operational logs.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_WritesOperationalLogs()
    {
        var logger = new CapturingLogger<DashboardShellViewModel>();
        var repository = new FakeRepository
        {
            Devices = [new NetworkDevice { DeviceId = 1, Hostname = "office-laptop", IpAddress = "192.168.1.25", MacAddress = "02:AC:CE:55:20:25" }],
            Applications = [new AppIdentity { ApplicationId = 2, DisplayName = "Visual Studio", ProcessName = "devenv" }],
            Ports = [new ListeningPort { PortNumber = 9443, LocalAddress = "0.0.0.0" }],
            Events = [new NetworkEvent { EventType = "NewListeningPort", RiskLevel = RiskLevel.High, Summary = "Visual Studio opened a port." }],
            Incidents = [new Incident { IncidentId = 3, Title = "Port opened", Summary = "Visual Studio opened a port.", RiskLevel = RiskLevel.High, Status = IncidentStatus.Open, StartedUtc = DateTimeOffset.UnixEpoch, LastUpdatedUtc = DateTimeOffset.UnixEpoch }],
            Rules = [new AccessWatchRule { RuleId = 4, Name = "Watch Visual Studio", Description = "Watch the port.", ConditionJson = "{}", RiskLevel = RiskLevel.High, Action = NotificationAction.AskBeforeAllow }]
        };
        var model = new DashboardShellViewModel(repository, logger: logger);

        await model.LoadAsync(CancellationToken.None);

        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Information && entry.Message == "Loading dashboard data.");
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Information && entry.Message.Contains("Loaded dashboard data with 1 events, 1 ports, 1 incidents, 1 devices, 1 applications, and 1 rules."));
    }

    /// <summary>
    /// Verifies repository failures are shown as dashboard status instead of crashing the window.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_LoadAsync_ShowsRepositoryFailure()
    {
        var logger = new CapturingLogger<DashboardShellViewModel>();
        var failure = new InvalidOperationException("database offline");
        var model = new DashboardShellViewModel(new FakeRepository { Failure = failure }, logger: logger);

        await model.LoadAsync(CancellationToken.None);

        Assert.Contains("database offline", model.StatusMessage);
        Assert.False(model.IsLoading);
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Error && entry.Exception == failure && entry.Message == "Could not load dashboard data.");
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
        var logger = new CapturingLogger<DashboardShellViewModel>();
        var model = new DashboardShellViewModel(new FakeRepository(), logger: logger);

        await model.RunScanAsync(CancellationToken.None);

        Assert.Equal("Dashboard scan is not connected yet.", model.StatusMessage);
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Warning && entry.Message == "Dashboard scan requested without a connected scan function.");
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
        var logger = new CapturingLogger<DashboardShellViewModel>();
        var model = new DashboardShellViewModel(repository, _ =>
        {
            scanCount++;
            return Task.FromResult(3);
        }, logger: logger);

        await model.RunScanAsync(CancellationToken.None);

        Assert.Equal(1, scanCount);
        Assert.Single(model.RecentActivity);
        Assert.Equal("Scan completed. Created 3 new events.", model.StatusMessage);
        Assert.False(model.IsLoading);
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Information && entry.Message == "Running dashboard scan.");
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Information && entry.Message == "Dashboard scan completed with 3 new events.");
    }

    /// <summary>
    /// Verifies scan failures are shown as dashboard status instead of crashing the window.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_RunScanAsync_ShowsScanFailure()
    {
        var logger = new CapturingLogger<DashboardShellViewModel>();
        var model = new DashboardShellViewModel(new FakeRepository(), _ => throw new InvalidOperationException("scan failed"), logger: logger);

        await model.RunScanAsync(CancellationToken.None);

        Assert.Contains("scan failed", model.StatusMessage);
        Assert.False(model.IsLoading);
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Error && entry.Message == "Could not run dashboard scan." && entry.Exception is InvalidOperationException);
    }
    /// <summary>
    /// Verifies simulator requests report when no simulator function is connected.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_RunSimulationAsyncWithoutSimulator_ShowsDisconnectedState()
    {
        var logger = new CapturingLogger<DashboardShellViewModel>();
        var model = new DashboardShellViewModel(new FakeRepository(), logger: logger);

        await model.RunSimulationAsync(CancellationToken.None);

        Assert.Equal("Event simulator is not connected yet.", model.StatusMessage);
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Warning && entry.Message == "Dashboard simulation requested without a connected simulator function.");
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
        var logger = new CapturingLogger<DashboardShellViewModel>();
        var model = new DashboardShellViewModel(
            repository,
            null,
            _ =>
            {
                simulationCount++;
                return Task.FromResult(1);
            },
            logger: logger);

        await model.RunSimulationAsync(CancellationToken.None);

        Assert.Equal(1, simulationCount);
        Assert.Single(model.RecentActivity);
        Assert.Equal("Simulation completed. Created 1 event.", model.StatusMessage);
        Assert.False(model.IsLoading);
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Information && entry.Message == "Running dashboard simulation.");
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Information && entry.Message == "Dashboard simulation completed with 1 new events.");
    }

    /// <summary>
    /// Verifies simulator failures are shown as dashboard status instead of crashing the window.
    /// </summary>
    [Fact]
    public async Task DashboardShellViewModel_RunSimulationAsync_ShowsSimulationFailure()
    {
        var logger = new CapturingLogger<DashboardShellViewModel>();
        var model = new DashboardShellViewModel(new FakeRepository(), null, _ => throw new InvalidOperationException("simulator failed"), logger: logger);

        await model.RunSimulationAsync(CancellationToken.None);

        Assert.Contains("simulator failed", model.StatusMessage);
        Assert.False(model.IsLoading);
        Assert.Contains(logger.Entries, entry => entry.Level == LogLevel.Error && entry.Message == "Could not run dashboard simulation." && entry.Exception is InvalidOperationException);
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

    [ExcludeFromCodeCoverage]
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<CapturedLogEntry> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            return NullScope.Instance;
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return true;
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Entries.Add(new CapturedLogEntry(logLevel, formatter(state, exception), exception));
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();

            public void Dispose()
            {
            }
        }
    }

    [ExcludeFromCodeCoverage]
    private sealed record CapturedLogEntry(LogLevel Level, string Message, Exception? Exception);

    private sealed class ReviewOnlyFirewallPlanner : IFirewallEnforcementPlanner
    {
        public FirewallEnforcementPlan CreateBlockDevicePlan(NetworkDevice device)
        {
            return new FirewallEnforcementPlan(
                "Device",
                device.Hostname ?? "Device",
                "Review the device before enforcement.",
                "This plan intentionally has no command yet.",
                [],
                false);
        }

        public FirewallEnforcementPlan CreateBlockApplicationPlan(AppIdentity application)
        {
            return new FirewallEnforcementPlan(
                "Application",
                application.DisplayName ?? "Application",
                "Review the application before enforcement.",
                "This plan intentionally has no command yet.",
                [],
                false);
        }
    }

    private sealed class FakeFirewallExecutor(bool succeeds) : IFirewallEnforcementExecutor
    {
        public Task<FirewallEnforcementResult> ApplyAsync(FirewallEnforcementPlan plan, CancellationToken cancellationToken)
        {
            return Task.FromResult(new FirewallEnforcementResult(
                succeeds,
                succeeds ? $"Applied firewall protection for {plan.TargetName}." : $"Could not apply protection for {plan.TargetName}.",
                succeeds ? $"AccessWatch applied {plan.PowerShellCommands.Count} Windows Firewall rule(s)." : "Firewall rule failed.",
                succeeds ? plan.PowerShellCommands : []));
        }
    }

    private sealed class FakeAiInvestigationBridge(AiInvestigationResult result) : IAiInvestigationBridge
    {
        public AiInvestigationRequest? Request { get; private set; }

        public Task<AiInvestigationResult> ReviewIncidentAsync(
            AiInvestigationRequest request,
            AccessWatchSettings settings,
            CancellationToken cancellationToken)
        {
            Request = request;
            return Task.FromResult(result);
        }
    }

    private static DashboardIncidentItemViewModel CreateIncidentRow(string title, string summary) =>
        new(
            1,
            null,
            null,
            RiskLevel.High,
            IncidentStatus.Open,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            title,
            RiskLevel.High.ToString(),
            IncidentStatus.Open.ToString(),
            1,
            "Target unavailable",
            "Now",
            "Now",
            summary);

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

        public long? NextRuleUpsertId { get; set; }

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
            var ruleId = NextRuleUpsertId ?? RuleUpserts.Count;
            NextRuleUpsertId = null;
            return Task.FromResult((long)ruleId);
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



