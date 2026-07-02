using System.Windows;
using AccessWatch.AI;
using AccessWatch.App.ViewModels;
using AccessWatch.Core;
using AccessWatch.Data;
using AccessWatch.Detection;
using AccessWatch.Notifications;
using AccessWatch.Rules;
using AccessWatch.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace AccessWatch.App;

/// <summary>
/// Interaction logic for the AccessWatch dashboard window.
/// </summary>
public partial class MainWindow : Window
{
    private readonly DashboardShellViewModel viewModel;
    private readonly WindowsTrayNotificationService notificationService;

    /// <summary>
    /// Initializes the dashboard shell window.
    /// </summary>
    public MainWindow()
    {
        InitializeComponent();
        var repository = new SqlServerAccessWatchRepository(new AccessWatchDatabaseOptions());
        notificationService = new WindowsTrayNotificationService();
        var notificationFactory = new NotificationMessageFactory();
        var settings = new AccessWatchSettings();
        var coordinator = new ServiceScanCoordinator(
            repository,
            new ListeningPortScanner(new AppIdentityResolver()),
            new NetworkDeviceDiscoveryService(),
            new RiskScoringService(),
            settings,
            notificationFactory,
            notificationService,
            NullLogger<ServiceScanCoordinator>.Instance);
        var simulator = new AccessWatchEventSimulator(repository, notificationFactory, notificationService);
        viewModel = new DashboardShellViewModel(
            repository,
            async cancellationToken =>
            {
                await coordinator.InitializeAsync(cancellationToken);
                return await coordinator.RunListeningPortScanAsync(cancellationToken);
            },
            simulator.TriggerDemoEventAsync,
            settings,
            new ManualAiHandoffService());
        DataContext = viewModel;
        Loaded += OnLoaded;
        Closed += OnClosed;
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        notificationService.Dispose();
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        await viewModel.LoadAsync(CancellationToken.None);
    }

    private async void OnRefreshClick(object sender, RoutedEventArgs e)
    {
        await viewModel.LoadAsync(CancellationToken.None);
    }

    private async void OnScanNowClick(object sender, RoutedEventArgs e)
    {
        await viewModel.RunScanAsync(CancellationToken.None);
    }

    private async void OnSimulateEventClick(object sender, RoutedEventArgs e)
    {
        await viewModel.RunSimulationAsync(CancellationToken.None);
    }

    private async void OnSaveDeviceAliasClick(object sender, RoutedEventArgs e)
    {
        await viewModel.SaveSelectedDeviceAliasAsync(CancellationToken.None);
    }

    private async void OnClearDeviceAliasClick(object sender, RoutedEventArgs e)
    {
        await viewModel.ClearSelectedDeviceAliasAsync(CancellationToken.None);
    }
    private async void OnTrustDeviceClick(object sender, RoutedEventArgs e)
    {
        await viewModel.ApplySelectedDeviceTrustDecisionAsync(TrustStatus.Trusted, CancellationToken.None);
    }

    private async void OnWatchDeviceClick(object sender, RoutedEventArgs e)
    {
        await viewModel.ApplySelectedDeviceTrustDecisionAsync(TrustStatus.KnownWatched, CancellationToken.None);
    }

    private async void OnBlockDeviceClick(object sender, RoutedEventArgs e)
    {
        await viewModel.ApplySelectedDeviceTrustDecisionAsync(TrustStatus.Blocked, CancellationToken.None);
    }

    private async void OnTrustApplicationClick(object sender, RoutedEventArgs e)
    {
        await viewModel.ApplySelectedApplicationTrustDecisionAsync(TrustStatus.Trusted, CancellationToken.None);
    }

    private async void OnWatchApplicationClick(object sender, RoutedEventArgs e)
    {
        await viewModel.ApplySelectedApplicationTrustDecisionAsync(TrustStatus.KnownWatched, CancellationToken.None);
    }

    private async void OnBlockApplicationClick(object sender, RoutedEventArgs e)
    {
        await viewModel.ApplySelectedApplicationTrustDecisionAsync(TrustStatus.Blocked, CancellationToken.None);
    }


    private void OnInvestigatePortClick(object sender, RoutedEventArgs e)
    {
        viewModel.InvestigateSelectedPort();
    }
    private async void OnResolveIncidentClick(object sender, RoutedEventArgs e)
    {
        await viewModel.ResolveSelectedIncidentAsync(CancellationToken.None);
    }

    private async void OnWatchIncidentClick(object sender, RoutedEventArgs e)
    {
        await viewModel.WatchSelectedIncidentAsync(CancellationToken.None);
    }

    private async void OnEscalateIncidentClick(object sender, RoutedEventArgs e)
    {
        await viewModel.EscalateSelectedIncidentAsync(CancellationToken.None);
    }

    private async void OnCreateIncidentRuleClick(object sender, RoutedEventArgs e)
    {
        await viewModel.CreateRuleFromSelectedIncidentAsync(CancellationToken.None);
    }

    private void OnReviewIncidentWithAiClick(object sender, RoutedEventArgs e)
    {
        viewModel.CreateSelectedIncidentAiReview();
    }

    private void OnCopyIncidentForChatGptClick(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(viewModel.SelectedIncidentAiReview))
        {
            System.Windows.Clipboard.SetText(viewModel.SelectedIncidentAiReview);
            viewModel.MarkIncidentChatGptCopied();
        }
    }

    private void OnApplySettingsClick(object sender, RoutedEventArgs e)
    {
        viewModel.ApplySettings();
    }

    private void OnResetSettingsClick(object sender, RoutedEventArgs e)
    {
        viewModel.ResetSettingsSelections();
    }
}
