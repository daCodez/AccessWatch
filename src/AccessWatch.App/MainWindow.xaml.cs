using System.Windows;
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
        var coordinator = new ServiceScanCoordinator(
            repository,
            new ListeningPortScanner(new AppIdentityResolver()),
            new NetworkDeviceDiscoveryService(),
            new RiskScoringService(),
            new AccessWatchSettings(),
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
            simulator.TriggerDemoEventAsync);
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
}

