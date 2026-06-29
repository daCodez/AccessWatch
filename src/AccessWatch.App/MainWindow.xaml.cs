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

    /// <summary>
    /// Initializes the dashboard shell window.
    /// </summary>
    public MainWindow()
    {
        InitializeComponent();
        var repository = new SqlServerAccessWatchRepository(new AccessWatchDatabaseOptions());
        var coordinator = new ServiceScanCoordinator(
            repository,
            new ListeningPortScanner(new AppIdentityResolver()),
            new NetworkDeviceDiscoveryService(),
            new RiskScoringService(),
            new AccessWatchSettings(),
            new NotificationMessageFactory(),
            NullLogger<ServiceScanCoordinator>.Instance);
        viewModel = new DashboardShellViewModel(repository, async cancellationToken =>
        {
            await coordinator.InitializeAsync(cancellationToken);
            return await coordinator.RunListeningPortScanAsync(cancellationToken);
        });
        DataContext = viewModel;
        Loaded += OnLoaded;
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
}
