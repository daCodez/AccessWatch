using System.Collections.ObjectModel;
using System.ComponentModel;
using AccessWatch.Core;

namespace AccessWatch.App.ViewModels;

/// <summary>
/// Represents a simple dashboard page entry for the MVP shell.
/// </summary>
public sealed record DashboardPageViewModel(string Name, string Summary);

/// <summary>
/// Represents a dashboard metric shown in the overview.
/// </summary>
public sealed record DashboardMetricViewModel(string Name, int Count);

/// <summary>
/// Represents a recent dashboard activity row.
/// </summary>
public sealed record DashboardActivityItemViewModel(string Kind, string Summary, string Detail);

/// <summary>
/// Provides dashboard data loaded from the AccessWatch repository.
/// </summary>
public sealed class DashboardShellViewModel : INotifyPropertyChanged
{
    private readonly IAccessWatchRepository? repository;
    private readonly Func<CancellationToken, Task<int>>? scanAsync;
    private string statusMessage = "Connect the service or run a scan to load AccessWatch activity.";
    private bool isLoading;

    /// <summary>
    /// Initializes a dashboard shell without live data access.
    /// </summary>
    public DashboardShellViewModel()
    {
    }

    /// <summary>
    /// Initializes a dashboard shell backed by the AccessWatch repository.
    /// </summary>
    /// <param name="repository">Repository used to load dashboard data.</param>
    /// <param name="scanAsync">Optional scan action that persists fresh observations.</param>
    public DashboardShellViewModel(
        IAccessWatchRepository repository,
        Func<CancellationToken, Task<int>>? scanAsync = null)
    {
        this.repository = repository;
        this.scanAsync = scanAsync;
    }

    /// <summary>
    /// Raised when dashboard state changes.
    /// </summary>
    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>
    /// Gets the visible dashboard pages.
    /// </summary>
    public IReadOnlyList<DashboardPageViewModel> Pages { get; } =
    [
        new("Overview", "Recent risk posture and service status."),
        new("Devices", "Known, guest, watched, and blocked devices."),
        new("Applications", "Resolved app identities and trust decisions."),
        new("Ports", "Current and historical listening ports."),
        new("Incidents", "Grouped low-noise security events."),
        new("Settings", "Protection mode and AI handoff settings.")
    ];

    /// <summary>
    /// Gets overview metrics loaded from storage.
    /// </summary>
    public ObservableCollection<DashboardMetricViewModel> Metrics { get; } = [];

    /// <summary>
    /// Gets recent activity loaded from storage.
    /// </summary>
    public ObservableCollection<DashboardActivityItemViewModel> RecentActivity { get; } = [];

    /// <summary>
    /// Gets the current dashboard load status.
    /// </summary>
    public string StatusMessage
    {
        get => statusMessage;
        private set
        {
            statusMessage = value;
            OnPropertyChanged(nameof(StatusMessage));
        }
    }

    /// <summary>
    /// Gets whether data is currently loading.
    /// </summary>
    public bool IsLoading
    {
        get => isLoading;
        private set
        {
            isLoading = value;
            OnPropertyChanged(nameof(IsLoading));
        }
    }

    /// <summary>
    /// Loads dashboard data from the repository.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task LoadAsync(CancellationToken cancellationToken)
    {
        if (repository is null)
        {
            StatusMessage = "Dashboard data is not connected yet.";
            return;
        }

        IsLoading = true;
        try
        {
            await repository.InitializeAsync(cancellationToken);
            var devices = await repository.ListRecentDevicesAsync(500, cancellationToken);
            var applications = await repository.ListRecentApplicationsAsync(500, cancellationToken);
            var ports = await repository.ListRecentPortsAsync(500, cancellationToken);
            var events = await repository.ListRecentNetworkEventsAsync(50, cancellationToken);

            ReplaceMetrics(devices.Count, applications.Count, ports.Count, events.Count);
            ReplaceRecentActivity(events, ports, devices);
            StatusMessage = events.Count == 0 && ports.Count == 0 && devices.Count == 0
                ? "No stored activity yet. Start the AccessWatch service to record listening ports and devices."
                : $"Loaded {events.Count} events, {ports.Count} ports, and {devices.Count} devices.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Could not load AccessWatch data: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }


    /// <summary>
    /// Runs a scan, saves any new observations, and reloads dashboard data.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task RunScanAsync(CancellationToken cancellationToken)
    {
        if (scanAsync is null)
        {
            StatusMessage = "Dashboard scan is not connected yet.";
            return;
        }

        IsLoading = true;
        try
        {
            var createdEvents = await scanAsync(cancellationToken);
            await LoadAsync(cancellationToken);
            StatusMessage = $"Scan completed. Created {createdEvents} new events.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Could not run AccessWatch scan: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }
    private void ReplaceMetrics(int devices, int applications, int ports, int events)
    {
        Metrics.Clear();
        Metrics.Add(new DashboardMetricViewModel("Devices", devices));
        Metrics.Add(new DashboardMetricViewModel("Apps", applications));
        Metrics.Add(new DashboardMetricViewModel("Ports", ports));
        Metrics.Add(new DashboardMetricViewModel("Events", events));
    }

    private void ReplaceRecentActivity(
        IReadOnlyList<NetworkEvent> events,
        IReadOnlyList<ListeningPort> ports,
        IReadOnlyList<NetworkDevice> devices)
    {
        RecentActivity.Clear();
        foreach (var networkEvent in events.Take(8))
        {
            RecentActivity.Add(new DashboardActivityItemViewModel(
                networkEvent.RiskLevel.ToString(),
                networkEvent.Summary,
                $"{networkEvent.EventType} on {networkEvent.DestinationIp ?? "local"}:{networkEvent.DestinationPort?.ToString() ?? "n/a"}"));
        }

        if (RecentActivity.Count == 0)
        {
            foreach (var port in ports.Take(5))
            {
                RecentActivity.Add(new DashboardActivityItemViewModel(
                    port.RiskStatus.ToString(),
                    $"Port {port.PortNumber} is listening on {port.LocalAddress}.",
                    port.Application?.DisplayName ?? "Application identity unavailable in list view."));
            }
        }

        if (RecentActivity.Count == 0)
        {
            foreach (var device in devices.Take(5))
            {
                RecentActivity.Add(new DashboardActivityItemViewModel(
                    device.TrustStatus.ToString(),
                    $"Device observed at {device.IpAddress}.",
                    device.MacAddress ?? "MAC address unavailable"));
            }
        }
    }

    private void OnPropertyChanged(string propertyName)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
