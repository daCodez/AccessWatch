using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Text.Json;
using AccessWatch.Core;
using AppIdentity = AccessWatch.Core.ApplicationIdentity;

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
public sealed record DashboardActivityItemViewModel(
    string Kind,
    string ApplicationName,
    string Summary,
    string Detail,
    string ApplicationIdentity,
    string WhyItMatters,
    string SuggestedAction);

/// <summary>
/// Represents a device row shown in the dashboard.
/// </summary>
public sealed record DashboardDeviceItemViewModel(
    string Name,
    string IpAddress,
    string MacAddress,
    string Vendor,
    string TrustStatus,
    string RiskStatus,
    string LastSeen,
    string Detail);

/// <summary>
/// Represents an application row shown in the dashboard.
/// </summary>
public sealed record DashboardApplicationItemViewModel(
    string Name,
    string ProcessName,
    string Publisher,
    string SignatureStatus,
    string TrustStatus,
    string LastSeen,
    string Detail);

/// <summary>
/// Provides dashboard data loaded from the AccessWatch repository.
/// </summary>
public sealed class DashboardShellViewModel : INotifyPropertyChanged
{
    private readonly IAccessWatchRepository? repository;
    private readonly Func<CancellationToken, Task<int>>? scanAsync;
    private DashboardPageViewModel selectedPage;
    private string statusMessage = "Connect the service or run a scan to load AccessWatch activity.";
    private string activeOperation = string.Empty;
    private bool isLoading;

    /// <summary>
    /// Initializes a dashboard shell without live data access.
    /// </summary>
    public DashboardShellViewModel()
    {
        selectedPage = Pages[0];
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
        selectedPage = Pages[0];
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
    /// Gets or sets the page selected by the sidebar.
    /// </summary>
    public DashboardPageViewModel? SelectedPage
    {
        get => selectedPage;
        set
        {
            if (Equals(selectedPage, value))
            {
                return;
            }

            selectedPage = value ?? Pages[0];
            OnPropertyChanged(nameof(SelectedPage));
            OnPropertyChanged(nameof(SelectedPageTitle));
            OnPropertyChanged(nameof(SelectedPageSummary));
            OnPropertyChanged(nameof(IsOverviewSelected));
            OnPropertyChanged(nameof(IsDevicesSelected));
            OnPropertyChanged(nameof(IsApplicationsSelected));
            OnPropertyChanged(nameof(IsPlaceholderSelected));
            OnPropertyChanged(nameof(OverviewVisibility));
            OnPropertyChanged(nameof(DevicesVisibility));
            OnPropertyChanged(nameof(ApplicationsVisibility));
            OnPropertyChanged(nameof(PlaceholderVisibility));
        }
    }

    /// <summary>
    /// Gets the selected page title.
    /// </summary>
    public string SelectedPageTitle => selectedPage.Name;

    /// <summary>
    /// Gets the selected page summary.
    /// </summary>
    public string SelectedPageSummary => selectedPage.Summary;

    /// <summary>
    /// Gets whether the overview page is selected.
    /// </summary>
    public bool IsOverviewSelected => SelectedPageTitle == "Overview";

    /// <summary>
    /// Gets whether the devices page is selected.
    /// </summary>
    public bool IsDevicesSelected => SelectedPageTitle == "Devices";

    /// <summary>
    /// Gets whether the applications page is selected.
    /// </summary>
    public bool IsApplicationsSelected => SelectedPageTitle == "Applications";

    /// <summary>
    /// Gets whether the selected page is not yet implemented.
    /// </summary>
    public bool IsPlaceholderSelected => !IsOverviewSelected && !IsDevicesSelected && !IsApplicationsSelected;

    /// <summary>
    /// Gets WPF visibility text for the overview panel.
    /// </summary>
    public string OverviewVisibility => ToVisibility(IsOverviewSelected);

    /// <summary>
    /// Gets WPF visibility text for the devices panel.
    /// </summary>
    public string DevicesVisibility => ToVisibility(IsDevicesSelected);

    /// <summary>
    /// Gets WPF visibility text for the applications panel.
    /// </summary>
    public string ApplicationsVisibility => ToVisibility(IsApplicationsSelected);

    /// <summary>
    /// Gets WPF visibility text for the placeholder panel.
    /// </summary>
    public string PlaceholderVisibility => ToVisibility(IsPlaceholderSelected);

    /// <summary>
    /// Gets overview metrics loaded from storage.
    /// </summary>
    public ObservableCollection<DashboardMetricViewModel> Metrics { get; } = [];

    /// <summary>
    /// Gets recent activity loaded from storage.
    /// </summary>
    public ObservableCollection<DashboardActivityItemViewModel> RecentActivity { get; } = [];

    /// <summary>
    /// Gets recent devices loaded from storage.
    /// </summary>
    public ObservableCollection<DashboardDeviceItemViewModel> Devices { get; } = [];

    /// <summary>
    /// Gets recent applications loaded from storage.
    /// </summary>
    public ObservableCollection<DashboardApplicationItemViewModel> Applications { get; } = [];

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
            OnPropertyChanged(nameof(CanRunActions));
            OnPropertyChanged(nameof(LoadingVisibility));
            OnPropertyChanged(nameof(ScanButtonText));
            OnPropertyChanged(nameof(RefreshButtonText));
            OnPropertyChanged(nameof(ProgressMessage));
        }
    }

    /// <summary>
    /// Gets whether dashboard actions can be started.
    /// </summary>
    public bool CanRunActions => !IsLoading;

    /// <summary>
    /// Gets WPF visibility text for the progress indicator.
    /// </summary>
    public string LoadingVisibility => ToVisibility(IsLoading);

    /// <summary>
    /// Gets the current scan button label.
    /// </summary>
    public string ScanButtonText => IsLoading && activeOperation == "Scan" ? "Scanning..." : "Scan now";

    /// <summary>
    /// Gets the current refresh button label.
    /// </summary>
    public string RefreshButtonText => IsLoading && activeOperation == "Refresh" ? "Refreshing..." : "Refresh";

    /// <summary>
    /// Gets the current progress indicator label.
    /// </summary>
    public string ProgressMessage => activeOperation == "Scan"
        ? "Searching network devices and listening ports..."
        : "Refreshing dashboard data...";

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

        var ownsLoading = !IsLoading;
        if (ownsLoading)
        {
            BeginLoading("Refresh", "Refreshing dashboard data...");
        }

        try
        {
            await repository.InitializeAsync(cancellationToken);
            var devices = await repository.ListRecentDevicesAsync(500, cancellationToken);
            var applications = await repository.ListRecentApplicationsAsync(500, cancellationToken);
            var ports = await repository.ListRecentPortsAsync(500, cancellationToken);
            var events = await repository.ListRecentNetworkEventsAsync(50, cancellationToken);

            ReplaceMetrics(devices.Count, applications.Count, ports.Count, events.Count);
            ReplaceDevices(devices);
            ReplaceApplications(applications);
            ReplaceRecentActivity(events, applications, ports, devices);
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
            if (ownsLoading)
            {
                EndLoading();
            }
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

        BeginLoading("Scan", "Scanning network devices and listening ports...");
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
            EndLoading();
        }
    }

    private void BeginLoading(string operation, string message)
    {
        activeOperation = operation;
        StatusMessage = message;
        IsLoading = true;
        OnPropertyChanged(nameof(ScanButtonText));
        OnPropertyChanged(nameof(RefreshButtonText));
        OnPropertyChanged(nameof(ProgressMessage));
    }

    private void EndLoading()
    {
        IsLoading = false;
        activeOperation = string.Empty;
        OnPropertyChanged(nameof(ScanButtonText));
        OnPropertyChanged(nameof(RefreshButtonText));
        OnPropertyChanged(nameof(ProgressMessage));
    }

    private static string ToVisibility(bool isVisible)
    {
        return isVisible ? "Visible" : "Collapsed";
    }

    private void ReplaceMetrics(int devices, int applications, int ports, int events)
    {
        Metrics.Clear();
        Metrics.Add(new DashboardMetricViewModel("Devices", devices));
        Metrics.Add(new DashboardMetricViewModel("Apps", applications));
        Metrics.Add(new DashboardMetricViewModel("Ports", ports));
        Metrics.Add(new DashboardMetricViewModel("Events", events));
    }

    private void ReplaceDevices(IReadOnlyList<NetworkDevice> devices)
    {
        Devices.Clear();
        foreach (var device in devices.Take(100))
        {
            Devices.Add(new DashboardDeviceItemViewModel(
                FirstUseful(device.Hostname, device.IpAddress, "Unknown device"),
                device.IpAddress,
                FirstUseful(device.MacAddress, "MAC address unavailable"),
                FirstUseful(device.Vendor, "Vendor unavailable"),
                device.TrustStatus.ToString(),
                device.RiskStatus.ToString(),
                FormatTimestamp(device.LastSeenUtc),
                BuildDeviceDetail(device)));
        }
    }

    private void ReplaceApplications(IReadOnlyList<AppIdentity> applications)
    {
        Applications.Clear();
        foreach (var application in applications.Take(100))
        {
            Applications.Add(new DashboardApplicationItemViewModel(
                FirstUseful(application.DisplayName, application.ProcessName, "Unknown application"),
                FirstUseful(application.ProcessName, "Process unavailable"),
                FirstUseful(application.Publisher, "Publisher unavailable"),
                SignatureLabel(application.SignatureStatus),
                application.TrustStatus.ToString(),
                FormatTimestamp(application.LastSeenUtc),
                BuildApplicationIdentity(application, application.ProcessName)));
        }
    }

    private void ReplaceRecentActivity(
        IReadOnlyList<NetworkEvent> events,
        IReadOnlyList<AppIdentity> applications,
        IReadOnlyList<ListeningPort> ports,
        IReadOnlyList<NetworkDevice> devices)
    {
        RecentActivity.Clear();
        foreach (var networkEvent in events.Take(8))
        {
            RecentActivity.Add(CreateEventActivity(networkEvent, applications));
        }

        if (RecentActivity.Count == 0)
        {
            foreach (var port in ports.Take(5))
            {
                var applicationName = port.Application?.DisplayName ?? "Unknown application";
                RecentActivity.Add(new DashboardActivityItemViewModel(
                    port.RiskStatus.ToString(),
                    applicationName,
                    $"Port {port.PortNumber} is listening on {port.LocalAddress}.",
                    $"{port.Protocol} {port.LocalAddress}:{port.PortNumber} is {port.Reachability}.",
                    BuildApplicationIdentity(port.Application, port.Application?.ProcessName),
                    port.Reachability == PortReachability.NetworkReachable
                        ? "Other devices on your network may be able to connect to this service."
                        : "The listener appears local to this computer or its reachability is unknown.",
                    "Review this only if you do not recognize the application or port."));
            }
        }

        if (RecentActivity.Count == 0)
        {
            foreach (var device in devices.Take(5))
            {
                RecentActivity.Add(new DashboardActivityItemViewModel(
                    device.TrustStatus.ToString(),
                    device.Hostname ?? device.IpAddress,
                    $"Device observed at {device.IpAddress}.",
                    device.MacAddress ?? "MAC address unavailable",
                    device.Vendor ?? "Device vendor unavailable",
                    "AccessWatch saw this device on the local network.",
                    "Trust or block the device when device controls are enabled."));
            }
        }
    }

    private static string BuildDeviceDetail(NetworkDevice device)
    {
        var details = new List<string>();
        if (!string.IsNullOrWhiteSpace(device.DeviceTypeGuess))
        {
            details.Add(device.DeviceTypeGuess);
        }

        if (!string.IsNullOrWhiteSpace(device.Notes))
        {
            details.Add(device.Notes);
        }

        if (details.Count == 0)
        {
            details.Add("No extra device details recorded yet.");
        }

        return string.Join("; ", details);
    }

    private static string FormatTimestamp(DateTimeOffset timestamp)
    {
        return timestamp == default
            ? "Not recorded"
            : timestamp.ToLocalTime().ToString("g", CultureInfo.CurrentCulture);
    }

    private static DashboardActivityItemViewModel CreateEventActivity(
        NetworkEvent networkEvent,
        IReadOnlyList<AppIdentity> applications)
    {
        var details = ParseEventDetails(networkEvent.DetailsJson);
        var application = applications.FirstOrDefault(candidate => candidate.ApplicationId == networkEvent.ApplicationId);
        var applicationName = FirstUseful(application?.DisplayName, details.App, "Unknown application");
        var endpoint = $"{networkEvent.Protocol} {networkEvent.DestinationIp ?? "local"}:{networkEvent.DestinationPort?.ToString() ?? "n/a"}";
        var reachability = string.IsNullOrWhiteSpace(details.Reachability) ? string.Empty : $"; {details.Reachability}";
        var whatHappened = FirstUseful(details.WhatHappened, FriendlyEventType(networkEvent.EventType));

        return new DashboardActivityItemViewModel(
            networkEvent.RiskLevel.ToString(),
            applicationName,
            networkEvent.Summary,
            $"{whatHappened} {endpoint}{reachability}.",
            BuildApplicationIdentity(application, details.ProcessName),
            FirstUseful(details.WhyItMatters, DefaultWhyItMatters(networkEvent.RiskLevel)),
            FirstUseful(details.SuggestedAction, DefaultSuggestedAction(networkEvent.RiskLevel)));
    }

    private static EventDetails ParseEventDetails(string detailsJson)
    {
        if (string.IsNullOrWhiteSpace(detailsJson))
        {
            return new EventDetails();
        }

        try
        {
            using var document = JsonDocument.Parse(detailsJson);
            var root = document.RootElement;
            return new EventDetails(
                GetString(root, "whatHappened"),
                GetString(root, "app"),
                GetString(root, "processName"),
                GetString(root, "reachability"),
                GetString(root, "whyItMatters"),
                GetString(root, "suggestedAction"));
        }
        catch (JsonException)
        {
            return new EventDetails();
        }
    }

    private static string BuildApplicationIdentity(AppIdentity? application, string? processName)
    {
        if (application is null)
        {
            return string.IsNullOrWhiteSpace(processName)
                ? "Application identity unavailable"
                : $"Process {processName}; stored app identity unavailable";
        }

        var parts = new List<string>();
        var resolvedProcessName = FirstUseful(application.ProcessName, processName, string.Empty);
        if (!string.IsNullOrWhiteSpace(resolvedProcessName))
        {
            parts.Add($"Process {resolvedProcessName}");
        }

        if (!string.IsNullOrWhiteSpace(application.Publisher))
        {
            var publisherPrefix = application.SignatureStatus is SignatureStatus.TrustedSigned or SignatureStatus.SignedUnknown
                ? "Signed by"
                : "Publisher";
            parts.Add($"{publisherPrefix} {application.Publisher}");
        }
        else
        {
            parts.Add(SignatureLabel(application.SignatureStatus));
        }

        if (!string.IsNullOrWhiteSpace(application.FilePath))
        {
            parts.Add(application.FilePath);
        }
        else
        {
            parts.Add("Executable path unavailable");
        }

        return string.Join("; ", parts);
    }

    private static string SignatureLabel(SignatureStatus signatureStatus)
    {
        return signatureStatus switch
        {
            SignatureStatus.TrustedSigned => "Trusted signature",
            SignatureStatus.SignedUnknown => "Signed; publisher trust unknown",
            SignatureStatus.Unsigned => "Unsigned executable",
            SignatureStatus.InvalidSignature => "Invalid signature",
            _ => "Signature status unknown"
        };
    }

    private static string FriendlyEventType(string eventType)
    {
        return eventType switch
        {
            "NewListeningPort" => "A new listening TCP port appeared.",
            "ListeningPortApplicationChanged" => "A known listening TCP port changed owning application.",
            _ => "AccessWatch recorded network activity."
        };
    }

    private static string DefaultWhyItMatters(RiskLevel riskLevel)
    {
        return riskLevel switch
        {
            RiskLevel.High or RiskLevel.Critical => "This activity may expose a service to other devices and deserves review.",
            RiskLevel.Medium => "This activity is visible enough to keep on your radar.",
            _ => "AccessWatch logged this for your activity history."
        };
    }

    private static string DefaultSuggestedAction(RiskLevel riskLevel)
    {
        return riskLevel switch
        {
            RiskLevel.High or RiskLevel.Critical => "Confirm the application and port are expected before trusting it.",
            RiskLevel.Medium => "No action needed if you recognize the application.",
            _ => "No action needed."
        };
    }

    private static string FirstUseful(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static string? GetString(JsonElement root, string propertyName)
    {
        return root.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;
    }

    private void OnPropertyChanged(string propertyName)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    private sealed record EventDetails(
        string? WhatHappened = null,
        string? App = null,
        string? ProcessName = null,
        string? Reachability = null,
        string? WhyItMatters = null,
        string? SuggestedAction = null);
}
