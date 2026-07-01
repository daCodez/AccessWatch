using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Net;
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
    long DeviceId,
    string Name,
    string UserAlias,
    string ResolvedName,
    string NameSource,
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
    long ApplicationId,
    string Name,
    string ProcessName,
    string Publisher,
    string SignatureStatus,
    string TrustStatus,
    string LastSeen,
    string Detail);

/// <summary>
/// Represents a listening port row shown in the dashboard.
/// </summary>
public sealed record DashboardPortItemViewModel(
    string Endpoint,
    string ApplicationName,
    string Reachability,
    string RiskStatus,
    string TrustStatus,
    string FirstSeen,
    string LastSeen,
    string Detail);

/// <summary>
/// Represents an incident row shown in the dashboard.
/// </summary>
public sealed record DashboardIncidentItemViewModel(
    long IncidentId,
    long? MainDeviceId,
    long? MainApplicationId,
    RiskLevel RawRiskLevel,
    IncidentStatus RawStatus,
    DateTimeOffset RawStartedUtc,
    DateTimeOffset RawLastUpdatedUtc,
    string Title,
    string RiskLevel,
    string Status,
    int EventCount,
    string MainTarget,
    string Started,
    string LastUpdated,
    string Summary);

/// <summary>
/// Represents a dashboard settings choice.
/// </summary>
public sealed record DashboardSettingsOptionViewModel(string Value, string Name, string Summary);

/// <summary>
/// Provides dashboard data loaded from the AccessWatch repository.
/// </summary>
public sealed class DashboardShellViewModel : INotifyPropertyChanged
{
    private readonly IAccessWatchRepository? repository;
    private readonly Func<CancellationToken, Task<int>>? scanAsync;
    private readonly Func<CancellationToken, Task<int>>? simulateAsync;
    private readonly IAiHandoffService? aiHandoffService;
    private readonly AccessWatchSettings settings;
    private DashboardPageViewModel selectedPage;
    private string selectedProtectionMode;
    private string selectedAiMode;
    private string settingsStatus = "Settings match the running configuration.";
    private string statusMessage = "Connect the service or run a scan to load AccessWatch activity.";
    private string activeOperation = string.Empty;
    private DashboardDeviceItemViewModel? selectedDevice;
    private DashboardApplicationItemViewModel? selectedApplication;
    private DashboardPortItemViewModel? selectedPort;
    private DashboardIncidentItemViewModel? selectedIncident;
    private string selectedIncidentAiHandoff = string.Empty;
    private string selectedIncidentRuleSuggestion = string.Empty;
    private string selectedDeviceAlias = string.Empty;
    private bool isLoading;

    /// <summary>
    /// Initializes a dashboard shell without live data access.
    /// </summary>
    public DashboardShellViewModel()
    {
        settings = new AccessWatchSettings();
        selectedProtectionMode = settings.ProtectionMode.ToString();
        selectedAiMode = settings.AiMode.ToString();
        selectedPage = Pages[0];
    }

    /// <summary>
    /// Initializes a dashboard shell backed by the AccessWatch repository.
    /// </summary>
    /// <param name="repository">Repository used to load dashboard data.</param>
    /// <param name="scanAsync">Optional scan action that persists fresh observations.</param>
    /// <param name="simulateAsync">Optional simulator action that persists a demo event.</param>
    /// <param name="settings">Mutable settings used by dashboard actions in this app session.</param>
    /// <param name="aiHandoffService">Optional service used to create redacted incident AI review packets.</param>
    public DashboardShellViewModel(
        IAccessWatchRepository repository,
        Func<CancellationToken, Task<int>>? scanAsync = null,
        Func<CancellationToken, Task<int>>? simulateAsync = null,
        AccessWatchSettings? settings = null,
        IAiHandoffService? aiHandoffService = null)
    {
        this.repository = repository;
        this.scanAsync = scanAsync;
        this.simulateAsync = simulateAsync;
        this.aiHandoffService = aiHandoffService;
        this.settings = settings ?? new AccessWatchSettings();
        selectedProtectionMode = this.settings.ProtectionMode.ToString();
        selectedAiMode = this.settings.AiMode.ToString();
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
            OnPropertyChanged(nameof(IsPortsSelected));
            OnPropertyChanged(nameof(IsIncidentsSelected));
            OnPropertyChanged(nameof(IsSettingsSelected));
            OnPropertyChanged(nameof(IsPlaceholderSelected));
            OnPropertyChanged(nameof(OverviewVisibility));
            OnPropertyChanged(nameof(DevicesVisibility));
            OnPropertyChanged(nameof(ApplicationsVisibility));
            OnPropertyChanged(nameof(PortsVisibility));
            OnPropertyChanged(nameof(IncidentsVisibility));
            OnPropertyChanged(nameof(SettingsVisibility));
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
    /// Gets whether the ports page is selected.
    /// </summary>
    public bool IsPortsSelected => SelectedPageTitle == "Ports";

    /// <summary>
    /// Gets whether the incidents page is selected.
    /// </summary>
    public bool IsIncidentsSelected => SelectedPageTitle == "Incidents";

    /// <summary>
    /// Gets whether the settings page is selected.
    /// </summary>
    public bool IsSettingsSelected => SelectedPageTitle == "Settings";

    /// <summary>
    /// Gets whether the selected page is not yet implemented.
    /// </summary>
    public bool IsPlaceholderSelected => !IsOverviewSelected && !IsDevicesSelected && !IsApplicationsSelected && !IsPortsSelected && !IsIncidentsSelected && !IsSettingsSelected;

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
    /// Gets WPF visibility text for the ports panel.
    /// </summary>
    public string PortsVisibility => ToVisibility(IsPortsSelected);

    /// <summary>
    /// Gets WPF visibility text for the incidents panel.
    /// </summary>
    public string IncidentsVisibility => ToVisibility(IsIncidentsSelected);

    /// <summary>
    /// Gets WPF visibility text for the settings panel.
    /// </summary>
    public string SettingsVisibility => ToVisibility(IsSettingsSelected);

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
    /// Gets or sets the selected device shown in the detail panel.
    /// </summary>
    public DashboardDeviceItemViewModel? SelectedDevice
    {
        get => selectedDevice;
        set
        {
            if (Equals(selectedDevice, value))
            {
                return;
            }

            selectedDevice = value;
            selectedDeviceAlias = value?.UserAlias ?? string.Empty;
            OnPropertyChanged(nameof(SelectedDevice));
            OnPropertyChanged(nameof(SelectedDeviceAlias));
            OnPropertyChanged(nameof(SelectedDeviceDetail));
            OnPropertyChanged(nameof(CanApplyDeviceTrustDecision));
        }
    }

    /// <summary>
    /// Gets plain-English details for the selected device.
    /// </summary>
    public string SelectedDeviceDetail => selectedDevice is null
        ? "Select a device to see its name, address, trust, and risk context."
        : $"Device: {selectedDevice.Name} | IP: {selectedDevice.IpAddress} | MAC: {selectedDevice.MacAddress} | Vendor: {selectedDevice.Vendor} | Trust: {selectedDevice.TrustStatus} | Risk: {selectedDevice.RiskStatus} | Details: {selectedDevice.Detail}";

    /// <summary>
    /// Gets whether device trust action buttons can run.
    /// </summary>
    public bool CanApplyDeviceTrustDecision => selectedDevice is not null;

    /// <summary>
    /// Gets or sets the editable alias for the selected device.
    /// </summary>
    public string SelectedDeviceAlias
    {
        get => selectedDeviceAlias;
        set
        {
            selectedDeviceAlias = value ?? string.Empty;
            OnPropertyChanged(nameof(SelectedDeviceAlias));
        }
    }

    /// <summary>
    /// Gets or sets the selected application shown in the detail panel.
    /// </summary>
    public DashboardApplicationItemViewModel? SelectedApplication
    {
        get => selectedApplication;
        set
        {
            if (Equals(selectedApplication, value))
            {
                return;
            }

            selectedApplication = value;
            OnPropertyChanged(nameof(SelectedApplication));
            OnPropertyChanged(nameof(SelectedApplicationDetail));
            OnPropertyChanged(nameof(CanApplyApplicationTrustDecision));
        }
    }

    /// <summary>
    /// Gets plain-English details for the selected application.
    /// </summary>
    public string SelectedApplicationDetail => selectedApplication is null
        ? "Select an application to see publisher, signature, trust, and executable context."
        : $"Application: {selectedApplication.Name} | Process: {selectedApplication.ProcessName} | Publisher: {selectedApplication.Publisher} | Signature: {selectedApplication.SignatureStatus} | Trust: {selectedApplication.TrustStatus} | Identity: {selectedApplication.Detail}";

    /// <summary>
    /// Gets whether application trust action buttons can run.
    /// </summary>
    public bool CanApplyApplicationTrustDecision => selectedApplication is not null;

    /// <summary>
    /// Gets or sets the selected port shown in the detail panel.
    /// </summary>
    public DashboardPortItemViewModel? SelectedPort
    {
        get => selectedPort;
        set
        {
            if (Equals(selectedPort, value))
            {
                return;
            }

            selectedPort = value;
            OnPropertyChanged(nameof(SelectedPort));
            OnPropertyChanged(nameof(SelectedPortDetail));
        }
    }

    /// <summary>
    /// Gets plain-English details for the selected listening port.
    /// </summary>
    public string SelectedPortDetail => selectedPort is null
        ? "Select a port to see the owning application, reachability, risk, and timing context."
        : $"Port: {selectedPort.Endpoint} | Application: {selectedPort.ApplicationName} | Reachability: {selectedPort.Reachability} | Risk: {selectedPort.RiskStatus} | Trust: {selectedPort.TrustStatus} | First seen: {selectedPort.FirstSeen} | Last seen: {selectedPort.LastSeen} | Identity: {selectedPort.Detail}";

    /// <summary>
    /// Gets or sets the selected incident shown in the detail panel.
    /// </summary>
    public DashboardIncidentItemViewModel? SelectedIncident
    {
        get => selectedIncident;
        set
        {
            if (Equals(selectedIncident, value))
            {
                return;
            }

            selectedIncident = value;
            selectedIncidentAiHandoff = string.Empty;
            selectedIncidentRuleSuggestion = string.Empty;
            OnPropertyChanged(nameof(SelectedIncident));
            OnPropertyChanged(nameof(SelectedIncidentDetail));
            OnPropertyChanged(nameof(SelectedIncidentExplanation));
            OnPropertyChanged(nameof(CanApplyIncidentAction));
            OnPropertyChanged(nameof(CanCreateIncidentAiHandoff));
            OnPropertyChanged(nameof(SelectedIncidentAiHandoff));
            OnPropertyChanged(nameof(HasIncidentAiHandoff));
            OnPropertyChanged(nameof(SelectedIncidentRuleSuggestion));
            OnPropertyChanged(nameof(HasIncidentRuleSuggestion));
        }
    }

    /// <summary>
    /// Gets plain-English details for the selected incident.
    /// </summary>
    public string SelectedIncidentDetail => selectedIncident is null
        ? "Select an incident to see its target, timeline, and AI review context."
        : $"Incident: {selectedIncident.Title} | Target: {selectedIncident.MainTarget} | Risk: {selectedIncident.RiskLevel} | Status: {selectedIncident.Status} | Events: {selectedIncident.EventCount} | Summary: {selectedIncident.Summary}";

    /// <summary>
    /// Gets a local explanation of the selected incident and what to verify next.
    /// </summary>
    public string SelectedIncidentExplanation => selectedIncident is null
        ? "Select an incident to see why AccessWatch grouped it and what to verify next."
        : BuildIncidentExplanation(selectedIncident);

    /// <summary>
    /// Gets whether incident action buttons can run.
    /// </summary>
    public bool CanApplyIncidentAction => selectedIncident is not null && repository is not null;

    /// <summary>
    /// Gets whether an incident is selected for AI handoff.
    /// </summary>
    public bool CanCreateIncidentAiHandoff =>
        selectedIncident is not null &&
        aiHandoffService is not null &&
        settings.AiMode != AiMode.Off;

    /// <summary>
    /// Gets the redacted AI handoff packet for the selected incident.
    /// </summary>
    public string SelectedIncidentAiHandoff => selectedIncidentAiHandoff;

    /// <summary>
    /// Gets whether the current incident has a generated handoff packet.
    /// </summary>
    public bool HasIncidentAiHandoff => !string.IsNullOrWhiteSpace(selectedIncidentAiHandoff);

    /// <summary>
    /// Gets the structured rule suggestion created from the selected incident.
    /// </summary>
    public string SelectedIncidentRuleSuggestion => selectedIncidentRuleSuggestion;

    /// <summary>
    /// Gets whether the current incident has a generated rule suggestion.
    /// </summary>
    public bool HasIncidentRuleSuggestion => !string.IsNullOrWhiteSpace(selectedIncidentRuleSuggestion);

    /// <summary>
    /// Gets recent listening ports loaded from storage.
    /// </summary>
    public ObservableCollection<DashboardPortItemViewModel> Ports { get; } = [];

    /// <summary>
    /// Gets recent incidents loaded from storage.
    /// </summary>
    public ObservableCollection<DashboardIncidentItemViewModel> Incidents { get; } = [];

    /// <summary>
    /// Gets protection mode choices shown on the Settings page.
    /// </summary>
    public IReadOnlyList<DashboardSettingsOptionViewModel> ProtectionModeOptions { get; } =
    [
        new("Quiet", "Quiet", "Minimize interruptions and keep medium-risk activity in history."),
        new("Balanced", "Balanced", "Default low-noise notifications for activity that deserves attention."),
        new("Strict", "Strict", "Notify more often when application or network activity is uncertain."),
        new("Lockdown", "Lockdown", "Prepare for strongest enforcement as blocking controls come online.")
    ];

    /// <summary>
    /// Gets AI handoff choices shown on the Settings page.
    /// </summary>
    public IReadOnlyList<DashboardSettingsOptionViewModel> AiModeOptions { get; } =
    [
        new("Off", "Off", "Keep incident review fully local with no AI handoff."),
        new("ManualChatGptCopy", "Manual ChatGPT copy", "Create redacted incident summaries for manual review."),
        new("LocalAi", "Local AI", "Reserve local model assistance for a future release."),
        new("OpenAiApi", "OpenAI API", "Reserve connected AI assistance for a future release.")
    ];

    /// <summary>
    /// Gets or sets the selected protection mode value.
    /// </summary>
    public string SelectedProtectionMode
    {
        get => selectedProtectionMode;
        set
        {
            selectedProtectionMode = value ?? settings.ProtectionMode.ToString();
            SettingsStatus = "Settings changed. Apply to update the running configuration.";
            OnPropertyChanged(nameof(SelectedProtectionMode));
        }
    }

    /// <summary>
    /// Gets or sets the selected AI handoff mode value.
    /// </summary>
    public string SelectedAiMode
    {
        get => selectedAiMode;
        set
        {
            selectedAiMode = value ?? settings.AiMode.ToString();
            SettingsStatus = "Settings changed. Apply to update the running configuration.";
            OnPropertyChanged(nameof(SelectedAiMode));
        }
    }

    /// <summary>
    /// Gets the protection mode currently used by new scans.
    /// </summary>
    public string CurrentProtectionMode => settings.ProtectionMode.ToString();

    /// <summary>
    /// Gets the AI handoff mode currently used by the dashboard.
    /// </summary>
    public string CurrentAiMode => settings.AiMode.ToString();

    /// <summary>
    /// Gets the current Settings page status.
    /// </summary>
    public string SettingsStatus
    {
        get => settingsStatus;
        private set
        {
            settingsStatus = value;
            OnPropertyChanged(nameof(SettingsStatus));
        }
    }

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
            OnPropertyChanged(nameof(SimulateButtonText));
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
    /// Gets the current simulator button label.
    /// </summary>
    public string SimulateButtonText => IsLoading && activeOperation == "Simulation" ? "Simulating..." : "Simulate event";

    /// <summary>
    /// Gets the current refresh button label.
    /// </summary>
    public string RefreshButtonText => IsLoading && activeOperation == "Refresh" ? "Refreshing..." : "Refresh";

    /// <summary>
    /// Gets the current progress indicator label.
    /// </summary>
    public string ProgressMessage => activeOperation switch
    {
        "Scan" => "Searching network devices and listening ports...",
        "Simulation" => "Creating a simulated network event...",
        _ => "Refreshing dashboard data..."
    };

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
            var storedDevices = await repository.ListRecentDevicesAsync(500, cancellationToken);
            var devices = storedDevices.Where(device => DeviceAddressClassifier.IsUsableDeviceAddress(device.IpAddress, device.MacAddress)).ToList();
            var applications = await repository.ListRecentApplicationsAsync(500, cancellationToken);
            var ports = await repository.ListRecentPortsAsync(500, cancellationToken);
            var events = await repository.ListRecentNetworkEventsAsync(50, cancellationToken);
            var incidents = await repository.ListRecentIncidentsAsync(200, cancellationToken);

            ReplaceMetrics(devices.Count, applications.Count, ports.Count, events.Count);
            ReplaceDevices(devices);
            ReplaceApplications(applications);
            ReplacePorts(ports);
            ReplaceIncidents(incidents, devices, applications);
            ReplaceRecentActivity(events, applications, ports, devices);
            StatusMessage = events.Count == 0 && ports.Count == 0 && devices.Count == 0 && incidents.Count == 0
                ? "No stored activity yet. Start the AccessWatch service to record listening ports and devices."
                : $"Loaded {events.Count} events, {ports.Count} ports, {incidents.Count} incidents, and {devices.Count} devices.";
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
    /// Applies selected Settings page values to the running configuration.
    /// </summary>
    public void ApplySettings()
    {
        settings.ProtectionMode = Enum.Parse<ProtectionMode>(SelectedProtectionMode);
        settings.AiMode = Enum.Parse<AiMode>(SelectedAiMode);
        SettingsStatus = $"Settings applied. Running {CurrentProtectionMode} protection with {CurrentAiMode} AI handoff.";
        OnPropertyChanged(nameof(CurrentProtectionMode));
        OnPropertyChanged(nameof(CurrentAiMode));
        OnPropertyChanged(nameof(CanCreateIncidentAiHandoff));
    }

    /// <summary>
    /// Restores Settings page selections to the running configuration.
    /// </summary>
    public void ResetSettingsSelections()
    {
        selectedProtectionMode = settings.ProtectionMode.ToString();
        selectedAiMode = settings.AiMode.ToString();
        SettingsStatus = "Settings match the running configuration.";
        OnPropertyChanged(nameof(SelectedProtectionMode));
        OnPropertyChanged(nameof(SelectedAiMode));
    }

    /// <summary>
    /// Saves the alias entered for the selected device.
    /// </summary>
    public async Task SaveSelectedDeviceAliasAsync(CancellationToken cancellationToken)
    {
        if (selectedDevice is null)
        {
            StatusMessage = "Select a device before saving an alias.";
            return;
        }

        var alias = NormalizeAlias(SelectedDeviceAlias);
        await repository!.UpdateDeviceAliasAsync(selectedDevice.DeviceId, alias, cancellationToken);
        UpdateSelectedDeviceAlias(alias);
        StatusMessage = alias is null
            ? $"Cleared alias for {selectedDevice.IpAddress}."
            : $"Saved alias {alias} for {selectedDevice.IpAddress}.";
    }

    /// <summary>
    /// Clears the alias for the selected device.
    /// </summary>
    public async Task ClearSelectedDeviceAliasAsync(CancellationToken cancellationToken)
    {
        SelectedDeviceAlias = string.Empty;
        await SaveSelectedDeviceAliasAsync(cancellationToken);
    }
    /// <summary>
    /// Applies a trust decision to the selected device and updates the dashboard row.
    /// </summary>
    public async Task ApplySelectedDeviceTrustDecisionAsync(TrustStatus decision, CancellationToken cancellationToken)
    {
        if (selectedDevice is null)
        {
            StatusMessage = "Select a device before applying a trust decision.";
            return;
        }

        var updatedDevice = selectedDevice with { TrustStatus = decision.ToString() };
        await repository!.AddTrustDecisionAsync(CreateTrustDecision("Device", selectedDevice.DeviceId, decision), cancellationToken);
        Devices[Devices.IndexOf(selectedDevice)] = updatedDevice;
        SelectedDevice = updatedDevice;
        StatusMessage = $"{TrustDecisionVerb(decision)} {updatedDevice.Name}.";
    }

    /// <summary>
    /// Applies a trust decision to the selected application and updates the dashboard row.
    /// </summary>
    public async Task ApplySelectedApplicationTrustDecisionAsync(TrustStatus decision, CancellationToken cancellationToken)
    {
        if (selectedApplication is null)
        {
            StatusMessage = "Select an application before applying a trust decision.";
            return;
        }

        var updatedApplication = selectedApplication with { TrustStatus = decision.ToString() };
        await repository!.AddTrustDecisionAsync(CreateTrustDecision("Application", selectedApplication.ApplicationId, decision), cancellationToken);
        Applications[Applications.IndexOf(selectedApplication)] = updatedApplication;
        SelectedApplication = updatedApplication;
        StatusMessage = $"{TrustDecisionVerb(decision)} {updatedApplication.Name}.";
    }

    /// <summary>
    /// Marks the selected incident as resolved.
    /// </summary>
    public Task ResolveSelectedIncidentAsync(CancellationToken cancellationToken)
    {
        return ApplySelectedIncidentUpdateAsync(IncidentStatus.Resolved, null, "Resolved", cancellationToken);
    }

    /// <summary>
    /// Marks the selected incident as watched.
    /// </summary>
    public Task WatchSelectedIncidentAsync(CancellationToken cancellationToken)
    {
        return ApplySelectedIncidentUpdateAsync(IncidentStatus.Watching, null, "Watching", cancellationToken);
    }

    /// <summary>
    /// Escalates the selected incident to critical review.
    /// </summary>
    public Task EscalateSelectedIncidentAsync(CancellationToken cancellationToken)
    {
        return ApplySelectedIncidentUpdateAsync(IncidentStatus.Open, RiskLevel.Critical, "Escalated", cancellationToken);
    }

    /// <summary>
    /// Creates a disabled rule suggestion from the selected incident.
    /// </summary>
    public async Task CreateRuleFromSelectedIncidentAsync(CancellationToken cancellationToken)
    {
        if (selectedIncident is null)
        {
            StatusMessage = "Select an incident before creating a rule suggestion.";
            return;
        }

        if (repository is null)
        {
            StatusMessage = "Rule suggestions are not connected for this dashboard session.";
            return;
        }

        var rule = CreateRuleSuggestion(selectedIncident);
        var ruleId = await repository.UpsertRuleAsync(rule, cancellationToken);
        selectedIncidentRuleSuggestion = rule.ConditionJson;
        OnPropertyChanged(nameof(SelectedIncidentRuleSuggestion));
        OnPropertyChanged(nameof(HasIncidentRuleSuggestion));
        StatusMessage = $"Created disabled rule suggestion #{ruleId} from {selectedIncident.Title}.";
    }

    /// <summary>
    /// Creates a redacted AI review packet for the selected incident.
    /// </summary>
    public void CreateSelectedIncidentAiHandoff()
    {
        if (selectedIncident is null)
        {
            StatusMessage = "Select an incident before creating an AI review packet.";
            return;
        }

        if (aiHandoffService is null)
        {
            StatusMessage = "AI handoff is not connected for this dashboard session.";
            return;
        }

        if (settings.AiMode == AiMode.Off)
        {
            StatusMessage = "Turn on AI handoff in Settings before creating a review packet.";
            return;
        }

        selectedIncidentAiHandoff = aiHandoffService.CreateRedactedIncidentSummary(ToIncident(selectedIncident));
        OnPropertyChanged(nameof(SelectedIncidentAiHandoff));
        OnPropertyChanged(nameof(HasIncidentAiHandoff));
        StatusMessage = $"Created redacted AI review packet for {selectedIncident.Title}.";
    }

    /// <summary>
    /// Updates the status after copying the incident AI handoff packet.
    /// </summary>
    public void MarkIncidentAiHandoffCopied()
    {
        StatusMessage = HasIncidentAiHandoff
            ? "Copied redacted AI review packet."
            : "Create an AI review packet before copying it.";
    }

    private async Task ApplySelectedIncidentUpdateAsync(
        IncidentStatus status,
        RiskLevel? riskLevel,
        string statusVerb,
        CancellationToken cancellationToken)
    {
        if (selectedIncident is null)
        {
            StatusMessage = "Select an incident before applying an incident action.";
            return;
        }

        if (repository is null)
        {
            StatusMessage = "Incident actions are not connected for this dashboard session.";
            return;
        }

        var now = DateTimeOffset.UtcNow;
        var updatedRisk = riskLevel ?? selectedIncident.RawRiskLevel;
        var updatedIncident = selectedIncident with
        {
            RawRiskLevel = updatedRisk,
            RawStatus = status,
            RiskLevel = updatedRisk.ToString(),
            Status = status.ToString(),
            LastUpdated = FormatTimestamp(now),
            RawLastUpdatedUtc = now
        };

        var incident = ToIncident(updatedIncident, status == IncidentStatus.Resolved ? now : null);
        await repository.UpsertIncidentAsync(incident, cancellationToken);
        var selectedIndex = Incidents.IndexOf(selectedIncident);
        if (selectedIndex >= 0)
        {
            Incidents[selectedIndex] = updatedIncident;
        }

        SelectedIncident = updatedIncident;
        StatusMessage = $"{statusVerb} incident {updatedIncident.Title}.";
    }

    private static Incident ToIncident(DashboardIncidentItemViewModel incident, DateTimeOffset? resolvedUtc = null)
    {
        return new Incident
        {
            IncidentId = incident.IncidentId,
            Title = incident.Title,
            Summary = incident.Summary,
            MainDeviceId = incident.MainDeviceId,
            MainApplicationId = incident.MainApplicationId,
            RiskLevel = incident.RawRiskLevel,
            Status = incident.RawStatus,
            EventCount = incident.EventCount,
            StartedUtc = incident.RawStartedUtc,
            LastUpdatedUtc = incident.RawLastUpdatedUtc,
            ResolvedUtc = resolvedUtc
        };
    }

    private static AccessWatchRule CreateRuleSuggestion(DashboardIncidentItemViewModel incident)
    {
        var condition = new
        {
            source = "IncidentSuggestion",
            incidentId = incident.IncidentId,
            title = incident.Title,
            target = incident.MainTarget,
            mainDeviceId = incident.MainDeviceId,
            mainApplicationId = incident.MainApplicationId,
            riskLevel = incident.RiskLevel,
            eventCount = incident.EventCount
        };

        return new AccessWatchRule
        {
            Name = $"Review {FirstUseful(incident.Title, "incident")}",
            Description = $"Suggested from incident {incident.IncidentId}: {incident.Summary}",
            ConditionJson = JsonSerializer.Serialize(condition, new JsonSerializerOptions { WriteIndented = true }),
            RiskLevel = incident.RawRiskLevel,
            Action = incident.RawRiskLevel >= RiskLevel.High ? NotificationAction.AskBeforeAllow : NotificationAction.SoftNotify,
            Enabled = false
        };
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

    /// <summary>
    /// Creates a simulated event, saves it, notifies the user, and reloads dashboard data.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task RunSimulationAsync(CancellationToken cancellationToken)
    {
        if (simulateAsync is null)
        {
            StatusMessage = "Event simulator is not connected yet.";
            return;
        }

        BeginLoading("Simulation", "Creating a simulated network event...");
        try
        {
            var createdEvents = await simulateAsync(cancellationToken);
            await LoadAsync(cancellationToken);
            StatusMessage = $"Simulation completed. Created {createdEvents} event.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Could not run AccessWatch simulator: {ex.Message}";
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
        OnPropertyChanged(nameof(SimulateButtonText));
        OnPropertyChanged(nameof(RefreshButtonText));
        OnPropertyChanged(nameof(ProgressMessage));
    }

    private void EndLoading()
    {
        IsLoading = false;
        activeOperation = string.Empty;
        OnPropertyChanged(nameof(ScanButtonText));
        OnPropertyChanged(nameof(SimulateButtonText));
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
                device.DeviceId,
                DisplayDeviceName(device),
                FirstUseful(device.UserAlias),
                ResolvedDeviceName(device),
                DeviceNameSource(device),
                device.IpAddress,
                FirstUseful(device.MacAddress, "MAC address unavailable"),
                FirstUseful(device.Vendor, "Vendor unavailable"),
                device.TrustStatus.ToString(),
                device.RiskStatus.ToString(),
                FormatTimestamp(device.LastSeenUtc),
                BuildDeviceDetail(device)));
        }

        SelectedDevice = Devices.FirstOrDefault();
    }

    private void ReplaceApplications(IReadOnlyList<AppIdentity> applications)
    {
        Applications.Clear();
        foreach (var application in applications.Take(100))
        {
            Applications.Add(new DashboardApplicationItemViewModel(
                application.ApplicationId,
                FirstUseful(application.DisplayName, application.ProcessName, "Unknown application"),
                FirstUseful(application.ProcessName, "Process unavailable"),
                FirstUseful(application.Publisher, "Publisher unavailable"),
                SignatureLabel(application.SignatureStatus),
                application.TrustStatus.ToString(),
                FormatTimestamp(application.LastSeenUtc),
                BuildApplicationIdentity(application, application.ProcessName)));
        }

        SelectedApplication = Applications.FirstOrDefault();
    }

    private void ReplacePorts(IReadOnlyList<ListeningPort> ports)
    {
        Ports.Clear();
        foreach (var port in ports.Take(200))
        {
            Ports.Add(new DashboardPortItemViewModel(
                $"{port.Protocol} {port.LocalAddress}:{port.PortNumber}",
                FirstUseful(port.Application?.DisplayName, port.Application?.ProcessName, "Unknown application"),
                port.Reachability.ToString(),
                port.RiskStatus.ToString(),
                port.TrustStatus.ToString(),
                FormatTimestamp(port.FirstSeenUtc),
                FormatTimestamp(port.LastSeenUtc),
                BuildApplicationIdentity(port.Application, port.Application?.ProcessName)));
        }

        SelectedPort = Ports.FirstOrDefault();
    }

    private void ReplaceIncidents(
        IReadOnlyList<Incident> incidents,
        IReadOnlyList<NetworkDevice> devices,
        IReadOnlyList<AppIdentity> applications)
    {
        Incidents.Clear();
        foreach (var incident in incidents.Take(200))
        {
            var device = devices.FirstOrDefault(candidate => incident.MainDeviceId is not null && candidate.DeviceId == incident.MainDeviceId.Value);
            var application = applications.FirstOrDefault(candidate => incident.MainApplicationId is not null && candidate.ApplicationId == incident.MainApplicationId.Value);
            Incidents.Add(new DashboardIncidentItemViewModel(
                incident.IncidentId,
                incident.MainDeviceId,
                incident.MainApplicationId,
                incident.RiskLevel,
                incident.Status,
                incident.StartedUtc,
                incident.LastUpdatedUtc,
                FirstUseful(incident.Title, "Untitled incident"),
                incident.RiskLevel.ToString(),
                incident.Status.ToString(),
                incident.EventCount,
                BuildIncidentTarget(device, application),
                FormatTimestamp(incident.StartedUtc),
                FormatTimestamp(incident.LastUpdatedUtc),
                FirstUseful(incident.Summary, "No incident summary recorded yet.")));
        }

        SelectedIncident = Incidents.FirstOrDefault();
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
            RecentActivity.Add(CreateEventActivity(networkEvent, applications, devices));
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
                    DisplayDeviceName(device),
                    $"Device observed at {device.IpAddress}.",
                    device.MacAddress ?? "MAC address unavailable",
                    device.Vendor ?? "Device vendor unavailable",
                    "AccessWatch saw this device on the local network.",
                    "Trust or block the device when device controls are enabled."));
            }
        }
    }

    private static string BuildIncidentTarget(NetworkDevice? device, AppIdentity? application)
    {
        var parts = new List<string>();
        if (application is not null)
        {
            parts.Add(FirstUseful(application.DisplayName, application.ProcessName, "Unknown application"));
        }

        if (device is not null)
        {
            parts.Add(DisplayDeviceName(device));
        }

        return parts.Count == 0 ? "Target unavailable" : string.Join(" on ", parts);
    }

    private void UpdateSelectedDeviceAlias(string? alias)
    {
        var currentDevice = selectedDevice!;
        var updatedDevice = currentDevice with
        {
            Name = FirstUseful(alias, currentDevice.ResolvedName, $"Device at {currentDevice.IpAddress}"),
            UserAlias = alias ?? string.Empty,
            NameSource = string.IsNullOrWhiteSpace(alias)
                ? (string.IsNullOrWhiteSpace(currentDevice.ResolvedName) ? "IP address fallback" : "Hostname")
                : "User alias"
        };
        Devices[Devices.IndexOf(currentDevice)] = updatedDevice;
        SelectedDevice = updatedDevice;
    }

    private static TrustDecision CreateTrustDecision(string targetType, long targetId, TrustStatus decision)
    {
        return new TrustDecision
        {
            TargetType = targetType,
            TargetId = targetId,
            Decision = decision,
            Reason = "Selected from dashboard inventory.",
            CreatedUtc = DateTimeOffset.UtcNow
        };
    }

    private static string TrustDecisionVerb(TrustStatus decision)
    {
        return decision switch
        {
            TrustStatus.Trusted => "Trusted",
            TrustStatus.KnownWatched => "Watching",
            TrustStatus.Blocked => "Blocked",
            _ => "Updated"
        };
    }

    private static string DisplayDeviceName(NetworkDevice device)
    {
        var resolvedName = ResolvedDeviceName(device);
        return FirstUseful(
            device.UserAlias,
            resolvedName,
            DeviceTypeName(device),
            VendorDeviceName(device),
            $"Device at {device.IpAddress}");
    }

    private static string ResolvedDeviceName(NetworkDevice device)
    {
        return IsUsefulDeviceName(device.Hostname) ? device.Hostname!.Trim() : string.Empty;
    }

    private static string DeviceNameSource(NetworkDevice device)
    {
        if (!string.IsNullOrWhiteSpace(device.UserAlias))
        {
            return "User alias";
        }

        if (!string.IsNullOrWhiteSpace(ResolvedDeviceName(device)))
        {
            return "Hostname";
        }

        if (!string.IsNullOrWhiteSpace(device.DeviceTypeGuess))
        {
            return "Device type";
        }

        if (!string.IsNullOrWhiteSpace(device.Vendor))
        {
            return "Vendor";
        }

        return "IP address fallback";
    }

    private static string DeviceTypeName(NetworkDevice device)
    {
        return string.IsNullOrWhiteSpace(device.DeviceTypeGuess)
            ? string.Empty
            : $"{device.DeviceTypeGuess.Trim()} at {device.IpAddress}";
    }

    private static string VendorDeviceName(NetworkDevice device)
    {
        return string.IsNullOrWhiteSpace(device.Vendor)
            ? string.Empty
            : $"{device.Vendor.Trim()} device at {device.IpAddress}";
    }

    private static bool IsUsefulDeviceName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        return !IPAddress.TryParse(trimmed, out _) && !trimmed.Contains(":", StringComparison.Ordinal);
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

    private static string BuildIncidentExplanation(DashboardIncidentItemViewModel incident)
    {
        var urgency = incident.RawRiskLevel >= RiskLevel.High
            ? "This deserves prompt review because the incident risk is high enough to interrupt normal workflow."
            : "This is worth watching, but it does not currently look severe enough for immediate blocking.";
        var status = incident.RawStatus == IncidentStatus.Resolved
            ? "It is marked resolved, so keep it as history unless it repeats."
            : "It is still active for review or monitoring.";
        var verify = incident.MainTarget == "Target unavailable"
            ? "Verify which app or device was involved before trusting or blocking anything."
            : $"Verify that {incident.MainTarget} was expected at the recorded time.";
        return $"Why: {urgency} {status} Verify: {verify} Recommended action: use Watch for expected but noisy behavior, Resolve when confirmed, or Escalate if this was unexpected.";
    }

    private static DashboardActivityItemViewModel CreateEventActivity(
        NetworkEvent networkEvent,
        IReadOnlyList<AppIdentity> applications,
        IReadOnlyList<NetworkDevice> devices)
    {
        var details = ParseEventDetails(networkEvent.DetailsJson);
        var application = applications.FirstOrDefault(candidate => candidate.ApplicationId == networkEvent.ApplicationId);
        var device = devices.FirstOrDefault(candidate => networkEvent.SourceDeviceId is not null && candidate.DeviceId == networkEvent.SourceDeviceId.Value);
        var applicationName = FirstUseful(application?.DisplayName, details.App, "Unknown application");
        var endpoint = networkEvent.DestinationPort is null
            ? string.Empty
            : $" {networkEvent.Protocol} {networkEvent.DestinationIp ?? "local"}:{networkEvent.DestinationPort}.";
        var reachability = string.IsNullOrWhiteSpace(details.Reachability) ? string.Empty : $" {details.Reachability}.";
        var sourceDeviceName = device is null
            ? FirstUseful(details.DeviceName, networkEvent.SourceIp)
            : FirstUseful(DisplayDeviceName(device), networkEvent.SourceIp);
        var sourceDevice = string.IsNullOrWhiteSpace(sourceDeviceName) ? string.Empty : $"Device {sourceDeviceName}. ";
        var whatHappened = FirstUseful(details.WhatHappened, FriendlyEventType(networkEvent.EventType));

        return new DashboardActivityItemViewModel(
            networkEvent.RiskLevel.ToString(),
            applicationName,
            networkEvent.Summary,
            $"{sourceDevice}{whatHappened}{endpoint}{reachability}",
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
                GetString(root, "deviceName"),
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

    private static string? NormalizeAlias(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
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
        string? DeviceName = null,
        string? Reachability = null,
        string? WhyItMatters = null,
        string? SuggestedAction = null);
}

