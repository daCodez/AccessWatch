using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Text.Json;
using AccessWatch.Core;
using AccessWatch.Enforcement;
using AppIdentity = AccessWatch.Core.ApplicationIdentity;

namespace AccessWatch.App.ViewModels;

/// <summary>
/// Provides dashboard data loaded from the AccessWatch repository.
/// </summary>
public sealed class DashboardShellViewModel : INotifyPropertyChanged
{
    private readonly IAccessWatchRepository? repository;
    private readonly Func<CancellationToken, Task<int>>? scanAsync;
    private readonly Func<CancellationToken, Task<int>>? simulateAsync;
    private readonly IAiHandoffService? aiHandoffService;
    private readonly IAiInvestigationBridge? aiInvestigationBridge;
    private readonly IFirewallEnforcementPlanner? firewallEnforcementPlanner;
    private readonly IFirewallEnforcementExecutor? firewallEnforcementExecutor;
    private readonly AccessWatchSettings settings;
    private DashboardPageViewModel selectedPage;
    private string selectedProtectionMode;
    private string selectedAiMode;
    private string selectedSupportBridgeEndpoint;
    private string selectedQuietHours = "Off";
    private string selectedNetworkProfile = "Home";
    private string currentQuietHours = "Off";
    private string currentNetworkProfile = "Home";
    private string settingsStatus = "Settings match the running configuration.";
    private string statusMessage = "Connect the service or run a scan to load AccessWatch activity.";
    private string activeOperation = string.Empty;
    private DashboardDeviceItemViewModel? selectedDevice;
    private DashboardApplicationItemViewModel? selectedApplication;
    private DashboardPortItemViewModel? selectedPort;
    private string selectedPortInvestigation = string.Empty;
    private string selectedDeviceTrace = DeviceTracePrompt(null);
    private DashboardIncidentItemViewModel? selectedIncident;
    private DashboardRuleItemViewModel? selectedRule;
    private string selectedRulePreview = "Select a rule to preview what it would affect.";
    private string selectedIncidentAiReview = string.Empty;
    private string selectedIncidentRuleSuggestion = string.Empty;
    private string selectedIncidentNotes = string.Empty;
    private string incidentSearchText = string.Empty;
    private string selectedIncidentStatusFilter = "All";
    private readonly List<DashboardIncidentItemViewModel> allIncidents = [];
    private readonly FirewallEnforcementPlanReviewViewModel enforcementPlanReview = new();
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
        selectedSupportBridgeEndpoint = settings.SupportBridgeEndpoint;
        selectedPage = Pages[0];
    }

    /// <summary>
    /// Initializes a dashboard shell backed by the AccessWatch repository.
    /// </summary>
    /// <param name="repository">Repository used to load dashboard data.</param>
    /// <param name="scanAsync">Optional scan action that persists fresh observations.</param>
    /// <param name="simulateAsync">Optional simulator action that persists a demo event.</param>
    /// <param name="settings">Mutable settings used by dashboard actions in this app session.</param>
    /// <param name="aiHandoffService">Optional service used to create redacted incident AI review briefs.</param>
    /// <param name="aiInvestigationBridge">Optional bridge used to request in-app AI reviews.</param>
    /// <param name="firewallEnforcementPlanner">Optional planner used to prepare reviewed Windows Firewall actions.</param>
    /// <param name="firewallEnforcementExecutor">Optional executor used to apply reviewed Windows Firewall actions.</param>
    public DashboardShellViewModel(
        IAccessWatchRepository repository,
        Func<CancellationToken, Task<int>>? scanAsync = null,
        Func<CancellationToken, Task<int>>? simulateAsync = null,
        AccessWatchSettings? settings = null,
        IAiHandoffService? aiHandoffService = null,
        IAiInvestigationBridge? aiInvestigationBridge = null,
        IFirewallEnforcementPlanner? firewallEnforcementPlanner = null,
        IFirewallEnforcementExecutor? firewallEnforcementExecutor = null)
    {
        this.repository = repository;
        this.scanAsync = scanAsync;
        this.simulateAsync = simulateAsync;
        this.aiHandoffService = aiHandoffService;
        this.aiInvestigationBridge = aiInvestigationBridge;
        this.firewallEnforcementPlanner = firewallEnforcementPlanner;
        this.firewallEnforcementExecutor = firewallEnforcementExecutor;
        this.settings = settings ?? new AccessWatchSettings();
        selectedProtectionMode = this.settings.ProtectionMode.ToString();
        selectedAiMode = this.settings.AiMode.ToString();
        selectedSupportBridgeEndpoint = this.settings.SupportBridgeEndpoint;
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
        new("Rules", "Preview, enable, and tune AccessWatch actions."),
        new("Settings", "Protection mode and AI review settings.")
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
    /// Gets whether the rules page is selected.
    /// </summary>
    public bool IsRulesSelected => SelectedPageTitle == "Rules";

    /// <summary>
    /// Gets whether the settings page is selected.
    /// </summary>
    public bool IsSettingsSelected => SelectedPageTitle == "Settings";

    /// <summary>
    /// Gets whether the selected page is not yet implemented.
    /// </summary>
    public bool IsPlaceholderSelected => !IsOverviewSelected && !IsDevicesSelected && !IsApplicationsSelected && !IsPortsSelected && !IsIncidentsSelected && !IsRulesSelected && !IsSettingsSelected;

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
    /// Gets WPF visibility text for the rules panel.
    /// </summary>
    public string RulesVisibility => ToVisibility(IsRulesSelected);

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
            selectedDeviceTrace = DeviceTracePrompt(value);
            OnPropertyChanged(nameof(SelectedDeviceDetail));
            OnPropertyChanged(nameof(SelectedDeviceTrace));
            OnPropertyChanged(nameof(CanApplyDeviceTrustDecision));
            OnPropertyChanged(nameof(CanTraceSelectedDevice));
        }
    }

    /// <summary>
    /// Gets plain-English details for the selected device.
    /// </summary>
    public string SelectedDeviceDetail => selectedDevice is null
        ? "Select a device to see its name, address, trust, and risk context."
        : selectedDevice.DetailText;

    /// <summary>
    /// Gets the current trace report for the selected device.
    /// </summary>
    public string SelectedDeviceTrace => selectedDeviceTrace;

    /// <summary>
    /// Gets whether the selected device can be traced.
    /// </summary>
    public bool CanTraceSelectedDevice => selectedDevice is not null;

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
        : selectedApplication.DetailText;

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
            selectedPortInvestigation = string.Empty;
            OnPropertyChanged(nameof(SelectedPort));
            OnPropertyChanged(nameof(SelectedPortDetail));
            OnPropertyChanged(nameof(SelectedPortInvestigation));
            OnPropertyChanged(nameof(CanInvestigateSelectedPort));
            OnPropertyChanged(nameof(PortInvestigationButtonText));
        }
    }

    /// <summary>
    /// Gets plain-English details for the selected listening port.
    /// </summary>
    public string SelectedPortDetail => selectedPort is null
        ? "Select a port to see the owning application, reachability, risk, and timing context."
        : selectedPort.DetailText;

    /// <summary>
    /// Gets the selected port investigation guidance.
    /// </summary>
    public string SelectedPortInvestigation => selectedPort is null
        ? "Select a port, then click Investigate port to generate a report."
        : string.IsNullOrWhiteSpace(selectedPortInvestigation)
            ? "Click Investigate port to generate a focused report for the selected endpoint."
            : selectedPortInvestigation;

    /// <summary>
    /// Gets the port investigation button label.
    /// </summary>
    public string PortInvestigationButtonText => string.IsNullOrWhiteSpace(selectedPortInvestigation)
        ? "Investigate port"
        : "Refresh investigation";

    /// <summary>
    /// Gets whether a selected port can be investigated.
    /// </summary>
    public bool CanInvestigateSelectedPort => selectedPort is not null;

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
            selectedIncidentAiReview = string.Empty;
            selectedIncidentRuleSuggestion = string.Empty;
            selectedIncidentNotes = value?.UserNotes ?? string.Empty;
            OnPropertyChanged(nameof(SelectedIncident));
            OnPropertyChanged(nameof(SelectedIncidentDetail));
            OnPropertyChanged(nameof(SelectedIncidentNotes));
            OnPropertyChanged(nameof(SelectedIncidentTimeline));
            OnPropertyChanged(nameof(SelectedIncidentEvidence));
            OnPropertyChanged(nameof(SelectedIncidentSeverityExplanation));
            OnPropertyChanged(nameof(SelectedIncidentRecommendedAction));
            OnPropertyChanged(nameof(SelectedIncidentExport));
            OnPropertyChanged(nameof(CanSaveIncidentNotes));
            OnPropertyChanged(nameof(CanExportIncident));
            OnPropertyChanged(nameof(SelectedIncidentExplanation));
            OnPropertyChanged(nameof(CanApplyIncidentAction));
            OnPropertyChanged(nameof(CanReviewIncidentWithAi));
            OnPropertyChanged(nameof(SelectedIncidentAiReview));
            OnPropertyChanged(nameof(HasIncidentAiReview));
            OnPropertyChanged(nameof(SelectedIncidentRuleSuggestion));
            OnPropertyChanged(nameof(HasIncidentRuleSuggestion));
            OnPropertyChanged(nameof(SelectedIncidentRuleWizard));
        }
    }

    /// <summary>
    /// Gets plain-English details for the selected incident.
    /// </summary>
    public string SelectedIncidentDetail => selectedIncident is null
        ? "Select an incident to see its target, timeline, and AI review context."
        : selectedIncident.DetailText;

    /// <summary>
    /// Gets a local explanation of the selected incident and what to verify next.
    /// </summary>
    public string SelectedIncidentExplanation => selectedIncident is null
        ? "Select an incident to see why AccessWatch grouped it and what to verify next."
        : BuildIncidentExplanation(selectedIncident);

    /// <summary>
    /// Gets timeline text for the selected incident.
    /// </summary>
    public string SelectedIncidentTimeline => selectedIncident is null
        ? "Select an incident to see when it started, changed, and last updated."
        : selectedIncident.Timeline;

    /// <summary>
    /// Gets the local evidence panel for the selected incident.
    /// </summary>
    public string SelectedIncidentEvidence => selectedIncident is null
        ? "Select an incident to see the evidence AccessWatch used."
        : selectedIncident.Evidence;

    /// <summary>
    /// Gets the severity explanation for the selected incident.
    /// </summary>
    public string SelectedIncidentSeverityExplanation => selectedIncident is null
        ? "Select an incident to see why this severity was assigned."
        : selectedIncident.SeverityExplanation;

    /// <summary>
    /// Gets the recommended action for the selected incident.
    /// </summary>
    public string SelectedIncidentRecommendedAction => selectedIncident is null
        ? "Select an incident to see whether Resolve, Watch, Escalate, or a rule is appropriate."
        : selectedIncident.RecommendedAction;

    /// <summary>
    /// Gets or sets editable notes for the selected incident.
    /// </summary>
    public string SelectedIncidentNotes
    {
        get => selectedIncidentNotes;
        set
        {
            selectedIncidentNotes = value ?? string.Empty;
            OnPropertyChanged(nameof(SelectedIncidentNotes));
        }
    }

    /// <summary>
    /// Gets whether selected incident notes can be saved.
    /// </summary>
    public bool CanSaveIncidentNotes => selectedIncident is not null && repository is not null;

    /// <summary>
    /// Gets whether the selected incident can be exported.
    /// </summary>
    public bool CanExportIncident => selectedIncident is not null;

    /// <summary>
    /// Gets export text for the selected incident.
    /// </summary>
    public string SelectedIncidentExport => selectedIncident is null
        ? "Select an incident to prepare an export."
        : selectedIncident.ExportText;

    /// <summary>
    /// Gets rule creation guidance for the selected incident.
    /// </summary>
    public string SelectedIncidentRuleWizard => selectedIncident is null
        ? "Select an incident to see a rule wizard preview."
        : BuildIncidentRuleWizard(selectedIncident, selectedIncidentRuleSuggestion);

    /// <summary>
    /// Gets whether incident action buttons can run.
    /// </summary>
    public bool CanApplyIncidentAction => selectedIncident is not null && repository is not null;

    /// <summary>
    /// Gets whether an incident is selected for the subscription-friendly AI review workspace.
    /// </summary>
    public bool CanReviewIncidentWithAi => selectedIncident is not null && HasAiReviewConnection();

    /// <summary>
    /// Gets the redacted in-app AI review brief for the selected incident.
    /// </summary>
    public string SelectedIncidentAiReview => selectedIncidentAiReview;

    /// <summary>
    /// Gets whether the current incident has a generated AI review brief.
    /// </summary>
    public bool HasIncidentAiReview => !string.IsNullOrWhiteSpace(selectedIncidentAiReview);


    /// <summary>
    /// Gets the current reviewed Windows Firewall protection plan.
    /// </summary>
    public string SelectedEnforcementPlan => enforcementPlanReview.Text;

    /// <summary>
    /// Gets whether a protection plan is available for review.
    /// </summary>
    public bool HasEnforcementPlan => enforcementPlanReview.HasText;

    /// <summary>
    /// Gets whether the reviewed firewall protection plan can be applied.
    /// </summary>
    public bool CanApplyEnforcementPlan => enforcementPlanReview.CanApply(IsLoading);

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
    /// Gets stored AccessWatch rules loaded from storage.
    /// </summary>
    public ObservableCollection<DashboardRuleItemViewModel> Rules { get; } = [];

    /// <summary>
    /// Gets or sets the selected rule shown in the detail panel.
    /// </summary>
    public DashboardRuleItemViewModel? SelectedRule
    {
        get => selectedRule;
        set
        {
            if (Equals(selectedRule, value))
            {
                return;
            }

            selectedRule = value;
            selectedRulePreview = value?.Preview ?? "Select a rule to preview what it would affect.";
            OnPropertyChanged(nameof(SelectedRule));
            OnPropertyChanged(nameof(SelectedRuleDetail));
            OnPropertyChanged(nameof(SelectedRulePreview));
            OnPropertyChanged(nameof(CanApplyRuleAction));
        }
    }

    /// <summary>
    /// Gets plain-English details for the selected rule.
    /// </summary>
    public string SelectedRuleDetail => selectedRule is null
        ? "Select a rule to see its conditions, action, duration, and safety notes."
        : selectedRule.DetailText;

    /// <summary>
    /// Gets the selected rule preview text.
    /// </summary>
    public string SelectedRulePreview => selectedRulePreview;

    /// <summary>
    /// Gets whether rule action buttons can run.
    /// </summary>
    public bool CanApplyRuleAction => selectedRule is not null && repository is not null;

    /// <summary>
    /// Gets incident status filter choices.
    /// </summary>
    public IReadOnlyList<string> IncidentStatusFilterOptions { get; } = ["All", "Open", "Watching", "Resolved"];

    /// <summary>
    /// Gets or sets the incident search text.
    /// </summary>
    public string IncidentSearchText
    {
        get => incidentSearchText;
        set
        {
            if (incidentSearchText == (value ?? string.Empty))
            {
                return;
            }

            incidentSearchText = value ?? string.Empty;
            ApplyIncidentFilters();
            OnPropertyChanged(nameof(IncidentSearchText));
        }
    }

    /// <summary>
    /// Gets or sets the selected incident status filter.
    /// </summary>
    public string SelectedIncidentStatusFilter
    {
        get => selectedIncidentStatusFilter;
        set
        {
            var next = string.IsNullOrWhiteSpace(value) ? "All" : value;
            if (selectedIncidentStatusFilter == next)
            {
                return;
            }

            selectedIncidentStatusFilter = next;
            ApplyIncidentFilters();
            OnPropertyChanged(nameof(SelectedIncidentStatusFilter));
        }
    }

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
    /// Gets AI review choices shown on the Settings page.
    /// </summary>
    public IReadOnlyList<DashboardSettingsOptionViewModel> AiModeOptions { get; } =
    [
        new("Off", "Off", "Keep incident review fully local without ChatGPT assistance."),
        new("ManualChatGptCopy", "ChatGPT subscription", "Use your ChatGPT subscription with redacted in-app incident review briefs."),
        new("SupportBridge", "Support bridge", "Send redacted reviews to a local local support bridge."),
        new("LocalAi", "Local AI", "Reserve local model assistance for a future release."),
        new("OpenAiApi", "OpenAI API", "Reserve connected AI assistance for a future release.")
    ];

    /// <summary>
    /// Gets quiet hour choices shown on the Settings page.
    /// </summary>
    public IReadOnlyList<DashboardSettingsOptionViewModel> QuietHoursOptions { get; } =
    [
        new("Off", "Off", "Show important alerts as they happen."),
        new("22-7", "10 PM - 7 AM", "Keep non-critical rule notifications quiet overnight."),
        new("23-6", "11 PM - 6 AM", "Use a shorter overnight quiet window.")
    ];

    /// <summary>
    /// Gets network profile choices shown on the Settings page.
    /// </summary>
    public IReadOnlyList<DashboardSettingsOptionViewModel> NetworkProfileOptions { get; } =
    [
        new("Home", "Home", "Default profile for your trusted home network."),
        new("Work", "Work", "Use stricter review for shared work networks."),
        new("Public", "Public Wi-Fi", "Treat new devices and reachable ports as more suspicious.")
    ];

    /// <summary>
    /// Gets or sets the selected quiet-hours rule notification window.
    /// </summary>
    public string SelectedQuietHours
    {
        get => selectedQuietHours;
        set
        {
            selectedQuietHours = string.IsNullOrWhiteSpace(value) ? currentQuietHours : value;
            SettingsStatus = "Settings changed. Apply to update the running configuration.";
            OnPropertyChanged(nameof(SelectedQuietHours));
        }
    }

    /// <summary>
    /// Gets or sets the selected network profile for rule previews.
    /// </summary>
    public string SelectedNetworkProfile
    {
        get => selectedNetworkProfile;
        set
        {
            selectedNetworkProfile = string.IsNullOrWhiteSpace(value) ? currentNetworkProfile : value;
            SettingsStatus = "Settings changed. Apply to update the running configuration.";
            OnPropertyChanged(nameof(SelectedNetworkProfile));
        }
    }

    /// <summary>
    /// Gets the quiet-hours setting currently used by rule previews.
    /// </summary>
    public string CurrentQuietHours => currentQuietHours;

    /// <summary>
    /// Gets the network profile currently used by rule previews.
    /// </summary>
    public string CurrentNetworkProfile => currentNetworkProfile;
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
    /// Gets or sets the selected AI review mode value.
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
    /// Gets or sets the support bridge endpoint.
    /// </summary>
    public string SelectedSupportBridgeEndpoint
    {
        get => selectedSupportBridgeEndpoint;
        set
        {
            selectedSupportBridgeEndpoint = value ?? settings.SupportBridgeEndpoint;
            SettingsStatus = "Settings changed. Apply to update the running configuration.";
            OnPropertyChanged(nameof(SelectedSupportBridgeEndpoint));
        }
    }

    /// <summary>
    /// Gets the protection mode currently used by new scans.
    /// </summary>
    public string CurrentProtectionMode => settings.ProtectionMode.ToString();

    /// <summary>
    /// Gets the AI review mode currently used by the dashboard.
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
            OnPropertyChanged(nameof(CanApplyEnforcementPlan));
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
            var devices = FilterUsableDevices(storedDevices);
            var applications = await repository.ListRecentApplicationsAsync(500, cancellationToken);
            var ports = await repository.ListRecentPortsAsync(500, cancellationToken);
            var events = await repository.ListRecentNetworkEventsAsync(50, cancellationToken);
            var incidents = await repository.ListRecentIncidentsAsync(200, cancellationToken);
            var rules = await repository.ListRulesAsync(true, cancellationToken);

            ReplaceMetrics(devices.Count, applications.Count, ports.Count, events.Count);
            ReplaceDevices(devices);
            ReplaceApplications(applications);
            ReplacePorts(ports, events);
            ReplaceIncidents(incidents, devices, applications);
            ReplaceRules(rules);
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
        settings.SupportBridgeEndpoint = string.IsNullOrWhiteSpace(SelectedSupportBridgeEndpoint)
            ? new AccessWatchSettings().SupportBridgeEndpoint
            : SelectedSupportBridgeEndpoint.Trim();
        selectedSupportBridgeEndpoint = settings.SupportBridgeEndpoint;
        currentQuietHours = SelectedQuietHours;
        currentNetworkProfile = SelectedNetworkProfile;
        SettingsStatus = $"Settings applied. Running {CurrentProtectionMode} protection with {CurrentAiMode} AI review, {DescribeQuietHours(CurrentQuietHours)}, and {CurrentNetworkProfile} network rules.";
        RefreshRulePreviews();
        OnPropertyChanged(nameof(CurrentProtectionMode));
        OnPropertyChanged(nameof(CurrentAiMode));
        OnPropertyChanged(nameof(CurrentQuietHours));
        OnPropertyChanged(nameof(CurrentNetworkProfile));
        OnPropertyChanged(nameof(SelectedSupportBridgeEndpoint));
        OnPropertyChanged(nameof(CanReviewIncidentWithAi));
    }
    /// <summary>
    /// Restores Settings page selections to the running configuration.
    /// </summary>
    public void ResetSettingsSelections()
    {
        selectedProtectionMode = settings.ProtectionMode.ToString();
        selectedAiMode = settings.AiMode.ToString();
        selectedSupportBridgeEndpoint = settings.SupportBridgeEndpoint;
        selectedQuietHours = currentQuietHours;
        selectedNetworkProfile = currentNetworkProfile;
        SettingsStatus = "Settings match the running configuration.";
        OnPropertyChanged(nameof(SelectedProtectionMode));
        OnPropertyChanged(nameof(SelectedAiMode));
        OnPropertyChanged(nameof(SelectedSupportBridgeEndpoint));
        OnPropertyChanged(nameof(SelectedQuietHours));
        OnPropertyChanged(nameof(SelectedNetworkProfile));
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
    /// Creates a plain-English trace report for the selected device.
    /// </summary>
    public void TraceSelectedDevice()
    {
        if (selectedDevice is null)
        {
            selectedDeviceTrace = DeviceTracePrompt(null);
            OnPropertyChanged(nameof(SelectedDeviceTrace));
            StatusMessage = "Select a device before tracing it.";
            return;
        }

        selectedDeviceTrace = BuildDeviceTrace(selectedDevice);
        OnPropertyChanged(nameof(SelectedDeviceTrace));
        StatusMessage = $"Trace ready for {selectedDevice.Name}.";
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
        UpdateDeviceEnforcementPlan(decision, updatedDevice);
        StatusMessage = decision == TrustStatus.Blocked && firewallEnforcementPlanner is not null
            ? $"Blocked {updatedDevice.Name}; protection plan prepared."
            : $"{TrustDecisionVerb(decision)} {updatedDevice.Name}.";
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
        UpdateApplicationEnforcementPlan(decision, updatedApplication);
        StatusMessage = decision == TrustStatus.Blocked && firewallEnforcementPlanner is not null
            ? $"Blocked {updatedApplication.Name}; protection plan prepared."
            : $"{TrustDecisionVerb(decision)} {updatedApplication.Name}.";
    }

    /// <summary>
    /// Applies the current reviewed Windows Firewall protection plan.
    /// </summary>
    public async Task ApplySelectedEnforcementPlanAsync(CancellationToken cancellationToken)
    {
        if (enforcementPlanReview.SelectedPlan is null)
        {
            StatusMessage = "Block a device or app before applying protection.";
            return;
        }

        if (firewallEnforcementExecutor is null)
        {
            StatusMessage = "Firewall protection application is not connected for this dashboard session.";
            return;
        }

        var plan = enforcementPlanReview.SelectedPlan;
        var result = await firewallEnforcementExecutor.ApplyAsync(plan, cancellationToken);
        enforcementPlanReview.ShowApplyResult(plan, result);
        StatusMessage = result.Summary;
        NotifyEnforcementPlanChanged();
    }

    /// <summary>
    /// Highlights the selected port investigation guidance.
    /// </summary>
    public void InvestigateSelectedPort()
    {
        if (selectedPort is null)
        {
            selectedPortInvestigation = string.Empty;
            StatusMessage = "Select a port before investigating it.";
        }
        else
        {
            selectedPortInvestigation = BuildPortInvestigationReport(selectedPort);
            StatusMessage = $"Investigation ready for {selectedPort.Endpoint}.";
        }

        OnPropertyChanged(nameof(SelectedPortInvestigation));
        OnPropertyChanged(nameof(PortInvestigationButtonText));
    }

    /// <summary>
    /// Marks the selected incident as resolved.
    /// </summary>
    public Task ResolveSelectedIncidentAsync(CancellationToken cancellationToken)
    {
        return ApplySelectedIncidentUpdateAsync(IncidentStatus.Resolved, null, "Resolved", "Resolved means you confirmed this was expected or no longer active; AccessWatch keeps it for history.", cancellationToken);
    }

    /// <summary>
    /// Marks the selected incident as watched.
    /// </summary>
    public Task WatchSelectedIncidentAsync(CancellationToken cancellationToken)
    {
        return ApplySelectedIncidentUpdateAsync(IncidentStatus.Watching, null, "Watching", "Watch keeps this grouped and visible if it repeats, without treating it as solved.", cancellationToken);
    }

    /// <summary>
    /// Escalates the selected incident to critical review.
    /// </summary>
    public Task EscalateSelectedIncidentAsync(CancellationToken cancellationToken)
    {
        return ApplySelectedIncidentUpdateAsync(IncidentStatus.Open, RiskLevel.Critical, "Escalated", "Escalate marks this as critical because it looks unexpected, sensitive, or worth immediate review.", cancellationToken);
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
    /// Refreshes the selected rule preview.
    /// </summary>
    public void PreviewSelectedRule()
    {
        if (selectedRule is null)
        {
            StatusMessage = "Select a rule before previewing it.";
            return;
        }

        selectedRulePreview = BuildRulePreview(selectedRule);
        StatusMessage = $"Previewed rule {selectedRule.Name}.";
        OnPropertyChanged(nameof(SelectedRulePreview));
    }

    /// <summary>
    /// Enables the selected rule after review.
    /// </summary>
    public Task EnableSelectedRuleAsync(CancellationToken cancellationToken)
    {
        return SetSelectedRuleEnabledAsync(true, cancellationToken);
    }

    /// <summary>
    /// Disables the selected rule.
    /// </summary>
    public Task DisableSelectedRuleAsync(CancellationToken cancellationToken)
    {
        return SetSelectedRuleEnabledAsync(false, cancellationToken);
    }

    private async Task SetSelectedRuleEnabledAsync(bool enabled, CancellationToken cancellationToken)
    {
        if (selectedRule is null)
        {
            StatusMessage = enabled ? "Select a rule before enabling it." : "Select a rule before disabling it.";
            return;
        }

        if (repository is null)
        {
            StatusMessage = "Rule actions are not connected for this dashboard session.";
            return;
        }

        var updatedRule = ToAccessWatchRule(selectedRule, enabled);
        var ruleId = await repository.UpsertRuleAsync(updatedRule, cancellationToken);
        var displayRule = CreateRuleItem(updatedRule with { RuleId = ruleId > 0 ? ruleId : updatedRule.RuleId });
        var index = Rules.IndexOf(selectedRule);
        if (index >= 0)
        {
            Rules[index] = displayRule;
        }
        else
        {
            Rules.Insert(0, displayRule);
        }

        SelectedRule = displayRule;
        StatusMessage = enabled
            ? $"Enabled rule {displayRule.Name}. AccessWatch will apply its {displayRule.Action} action when matching activity appears."
            : $"Disabled rule {displayRule.Name}. Matching activity will stay visible, but this rule will not act on it.";
    }
    /// <summary>
    /// Creates a redacted in-app AI review brief for the selected incident.
    /// </summary>
    public void CreateSelectedIncidentAiReview()
    {
        CreateSelectedIncidentAiReviewAsync(CancellationToken.None).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Creates or requests an in-app AI review for the selected incident.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for bridge review.</param>
    public async Task CreateSelectedIncidentAiReviewAsync(CancellationToken cancellationToken)
    {
        if (selectedIncident is null)
        {
            StatusMessage = "Select an incident before starting AI review.";
            return;
        }

        if (settings.AiMode == AiMode.Off)
        {
            StatusMessage = "Turn on AI review in Settings before reviewing with AI.";
            return;
        }

        if (aiHandoffService is null)
        {
            StatusMessage = "AI review is not connected for this dashboard session.";
            return;
        }

        var redactedIncident = aiHandoffService.CreateRedactedIncidentSummary(ToIncident(selectedIncident));
        if (settings.AiMode == AiMode.SupportBridge)
        {
            if (aiInvestigationBridge is null)
            {
                StatusMessage = "Support bridge is not connected for this dashboard session.";
                return;
            }

            selectedIncidentAiReview = "Support bridge is reviewing the redacted incident context...";
            OnPropertyChanged(nameof(SelectedIncidentAiReview));
            OnPropertyChanged(nameof(HasIncidentAiReview));
            StatusMessage = $"Sent redacted review request for {selectedIncident.Title} to support bridge.";
            var result = await aiInvestigationBridge.ReviewIncidentAsync(
                BuildAiInvestigationRequest(selectedIncident, redactedIncident),
                settings,
                cancellationToken).ConfigureAwait(true);
            selectedIncidentAiReview = BuildBridgeReview(selectedIncident, result);
            OnPropertyChanged(nameof(SelectedIncidentAiReview));
            OnPropertyChanged(nameof(HasIncidentAiReview));
            StatusMessage = result.Succeeded
                ? $"Support bridge review ready for {selectedIncident.Title}."
                : $"Support bridge review unavailable for {selectedIncident.Title}.";
            return;
        }

        selectedIncidentAiReview = BuildChatGptReviewBrief(selectedIncident, redactedIncident);
        OnPropertyChanged(nameof(SelectedIncidentAiReview));
        OnPropertyChanged(nameof(HasIncidentAiReview));
        StatusMessage = $"Prepared AI review brief for {selectedIncident.Title}.";
    }

    /// <summary>
    /// Updates the status after copying the selected incident review brief for ChatGPT.
    /// </summary>
    public void MarkIncidentChatGptCopied()
    {
        StatusMessage = HasIncidentAiReview
            ? "Copied the redacted review brief. Paste it into ChatGPT when you are ready."
            : "Review the incident with AI before copying it for ChatGPT.";
    }

    /// <summary>
    /// Saves notes for the selected incident.
    /// </summary>
    public async Task SaveSelectedIncidentNotesAsync(CancellationToken cancellationToken)
    {
        if (selectedIncident is null)
        {
            StatusMessage = "Select an incident before saving notes.";
            return;
        }

        if (repository is null)
        {
            StatusMessage = "Incident notes are not connected for this dashboard session.";
            return;
        }

        var updatedIncident = selectedIncident with { UserNotes = selectedIncidentNotes.Trim() };
        await repository.UpsertIncidentAsync(ToIncident(updatedIncident), cancellationToken);
        ReplaceIncidentRow(selectedIncident, updatedIncident);
        SelectedIncident = updatedIncident;
        StatusMessage = $"Saved notes for {updatedIncident.Title}.";
    }

    /// <summary>
    /// Prepares export text for the selected incident.
    /// </summary>
    public void PrepareSelectedIncidentExport()
    {
        StatusMessage = selectedIncident is null
            ? "Select an incident before preparing an export."
            : $"Prepared export for {selectedIncident.Title}.";
        OnPropertyChanged(nameof(SelectedIncidentExport));
    }

    private bool HasAiReviewConnection() => settings.AiMode switch
    {
        AiMode.Off => false,
        AiMode.SupportBridge => aiHandoffService is not null && aiInvestigationBridge is not null,
        _ => aiHandoffService is not null
    };

    private async Task ApplySelectedIncidentUpdateAsync(
        IncidentStatus status,
        RiskLevel? riskLevel,
        string statusVerb,
        string statusMeaning,
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
            RawLastUpdatedUtc = now,
            UserNotes = selectedIncidentNotes.Trim()
        };

        var incident = ToIncident(updatedIncident, status == IncidentStatus.Resolved ? now : null);
        await repository.UpsertIncidentAsync(incident, cancellationToken);
        var selectedIndex = Incidents.IndexOf(selectedIncident);
        if (selectedIndex >= 0)
        {
            Incidents[selectedIndex] = updatedIncident;
        }

        SelectedIncident = updatedIncident;
        StatusMessage = $"{statusVerb} incident {updatedIncident.Title}. {statusMeaning}";
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
            ResolvedUtc = resolvedUtc,
            UserNotes = string.IsNullOrWhiteSpace(incident.UserNotes) ? null : incident.UserNotes
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
            eventCount = incident.EventCount,
            groupKey = incident.GroupKey,
            recommendedAction = incident.RecommendedAction
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
                DeviceInventoryState(device),
                FormatTimestamp(device.FirstSeenUtc),
                FormatTimestamp(device.LastSeenUtc),
                FormatOptionalTimestamp(device.LastConfirmedUtc),
                DeviceRecommendedAction(device),
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
                application.FilePath ?? string.Empty,
                BuildApplicationIdentity(application, application.ProcessName)));
        }

        SelectedApplication = Applications.FirstOrDefault();
    }

    private void ReplacePorts(IReadOnlyList<ListeningPort> ports, IReadOnlyList<NetworkEvent> events)
    {
        Ports.Clear();
        foreach (var port in ports.Take(200))
        {
            var latestPortEvent = FindLatestPortEvent(port, events);
            var meaning = DescribePortMeaning(port.PortNumber);
            var exposure = DescribePortExposure(port);
            var networkZone = DescribeNetworkZone(port.LocalAddress);
            var networkAdapter = DescribeNetworkAdapter(port.LocalAddress, networkZone);
            var reachabilityTest = DescribeReachabilityTest(port, networkZone);
            var historyStatus = DescribePortHistory(port, latestPortEvent);
            var exposureChange = DescribeExposureChange(port, latestPortEvent);
            var appConfidence = DescribePortAppConfidence(port.Application);
            var suggestedAction = SuggestPortAction(port, latestPortEvent);
            var applicationName = FirstUseful(port.Application?.DisplayName, port.Application?.ProcessName, "Unknown application");
            var identity = BuildApplicationIdentity(port.Application, port.Application?.ProcessName);

            Ports.Add(new DashboardPortItemViewModel(
                $"{port.Protocol} {port.LocalAddress}:{port.PortNumber}",
                applicationName,
                port.Reachability.ToString(),
                port.RiskStatus.ToString(),
                port.TrustStatus.ToString(),
                FormatTimestamp(port.FirstSeenUtc),
                FormatTimestamp(port.LastSeenUtc),
                identity,
                port.PortNumber,
                port.LocalAddress,
                meaning,
                exposure,
                networkAdapter,
                networkZone,
                reachabilityTest,
                historyStatus,
                exposureChange,
                appConfidence,
                suggestedAction,
                BuildPortInvestigation(port, meaning, exposure, networkAdapter, networkZone, reachabilityTest, historyStatus, exposureChange, appConfidence, suggestedAction)));
        }

        SelectedPort = Ports.FirstOrDefault();
    }

    private void ReplaceIncidents(
        IReadOnlyList<Incident> incidents,
        IReadOnlyList<NetworkDevice> devices,
        IReadOnlyList<AppIdentity> applications)
    {
        allIncidents.Clear();
        foreach (var incident in incidents.Take(200))
        {
            var device = devices.FirstOrDefault(candidate => incident.MainDeviceId is not null && candidate.DeviceId == incident.MainDeviceId.Value);
            var application = applications.FirstOrDefault(candidate => incident.MainApplicationId is not null && candidate.ApplicationId == incident.MainApplicationId.Value);
            var target = BuildIncidentTarget(device, application);
            var title = FirstUseful(incident.Title, "Untitled incident");
            var summary = FirstUseful(incident.Summary, "No incident summary recorded yet.");
            var grouping = BuildIncidentGrouping(incident, target);
            var severityExplanation = BuildIncidentSeverityExplanation(incident.RiskLevel, incident.EventCount);
            var timeline = BuildIncidentTimeline(incident);
            var evidence = BuildIncidentEvidence(title, summary, target, grouping, incident.UserNotes);
            var recommendedAction = BuildIncidentRecommendedAction(incident.RiskLevel, incident.Status, incident.EventCount);

            allIncidents.Add(new DashboardIncidentItemViewModel(
                incident.IncidentId,
                incident.MainDeviceId,
                incident.MainApplicationId,
                incident.RiskLevel,
                incident.Status,
                incident.StartedUtc,
                incident.LastUpdatedUtc,
                title,
                incident.RiskLevel.ToString(),
                incident.Status.ToString(),
                incident.EventCount,
                target,
                FormatTimestamp(incident.StartedUtc),
                FormatTimestamp(incident.LastUpdatedUtc),
                summary,
                grouping.Key,
                grouping.Description,
                severityExplanation,
                timeline,
                evidence,
                recommendedAction,
                incident.UserNotes ?? string.Empty,
                BuildIncidentExport(title, incident, target, grouping.Description, severityExplanation, timeline, evidence, recommendedAction)));
        }

        ApplyIncidentFilters();
    }

    private void ApplyIncidentFilters()
    {
        var previousSelection = selectedIncident;
        Incidents.Clear();
        foreach (var incident in allIncidents.Where(MatchesIncidentFilters))
        {
            Incidents.Add(incident);
        }

        SelectedIncident = previousSelection is not null && Incidents.Contains(previousSelection)
            ? previousSelection
            : Incidents.FirstOrDefault();
    }

    private bool MatchesIncidentFilters(DashboardIncidentItemViewModel incident)
    {
        var statusMatches = selectedIncidentStatusFilter == "All" || incident.Status == selectedIncidentStatusFilter;
        if (!statusMatches)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(incidentSearchText))
        {
            return true;
        }

        return incident.DetailText.Contains(incidentSearchText, StringComparison.OrdinalIgnoreCase) ||
            incident.GroupKey.Contains(incidentSearchText, StringComparison.OrdinalIgnoreCase);
    }

    private void ReplaceIncidentRow(DashboardIncidentItemViewModel oldIncident, DashboardIncidentItemViewModel newIncident)
    {
        var allIndex = allIncidents.IndexOf(oldIncident);
        if (allIndex >= 0)
        {
            allIncidents[allIndex] = newIncident;
        }

        var visibleIndex = Incidents.IndexOf(oldIncident);
        if (visibleIndex >= 0)
        {
            Incidents[visibleIndex] = newIncident;
        }
    }

    private void ReplaceRules(IReadOnlyList<AccessWatchRule> rules)
    {
        Rules.Clear();
        foreach (var rule in rules.Take(200))
        {
            Rules.Add(CreateRuleItem(rule));
        }

        SelectedRule = Rules.FirstOrDefault();
    }

    private void RefreshRulePreviews()
    {
        if (Rules.Count == 0)
        {
            return;
        }

        var selectedRuleId = selectedRule?.RuleId;
        var refreshed = Rules.Select(rule => CreateRuleItem(ToAccessWatchRule(rule, rule.IsEnabled))).ToList();
        Rules.Clear();
        foreach (var rule in refreshed)
        {
            Rules.Add(rule);
        }

        SelectedRule = Rules.FirstOrDefault(rule => rule.RuleId == selectedRuleId) ?? Rules.FirstOrDefault();
    }

    private DashboardRuleItemViewModel CreateRuleItem(AccessWatchRule rule)
    {
        var app = GetRuleConditionValue(rule.ConditionJson, "app") ?? GetRuleConditionValue(rule.ConditionJson, "mainApplicationId");
        var device = GetRuleConditionValue(rule.ConditionJson, "device") ?? GetRuleConditionValue(rule.ConditionJson, "mainDeviceId");
        var port = GetRuleConditionValue(rule.ConditionJson, "port") ?? GetRuleConditionValue(rule.ConditionJson, "destinationPort");
        var network = GetRuleConditionValue(rule.ConditionJson, "network");
        var signature = GetRuleConditionValue(rule.ConditionJson, "signature");
        var path = GetRuleConditionValue(rule.ConditionJson, "path");
        var title = GetRuleConditionValue(rule.ConditionJson, "title");
        var target = GetRuleConditionValue(rule.ConditionJson, "target");
        var source = GetRuleConditionValue(rule.ConditionJson, "source");
        var groupKey = GetRuleConditionValue(rule.ConditionJson, "groupKey");
        var conditionParts = new List<string>();
        AddRuleCondition(conditionParts, "App", app);
        AddRuleCondition(conditionParts, "Device", device);
        AddRuleCondition(conditionParts, "Port", port);
        AddRuleCondition(conditionParts, "Network", network);
        AddRuleCondition(conditionParts, "Signature", signature);
        AddRuleCondition(conditionParts, "Path", path);
        AddRuleCondition(conditionParts, "Incident", title);
        AddRuleCondition(conditionParts, "Target", target);
        AddRuleCondition(conditionParts, "Group", groupKey);

        var conditions = conditionParts.Count == 0
            ? "No specific conditions stored yet. Review before enabling."
            : string.Join("; ", conditionParts);
        var scope = FirstUseful(
            LabelRuleScope("Application", app),
            LabelRuleScope("Device", device),
            LabelRuleScope("Port", port),
            LabelRuleScope("Target", target),
            "Matching future AccessWatch activity");
        var duration = DescribeRuleDuration(rule.ConditionJson);
        var quietHours = DescribeQuietHours(CurrentQuietHours);
        var profile = DescribeNetworkProfile(CurrentNetworkProfile);
        var changeDetection = DescribeRuleChangeDetection(app, device, signature, path);
        var summary = BuildRuleInvestigationSummary(rule, scope, conditions, duration, profile, source);
        var preview = BuildRulePreview(rule, scope, conditions, duration, quietHours, profile);

        return new DashboardRuleItemViewModel(
            rule.RuleId,
            FirstUseful(rule.Name, "Unnamed rule"),
            rule.Enabled ? "Enabled" : "Disabled",
            rule.Enabled,
            rule.Action.ToString(),
            rule.RiskLevel.ToString(),
            scope,
            conditions,
            preview,
            duration,
            quietHours,
            profile,
            changeDetection,
            summary,
            FirstUseful(rule.Description, "No description recorded."),
            FirstUseful(rule.ConditionJson, "{}"),
            FormatTimestamp(rule.CreatedUtc),
            FormatTimestamp(rule.UpdatedUtc));
    }

    private static AccessWatchRule ToAccessWatchRule(DashboardRuleItemViewModel rule, bool enabled)
    {
        return new AccessWatchRule
        {
            RuleId = rule.RuleId,
            Name = rule.Name,
            Description = rule.Description,
            ConditionJson = string.IsNullOrWhiteSpace(rule.ConditionJson) ? "{}" : rule.ConditionJson,
            RiskLevel = Enum.TryParse<RiskLevel>(rule.RiskLevel, out var riskLevel) ? riskLevel : RiskLevel.Medium,
            Action = Enum.TryParse<NotificationAction>(rule.Action, out var action) ? action : NotificationAction.SoftNotify,
            Enabled = enabled,
            UpdatedUtc = DateTimeOffset.UtcNow
        };
    }

    private static void AddRuleCondition(ICollection<string> parts, string label, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            parts.Add($"{label}: {value}");
        }
    }

    private static string? LabelRuleScope(string label, string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : $"{label} {value}";
    }

    private static string BuildRulePreview(DashboardRuleItemViewModel rule)
    {
        return $"This rule would affect {rule.Scope}. Conditions: {rule.Conditions}. Action: {rule.Action}. Risk label: {rule.RiskLevel}. Duration: {rule.Duration}. Notifications: {rule.QuietHours}. Network profile: {rule.NetworkProfile}.";
    }

    private static string BuildRulePreview(AccessWatchRule rule, string scope, string conditions, string duration, string quietHours, string profile)
    {
        var state = rule.Enabled ? "enabled" : "disabled until you turn it on";
        return $"This rule is {state}. It would affect {scope}. Conditions: {conditions}. Action: {rule.Action}. Risk label: {rule.RiskLevel}. Duration: {duration}. Notifications: {quietHours}. Network profile: {profile}.";
    }

    private static string BuildRuleInvestigationSummary(AccessWatchRule rule, string scope, string conditions, string duration, string profile, string? source)
    {
        var origin = string.IsNullOrWhiteSpace(source) ? "manual or stored rule" : source;
        return $"In-app investigation summary: this {origin} rule watches {scope}, checks {conditions}, uses {rule.Action}, and is scoped to {profile}. {duration}";
    }

    private static string DescribeRuleDuration(string conditionJson)
    {
        var expires = GetRuleConditionValue(conditionJson, "expiresUtc");
        if (!string.IsNullOrWhiteSpace(expires))
        {
            return $"Temporary until {expires}.";
        }

        var hours = GetRuleConditionValue(conditionJson, "durationHours");
        return string.IsNullOrWhiteSpace(hours)
            ? "Permanent until disabled."
            : $"Temporary: watch for {hours} hours.";
    }

    private static string DescribeQuietHours(string value)
    {
        return value switch
        {
            "22-7" => "quiet hours from 10 PM to 7 AM",
            "23-6" => "quiet hours from 11 PM to 6 AM",
            _ => "quiet hours off"
        };
    }

    private static string DescribeNetworkProfile(string value)
    {
        return value switch
        {
            "Work" => "Work network profile",
            "Public" => "Public Wi-Fi profile",
            _ => "Home network profile"
        };
    }

    private static string DescribeRuleChangeDetection(string? app, string? device, string? signature, string? path)
    {
        if (!string.IsNullOrWhiteSpace(signature) || !string.IsNullOrWhiteSpace(path))
        {
            return "Review if the app signature or executable path changes.";
        }

        if (!string.IsNullOrWhiteSpace(app) || !string.IsNullOrWhiteSpace(device))
        {
            return "Review if this trusted app or device changes identity.";
        }

        return "Review matches before trusting because no stable app or device identity is stored.";
    }

    private static string? GetRuleConditionValue(string conditionJson, string propertyName)
    {
        if (string.IsNullOrWhiteSpace(conditionJson))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(conditionJson);
            return ReadRuleConditionValue(document.RootElement, propertyName);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? ReadRuleConditionValue(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var property) || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return null;
        }

        return property.ValueKind switch
        {
            JsonValueKind.String => property.GetString(),
            JsonValueKind.Number => property.TryGetInt64(out var integer) ? integer.ToString(CultureInfo.InvariantCulture) : property.GetDouble().ToString(CultureInfo.InvariantCulture),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => property.GetRawText()
        };
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


    private static readonly IReadOnlyDictionary<int, string> KnownPortMeanings = new Dictionary<int, string>
    {
        [21] = "FTP file transfer. This sends credentials in older plain-text setups and should not be exposed unless you intentionally run it.",
        [22] = "SSH remote shell. Useful for administration, but it allows sign-in attempts from other devices when reachable.",
        [23] = "Telnet remote shell. This is legacy and usually unsafe because it is commonly unencrypted.",
        [25] = "SMTP mail service. Home PCs rarely need to expose this directly.",
        [53] = "DNS service. Usually belongs to resolvers, VPN tools, containers, or development environments.",
        [80] = "HTTP web service. This may be IIS, a local web app, a router/admin page, or development tooling.",
        [135] = "Windows RPC endpoint mapper. This is a Windows service endpoint and should stay limited to trusted private networks.",
        [137] = "NetBIOS name service. This is legacy Windows discovery and is normally only expected on private networks.",
        [139] = "NetBIOS session service. This is usually legacy Windows file/printer sharing discovery.",
        [443] = "HTTPS web service. This can be a browser-facing site, admin page, sync tool, or local development server.",
        [445] = "SMB file sharing. This is Windows file sharing and should normally be limited to trusted private networks.",
        [1433] = "Microsoft SQL Server. Database ports should rarely be reachable from ordinary home or public networks.",
        [3306] = "MySQL or MariaDB database. Database ports should stay local or limited to trusted systems.",
        [3389] = "Remote Desktop. This allows remote sign-in when enabled and deserves careful review.",
        [5432] = "PostgreSQL database. Database ports should stay local or limited to trusted systems.",
        [5900] = "VNC remote screen sharing. This allows remote desktop-style access when enabled.",
        [5985] = "Windows Remote Management over HTTP. This is administrative access and should be limited to trusted networks.",
        [5986] = "Windows Remote Management over HTTPS. This is administrative access and should be limited to trusted networks.",
        [8080] = "Alternate HTTP web service. Common for development servers, proxies, device tools, and admin consoles.",
        [8443] = "Alternate HTTPS web service. Common for secure admin consoles, development servers, and local services.",
        [9443] = "Alternate HTTPS/admin service. Many tools use this for local dashboards, admin consoles, or development servers.",
        [47001] = "Windows remote management helper service. Often related to local Windows service management.",
        [60000] = "High dynamic/private port. Often assigned by an app, device sync tool, VM, container, or local service."
    };

    private static string BuildPortInvestigation(
        ListeningPort port,
        string meaning,
        string exposure,
        string networkAdapter,
        string networkZone,
        string reachabilityTest,
        string historyStatus,
        string exposureChange,
        string appConfidence,
        string suggestedAction)
    {
        return string.Join(
            Environment.NewLine,
            $"Meaning: {meaning}",
            $"Exposure: {exposure}",
            $"Likely adapter: {networkAdapter}",
            $"Network zone: {networkZone}",
            $"Reachability check: {reachabilityTest}",
            $"History: {historyStatus}",
            $"Exposure change: {exposureChange}",
            $"Application: {FirstUseful(port.Application?.DisplayName, port.Application?.ProcessName, "Unknown application")}",
            $"Application confidence: {appConfidence}",
            $"Identity: {BuildApplicationIdentity(port.Application, port.Application?.ProcessName)}",
            $"Next step: {suggestedAction}");
    }

    private static string BuildPortInvestigationReport(DashboardPortItemViewModel port)
    {
        return string.Join(
            Environment.NewLine,
            "Investigation report",
            $"Endpoint: {port.Endpoint}",
            $"Application: {port.ApplicationName}",
            $"Application confidence: {port.AppConfidence}",
            $"Meaning: {port.Meaning}",
            $"Exposure: {port.Exposure}",
            $"Likely adapter: {port.NetworkAdapter}",
            $"Network zone: {port.NetworkZone}",
            $"Reachability check: {port.ReachabilityTest}",
            $"History: {port.HistoryStatus}",
            $"Exposure change: {port.ExposureChange}",
            $"Identity: {port.Detail}",
            "What to check:",
            $"- Confirm {port.ApplicationName} is expected to own {port.Endpoint}.",
            $"- Confirm {port.NetworkAdapter} is the adapter you expect.",
            "- If this is unexpected, close the app or service and run another scan.",
            $"Recommended decision: {port.SuggestedAction}");
    }

    private static string DescribePortMeaning(int portNumber)
    {
        return KnownPortMeanings.TryGetValue(portNumber, out var meaning)
            ? meaning
            : "No common profile is built in for this port yet. Investigate the owning process before trusting it.";
    }

    private static string DescribePortExposure(ListeningPort port)
    {
        if (port.Reachability == PortReachability.LocalOnly)
        {
            return "Local-only listener. Other devices should not be able to connect to this bind address.";
        }

        if (IsAllAdaptersAddress(port.LocalAddress))
        {
            return "Listening on all network adapters. This can include Wi-Fi, Ethernet, VPN, WSL, Docker, and virtual adapters.";
        }

        if (IsPrivateOrVirtualAddress(port.LocalAddress))
        {
            return $"Listening on private or virtual address {port.LocalAddress}. Confirm which adapter owns this address before treating it as real LAN exposure.";
        }

        return $"Listening on {port.LocalAddress}. Confirm whether this address is reachable from another device.";
    }

    private static string DescribeNetworkZone(string localAddress)
    {
        if (IsAllAdaptersAddress(localAddress))
        {
            return "All adapters";
        }

        if (IsLoopbackAddress(localAddress))
        {
            return "Loopback";
        }

        if (localAddress.StartsWith("172.17.", StringComparison.Ordinal) || localAddress.StartsWith("172.18.", StringComparison.Ordinal))
        {
            return "Docker";
        }

        if (localAddress.StartsWith("172.22.", StringComparison.Ordinal) || localAddress.StartsWith("172.24.", StringComparison.Ordinal) || localAddress.StartsWith("172.25.", StringComparison.Ordinal))
        {
            return "WSL or Hyper-V";
        }

        if (localAddress.StartsWith("10.", StringComparison.Ordinal) || localAddress.StartsWith("192.168.", StringComparison.Ordinal))
        {
            return "LAN";
        }

        if (localAddress.StartsWith("172.", StringComparison.Ordinal))
        {
            return "VPN or private virtual network";
        }

        if (localAddress.StartsWith("169.254.", StringComparison.Ordinal) || localAddress.StartsWith("fe80", StringComparison.OrdinalIgnoreCase))
        {
            return "Link-local";
        }

        return "Public or unknown network";
    }

    private static string DescribeNetworkAdapter(string localAddress, string networkZone)
    {
        return networkZone switch
        {
            "All adapters" => "All network adapters",
            "Loopback" => "Loopback adapter on this PC",
            "LAN" => $"LAN adapter with address {localAddress}",
            "Docker" => $"Docker virtual adapter with address {localAddress}",
            "WSL or Hyper-V" => $"WSL or Hyper-V virtual adapter with address {localAddress}",
            "VPN or private virtual network" => $"VPN or private virtual adapter with address {localAddress}",
            "Link-local" => $"Link-local adapter with address {localAddress}",
            _ => $"Adapter for {localAddress}"
        };
    }

    private static string DescribeReachabilityTest(ListeningPort port, string networkZone)
    {
        if (port.Reachability == PortReachability.LocalOnly)
        {
            return "No. It is bound to this PC only.";
        }

        if (port.Reachability == PortReachability.Unknown)
        {
            return "Unknown from this scan. Run another scan or test from a second device to confirm.";
        }

        if (networkZone == "All adapters")
        {
            return "Possibly. It listens on all adapters, so another device may be able to connect if the firewall allows it.";
        }

        if (networkZone is "LAN" or "VPN or private virtual network")
        {
            return "Possibly. It is bound to a network address; verify from another device or block it if unexpected.";
        }

        if (networkZone is "Docker" or "WSL or Hyper-V")
        {
            return "Usually limited to a virtual network, but forwarded ports can still expose it. Verify if unexpected.";
        }

        return "Possibly reachable. Confirm from another device before trusting it.";
    }

    private static string DescribePortHistory(ListeningPort port, NetworkEvent? latestPortEvent)
    {
        if (latestPortEvent?.EventType == "NewListeningPort")
        {
            return "Newly opened since the latest recorded scan.";
        }

        if (latestPortEvent?.EventType == "ListeningPortApplicationChanged")
        {
            return "Owning application changed since this port was first seen.";
        }

        if (port.FirstSeenUtc == default || port.LastSeenUtc == default)
        {
            return "No history yet; run another scan to compare changes.";
        }

        if (port.FirstSeenUtc == port.LastSeenUtc)
        {
            return "Opened once; waiting for another scan to confirm whether it stays open.";
        }

        return "Previously seen and still open on the latest scan.";
    }

    private static string DescribeExposureChange(ListeningPort port, NetworkEvent? latestPortEvent)
    {
        if (latestPortEvent?.EventType == "NewListeningPort" && IsHighRiskStatus(port.RiskStatus))
        {
            return "New high-risk exposure since the last scan.";
        }

        if (latestPortEvent?.EventType == "ListeningPortApplicationChanged" && IsHighRiskStatus(port.RiskStatus))
        {
            return "High-risk port changed owning application.";
        }

        if (port.Reachability == PortReachability.NetworkReachable && IsHighRiskStatus(port.RiskStatus))
        {
            return "High-risk network exposure; verify it is expected.";
        }

        return "No high-risk exposure change detected.";
    }

    private static string DescribePortAppConfidence(AppIdentity? application)
    {
        if (application is null || application.DisplayName == "Unknown application")
        {
            return "Low (20%) - application identity is unavailable.";
        }

        if (!string.IsNullOrWhiteSpace(application.FilePath) && application.SignatureStatus == SignatureStatus.TrustedSigned)
        {
            return "High (90%) - signed executable path is known.";
        }

        if (!string.IsNullOrWhiteSpace(application.ProcessName) || !string.IsNullOrWhiteSpace(application.DisplayName))
        {
            return "Medium (60%) - process identity is known, but publisher or signature is incomplete.";
        }

        return "Low (20%) - application identity is incomplete.";
    }

    private static NetworkEvent? FindLatestPortEvent(ListeningPort port, IReadOnlyList<NetworkEvent> events)
    {
        return events
            .Where(networkEvent => MatchesPortEvent(port, networkEvent))
            .OrderByDescending(networkEvent => networkEvent.CreatedUtc)
            .FirstOrDefault();
    }

    private static bool MatchesPortEvent(ListeningPort port, NetworkEvent networkEvent)
    {
        if (networkEvent.DestinationPort != port.PortNumber)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(networkEvent.Protocol) && !string.Equals(networkEvent.Protocol, port.Protocol, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return string.IsNullOrWhiteSpace(networkEvent.DestinationIp) || string.Equals(networkEvent.DestinationIp, port.LocalAddress, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPrivateOrVirtualAddress(string localAddress)
    {
        return localAddress.StartsWith("10.", StringComparison.Ordinal) ||
            localAddress.StartsWith("172.", StringComparison.Ordinal) ||
            localAddress.StartsWith("192.168.", StringComparison.Ordinal);
    }

    private static bool IsAllAdaptersAddress(string localAddress)
    {
        return localAddress is "0.0.0.0" or "::" or "[::]";
    }

    private static bool IsLoopbackAddress(string localAddress)
    {
        return localAddress.StartsWith("127.", StringComparison.Ordinal) ||
            localAddress.Equals("::1", StringComparison.OrdinalIgnoreCase) ||
            localAddress.Equals("[::1]", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsHighRiskStatus(RiskStatus riskStatus)
    {
        return riskStatus is RiskStatus.HighRisk or RiskStatus.Critical;
    }

    private static string SuggestPortAction(ListeningPort port, NetworkEvent? latestPortEvent)
    {
        if (latestPortEvent?.EventType == "NewListeningPort" && IsHighRiskStatus(port.RiskStatus))
        {
            return "Treat this as new exposure: confirm the app, then watch or block it if you did not expect it.";
        }

        if (port.Application is null || port.Application.DisplayName == "Unknown application")
        {
            return "Run a fresh scan and confirm the owning process, executable path, publisher, and adapter before trusting it.";
        }

        if (port.Reachability == PortReachability.NetworkReachable)
        {
            return "Confirm this application is expected to accept connections, then trust or watch the app if it is normal for your workflow.";
        }

        return "No action needed if you recognize the app; watch it if the listener keeps reappearing unexpectedly.";
    }

    private static string BuildIncidentTarget(NetworkDevice? device, AppIdentity? application)
    {
        if (application is null)
        {
            return device is null ? "Target unavailable" : DisplayDeviceName(device);
        }

        var applicationName = FirstUseful(application.DisplayName, application.ProcessName, "Unknown application");
        return device is null
            ? applicationName
            : string.Concat(applicationName, " on ", DisplayDeviceName(device));
    }

    private static (string Key, string Description) BuildIncidentGrouping(Incident incident, string target)
    {
        var targetKind = incident.MainApplicationId is not null && incident.MainDeviceId is not null
            ? "app/device"
            : incident.MainApplicationId is not null
                ? "app"
                : incident.MainDeviceId is not null ? "device" : "event";
        var targetId = incident.MainApplicationId?.ToString(CultureInfo.InvariantCulture) ??
            incident.MainDeviceId?.ToString(CultureInfo.InvariantCulture) ??
            FirstUseful(target, "unknown target");
        var key = $"{targetKind}:{targetId}:{incident.RiskLevel}";
        return (key, $"Grouped by {targetKind}, target {target}, and {incident.RiskLevel} severity.");
    }

    private static string BuildIncidentSeverityExplanation(RiskLevel riskLevel, int eventCount)
    {
        var countText = eventCount <= 1
            ? "single event"
            : $"{eventCount} related events";
        return riskLevel switch
        {
            RiskLevel.Critical => $"Critical because {countText} may indicate active exposure or sensitive access that needs immediate review.",
            RiskLevel.High => $"High because {countText} involve sensitive access, remote reachability, or unknown ownership.",
            RiskLevel.Medium => $"Medium because {countText} deserve visibility while you confirm whether the activity is expected.",
            _ => $"Low because AccessWatch recorded {countText} for history without strong suspicious signals."
        };
    }

    private static string BuildIncidentTimeline(Incident incident)
    {
        return string.Join(
            Environment.NewLine,
            $"Started: {FormatTimestamp(incident.StartedUtc)}",
            $"Last updated: {FormatTimestamp(incident.LastUpdatedUtc)}",
            $"Events grouped: {incident.EventCount}",
            incident.ResolvedUtc is null ? "Resolved: not resolved" : $"Resolved: {FormatTimestamp(incident.ResolvedUtc.Value)}");
    }

    private static string BuildIncidentEvidence(string title, string summary, string target, (string Key, string Description) grouping, string? notes)
    {
        var noteText = string.IsNullOrWhiteSpace(notes) ? "No analyst notes yet." : notes.Trim();
        return string.Join(
            Environment.NewLine,
            $"Title: {title}",
            $"Target: {target}",
            $"Grouping: {grouping.Description}",
            $"Summary: {summary}",
            $"Notes: {noteText}");
    }

    private static string BuildIncidentRecommendedAction(RiskLevel riskLevel, IncidentStatus status, int eventCount)
    {
        if (status == IncidentStatus.Resolved)
        {
            return "Resolved: keep for history unless the same grouped activity returns.";
        }

        if (riskLevel >= RiskLevel.High)
        {
            return eventCount > 1
                ? "Escalate if unexpected; repeated high-risk activity should stay visible until confirmed."
                : "Escalate if unexpected, or Watch while confirming the app, device, and timing.";
        }

        return status == IncidentStatus.Watching
            ? "Watching: leave grouped so repeats stay visible without creating extra noise."
            : "Resolve if expected; Watch if it repeats or you are still unsure.";
    }

    private static string BuildIncidentExport(
        string title,
        Incident incident,
        string target,
        string grouping,
        string severityExplanation,
        string timeline,
        string evidence,
        string recommendedAction)
    {
        return string.Join(
            Environment.NewLine,
            "AccessWatch incident export",
            $"Incident: {title}",
            $"Target: {target}",
            $"Risk: {incident.RiskLevel}",
            $"Status: {incident.Status}",
            $"Grouping: {grouping}",
            $"Severity: {severityExplanation}",
            "Timeline:",
            timeline,
            "Evidence:",
            evidence,
            $"Recommended action: {recommendedAction}");
    }

    private static string BuildIncidentRuleWizard(DashboardIncidentItemViewModel incident, string ruleSuggestion)
    {
        var ruleState = string.IsNullOrWhiteSpace(ruleSuggestion)
            ? "No rule has been created yet. Use Create rule after you understand the pattern."
            : "Disabled rule suggestion created. Review it before enabling any automation.";
        return string.Join(
            Environment.NewLine,
            "Rule creation wizard",
            $"1. Scope: {incident.Grouping}",
            $"2. Match: {incident.GroupKey}",
            $"3. Action: {incident.RecommendedAction}",
            $"4. Safety: keep disabled until this pattern is known and expected.",
            ruleState);
    }
    private static IReadOnlyList<NetworkDevice> FilterUsableDevices(IReadOnlyList<NetworkDevice> devices)
    {
        List<NetworkDevice>? filteredDevices = null;
        for (var index = 0; index < devices.Count; index++)
        {
            var device = devices[index];
            if (DeviceAddressClassifier.IsUsableDeviceAddress(device.IpAddress, device.MacAddress))
            {
                filteredDevices?.Add(device);
                continue;
            }

            filteredDevices ??= CopyDevicePrefix(devices, index);
        }

        return filteredDevices ?? devices;
    }

    private static List<NetworkDevice> CopyDevicePrefix(IReadOnlyList<NetworkDevice> devices, int length)
    {
        var filteredDevices = new List<NetworkDevice>(devices.Count);
        for (var index = 0; index < length; index++)
        {
            filteredDevices.Add(devices[index]);
        }

        return filteredDevices;
    }

    private void UpdateSelectedDeviceAlias(string? alias)
    {
        var currentDevice = selectedDevice!;
        var updatedDevice = currentDevice with
        {
            Name = string.IsNullOrWhiteSpace(alias)
                ? FirstUseful(currentDevice.ResolvedName, $"Device at {currentDevice.IpAddress}")
                : alias,
            UserAlias = alias ?? string.Empty,
            NameSource = string.IsNullOrWhiteSpace(alias)
                ? (string.IsNullOrWhiteSpace(currentDevice.ResolvedName) ? "IP address fallback" : "Hostname")
                : "User alias"
        };
        Devices[Devices.IndexOf(currentDevice)] = updatedDevice;
        SelectedDevice = updatedDevice;
    }

    private void UpdateDeviceEnforcementPlan(TrustStatus decision, DashboardDeviceItemViewModel device)
    {
        if (decision != TrustStatus.Blocked)
        {
            ResetEnforcementPlan();
            return;
        }

        if (firewallEnforcementPlanner is null)
        {
            ShowEnforcementPlanningDisconnected();
            return;
        }

        var plan = firewallEnforcementPlanner.CreateBlockDevicePlan(new NetworkDevice
        {
            DeviceId = device.DeviceId,
            IpAddress = device.IpAddress,
            MacAddress = device.MacAddress == "MAC address unavailable" ? null : device.MacAddress,
            Hostname = device.ResolvedName,
            UserAlias = device.UserAlias
        });
        SetEnforcementPlan(plan);
    }

    private void UpdateApplicationEnforcementPlan(TrustStatus decision, DashboardApplicationItemViewModel application)
    {
        if (decision != TrustStatus.Blocked)
        {
            ResetEnforcementPlan();
            return;
        }

        if (firewallEnforcementPlanner is null)
        {
            ShowEnforcementPlanningDisconnected();
            return;
        }

        var plan = firewallEnforcementPlanner.CreateBlockApplicationPlan(new AppIdentity
        {
            ApplicationId = application.ApplicationId,
            DisplayName = application.Name,
            ProcessName = application.ProcessName,
            FilePath = application.ExecutablePath
        });
        SetEnforcementPlan(plan);
    }

    private void SetEnforcementPlan(FirewallEnforcementPlan plan)
    {
        enforcementPlanReview.SetPlan(plan);
        NotifyEnforcementPlanChanged();
    }

    private void ShowEnforcementPlanningDisconnected()
    {
        enforcementPlanReview.ShowPlanningDisconnected();
        NotifyEnforcementPlanChanged();
    }

    private void ResetEnforcementPlan()
    {
        enforcementPlanReview.Reset();
        NotifyEnforcementPlanChanged();
    }

    private void NotifyEnforcementPlanChanged()
    {
        OnPropertyChanged(nameof(SelectedEnforcementPlan));
        OnPropertyChanged(nameof(HasEnforcementPlan));
        OnPropertyChanged(nameof(CanApplyEnforcementPlan));
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
            TrustStatus.Guest => "Marked guest",
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

    private static string DeviceInventoryState(NetworkDevice device)
    {
        var now = DateTimeOffset.UtcNow;
        if (device.FirstSeenUtc != default && now - device.FirstSeenUtc <= TimeSpan.FromHours(24))
        {
            return "New device";
        }

        if (device.LastConfirmedUtc is null)
        {
            return "Unconfirmed";
        }

        return now - device.LastConfirmedUtc.Value > TimeSpan.FromDays(7)
            ? "Not seen lately"
            : "Recently confirmed";
    }

    private static string DeviceRecommendedAction(NetworkDevice device)
    {
        return device.TrustStatus switch
        {
            TrustStatus.Trusted => "No action needed unless the device identity changes.",
            TrustStatus.KnownWatched => "Keep watching for repeated or unexpected activity.",
            TrustStatus.Guest => "Keep guest access limited and review if it exposes services.",
            TrustStatus.Blocked => "Keep blocked; investigate if it reappears.",
            _ => "Click Trace device. If AccessWatch still cannot identify it, leave it watched or block it instead of naming it."
        };
    }

    private static string FormatOptionalTimestamp(DateTimeOffset? timestamp)
    {
        return timestamp is null ? "Not confirmed" : FormatTimestamp(timestamp.Value);
    }

    private static string BuildDeviceDetail(NetworkDevice device)
    {
        var deviceType = string.IsNullOrWhiteSpace(device.DeviceTypeGuess) ? null : device.DeviceTypeGuess;
        var notes = string.IsNullOrWhiteSpace(device.Notes) ? null : device.Notes;
        return (deviceType, notes) switch
        {
            (not null, not null) => string.Concat(deviceType, "; ", notes),
            (not null, null) => deviceType,
            (null, not null) => notes,
            _ => "No extra device details recorded yet."
        };
    }

    private static string DeviceTracePrompt(DashboardDeviceItemViewModel? device) => device is null
        ? "Select a device, then click Trace device to see where it came from and what to do next."
        : $"Click Trace device to review {device.Name}.";

    private static string BuildDeviceTrace(DashboardDeviceItemViewModel device)
    {
        return string.Join(Environment.NewLine,
        [
            $"Trace report: {device.Name}",
            $"Network address: {device.IpAddress}",
            $"Hardware ID: {device.MacAddress}",
            $"Maker: {device.Vendor}",
            $"Name source: {device.NameSource}",
            $"AccessWatch guess: {DeviceIdentityGuess(device)}",
            $"First seen: {device.FirstSeen}",
            $"Last seen: {device.LastSeen}",
            $"Last confirmed: {device.LastConfirmed}",
            $"Trust: {device.TrustStatus}",
            $"Risk: {device.RiskStatus}",
            $"Clues AccessWatch found: {device.Detail}",
            $"Next step: {device.RecommendedAction}"
        ]);
    }

    private static string DeviceIdentityGuess(DashboardDeviceItemViewModel device)
    {
        var evidence = string.Concat(device.Name, " ", device.Vendor, " ", device.Detail).ToLowerInvariant();
        if (HasDeviceHint(evidence, ["phone", "tablet", "android", "iphone", "ipad"]))
        {
            return "Likely phone or tablet.";
        }

        if (HasDeviceHint(evidence, ["router", "gateway"]) || device.IpAddress.EndsWith(".1", StringComparison.Ordinal))
        {
            return "Likely router or gateway.";
        }

        if (HasDeviceHint(evidence, ["windows", "workstation", "laptop", "desktop", "pc"]))
        {
            return "Likely PC or laptop.";
        }

        return "Unknown device; keep it watched until AccessWatch sees a clearer name or you recognize it.";
    }

    private static bool HasDeviceHint(string evidence, string[] hints) =>
        Array.Exists(hints, hint => evidence.Contains(hint, StringComparison.Ordinal));
    private static string FormatTimestamp(DateTimeOffset timestamp)
    {
        return timestamp == default
            ? "Not recorded"
            : timestamp.ToLocalTime().ToString("g", CultureInfo.CurrentCulture);
    }

    private static string BuildIncidentExplanation(DashboardIncidentItemViewModel incident)
    {
        var privacyFocus = IncidentPrivacyFocus(incident);
        var urgency = incident.RawRiskLevel >= RiskLevel.High
            ? "This deserves prompt review because the incident risk is high enough to interrupt normal workflow."
            : "This is worth watching, but it does not currently look severe enough for immediate blocking.";
        var status = incident.RawStatus == IncidentStatus.Resolved
            ? "It is marked resolved, so keep it as history unless it repeats."
            : "It is still active for review or monitoring.";
        var verify = incident.MainTarget == "Target unavailable"
            ? "Verify which app or device was involved before trusting or blocking anything."
            : $"Verify that {incident.MainTarget} was expected at the recorded time.";
        return $"Protection focus: {privacyFocus} Why: {urgency} {status} Verify: {verify} Recommended action: use Watch for expected but noisy behavior, Resolve when confirmed, or Escalate if this was unexpected.";
    }

    private static string IncidentPrivacyFocus(DashboardIncidentItemViewModel incident)
    {
        var evidence = string.Concat(incident.Title, " ", incident.Summary).ToLowerInvariant();
        if (evidence.Contains("camera", StringComparison.Ordinal))
        {
            return "Camera use was detected. Outside sources usually reach the camera through a local app, browser permission, remote session, or malware.";
        }

        if (evidence.Contains("microphone", StringComparison.Ordinal))
        {
            return "Microphone use was detected. Outside sources usually reach the microphone through a local app, browser permission, remote session, or malware.";
        }

        if (evidence.Contains("network port", StringComparison.Ordinal) || evidence.Contains("listening", StringComparison.Ordinal) || evidence.Contains("remote", StringComparison.Ordinal))
        {
            return "A possible outside connection path was detected. Other devices may be able to try reaching this PC.";
        }

        if (evidence.Contains("new device", StringComparison.Ordinal))
        {
            return "A new network device was detected. Keep it watched until you recognize it.";
        }

        return "AccessWatch grouped this because it may affect privacy, remote access, or network exposure.";
    }

    private static AiInvestigationRequest BuildAiInvestigationRequest(DashboardIncidentItemViewModel incident, string redactedIncident)
    {
        return new AiInvestigationRequest(
            "AccessWatch",
            "Incident",
            incident.Title,
            incident.RiskLevel,
            incident.Status,
            redactedIncident,
            "Explain the likely cause, identify missing evidence, recommend Resolve/Watch/Escalate/Create rule, and keep sensitive data local.");
    }

    private static string BuildBridgeReview(DashboardIncidentItemViewModel incident, AiInvestigationResult result)
    {
        return string.Join(
            Environment.NewLine + Environment.NewLine,
            "AccessWatch support bridge review",
            $"Incident: {incident.Title}",
            $"Provider: {result.Provider}",
            $"Status: {(result.Succeeded ? "Completed" : "Unavailable")}",
            $"Confidence: {result.Confidence}",
            "Summary:",
            result.Summary,
            "Recommended action:",
            result.RecommendedAction);
    }

    private static string BuildChatGptReviewBrief(DashboardIncidentItemViewModel incident, string redactedIncident)
    {
        var recommendation = BuildReviewRecommendation(incident);
        return string.Join(
            Environment.NewLine + Environment.NewLine,
            "AccessWatch AI review workspace",
            $"Incident: {incident.Title}",
            $"Target: {incident.MainTarget}",
            $"Risk: {incident.RiskLevel}; Status: {incident.Status}; Events: {incident.EventCount}",
            $"Recommended AccessWatch action: {recommendation.Action}",
            $"Why: {recommendation.Reason}",
            "Evidence checklist:",
            BuildEvidenceChecklist(incident),
            "Action shortcuts in AccessWatch:",
            "Use Resolve when confirmed expected, Watch when expected but noisy, Escalate when unexpected or sensitive, and Create rule after you know the pattern is safe to automate.",
            "ChatGPT prompt:",
            "Explain the likely cause, identify evidence that would confirm whether this is expected or suspicious, recommend Resolve/Watch/Escalate/Create rule, and call out any sensitive data that should stay local.",
            "Redacted incident context:",
            redactedIncident);
    }

    private static (string Action, string Reason) BuildReviewRecommendation(DashboardIncidentItemViewModel incident)
    {
        if (incident.RawStatus == IncidentStatus.Resolved)
        {
            return ("Resolve", "The incident is already resolved; keep it as history unless it repeats.");
        }

        return incident.RawRiskLevel switch
        {
            >= RiskLevel.Critical => ("Escalate", "Critical incidents should be treated as unexpected until you confirm the app, device, and timing."),
            RiskLevel.High => ("Escalate", "High-risk activity deserves prompt review, especially for reachable ports or sensitive device access."),
            RiskLevel.Medium => ("Watch", "Medium-risk activity is worth monitoring while you confirm whether the target was expected."),
            _ => ("Resolve or Watch", "Low-risk activity can usually be resolved once expected, or watched if it keeps repeating.")
        };
    }

    private static string BuildEvidenceChecklist(DashboardIncidentItemViewModel incident)
    {
        var targetCheck = incident.MainTarget == "Target unavailable"
            ? "- Identify the app or device involved before trusting or blocking anything."
            : $"- Confirm {incident.MainTarget} was expected at the recorded time.";
        return string.Join(
            Environment.NewLine,
            targetCheck,
            "- Check whether the publisher, signature, and path match what you recognize.",
            "- Confirm whether this was triggered by your own activity or a scheduled service.",
            "- If this repeats, decide whether a disabled rule suggestion should become an enabled rule.");
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
        var protection = ClassifyProtectionActivity(networkEvent, details, applicationName);

        return new DashboardActivityItemViewModel(
            networkEvent.RiskLevel.ToString(),
            applicationName,
            protection.Summary,
            $"{protection.Detail} Evidence: {sourceDevice}{whatHappened}{endpoint}{reachability}",
            BuildApplicationIdentity(application, details.ProcessName),
            FirstUseful(protection.WhyItMatters, details.WhyItMatters, DefaultWhyItMatters(networkEvent.RiskLevel)),
            FirstUseful(protection.SuggestedAction, details.SuggestedAction, DefaultSuggestedAction(networkEvent.RiskLevel)));
    }

    private static ProtectionActivity ClassifyProtectionActivity(NetworkEvent networkEvent, EventDetails details, string applicationName)
    {
        return networkEvent.EventType switch
        {
            "CameraActivated" => new ProtectionActivity(
                "Camera access detected.",
                $"{applicationName} is using the camera. Outside sources usually reach the camera through a local app, browser permission, remote session, or malware.",
                "Camera access can expose the room around you.",
                "If you did not start this, close the app and watch or block it in AccessWatch."),
            "MicrophoneActivated" => new ProtectionActivity(
                "Microphone access detected.",
                $"{applicationName} is using the microphone. Outside sources usually reach the microphone through a local app, browser permission, remote session, or malware.",
                "Microphone access can expose nearby conversations.",
                "If you did not start this, close the app and watch or block it in AccessWatch."),
            "NewListeningPort" or "ListeningPortApplicationChanged" => new ProtectionActivity(
                "Possible outside connection path detected.",
                $"Other devices may be able to connect to {applicationName} on this PC.",
                "Open network services can let other devices try to reach this PC.",
                "If you do not recognize this app or port, watch it or block it."),
            "NewDeviceObserved" => new ProtectionActivity(
                "New network device detected.",
                "A device appeared on your network.",
                "Unknown devices can be harmless, but they should stay visible until recognized.",
                "Trace the device before trusting or naming it."),
            _ => new ProtectionActivity(
                FirstUseful(networkEvent.Summary, FriendlyEventType(networkEvent.EventType)),
                "AccessWatch recorded activity that may affect your privacy or network exposure.",
                details.WhyItMatters,
                details.SuggestedAction)
        };
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

        var resolvedProcessName = FirstUseful(application.ProcessName, processName, string.Empty);
        var processPart = string.IsNullOrWhiteSpace(resolvedProcessName)
            ? string.Empty
            : $"Process {resolvedProcessName}";
        string publisherPart;
        if (!string.IsNullOrWhiteSpace(application.Publisher))
        {
            var publisherPrefix = application.SignatureStatus is SignatureStatus.TrustedSigned or SignatureStatus.SignedUnknown
                ? "Signed by"
                : "Publisher";
            publisherPart = $"{publisherPrefix} {application.Publisher}";
        }
        else
        {
            publisherPart = SignatureLabel(application.SignatureStatus);
        }

        var pathPart = string.IsNullOrWhiteSpace(application.FilePath)
            ? "Executable path unavailable"
            : application.FilePath;
        return string.IsNullOrWhiteSpace(processPart)
            ? string.Concat(publisherPart, "; ", pathPart)
            : string.Concat(processPart, "; ", publisherPart, "; ", pathPart);
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

    private static string FirstUseful(params ReadOnlySpan<string?> values)
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

    private sealed record ProtectionActivity(string Summary, string Detail, string? WhyItMatters, string? SuggestedAction);

    private sealed record EventDetails(
        string? WhatHappened = null,
        string? App = null,
        string? ProcessName = null,
        string? DeviceName = null,
        string? Reachability = null,
        string? WhyItMatters = null,
        string? SuggestedAction = null);
}
