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
    string InventoryState,
    string FirstSeen,
    string LastSeen,
    string LastConfirmed,
    string RecommendedAction,
    string Detail)
{
    /// <summary>
    /// Gets the plain-English detail text for this device row.
    /// </summary>
    public string DetailText => $"Device: {Name} | State: {InventoryState} | IP: {IpAddress} | MAC: {MacAddress} | Vendor: {Vendor} | Trust: {TrustStatus} | Risk: {RiskStatus} | First seen: {FirstSeen} | Last seen: {LastSeen} | Last confirmed: {LastConfirmed} | Next: {RecommendedAction} | Details: {Detail}";
}

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
    string ExecutablePath,
    string Detail)
{
    /// <summary>
    /// Gets the plain-English detail text for this application row.
    /// </summary>
    public string DetailText => $"Application: {Name} | Process: {ProcessName} | Publisher: {Publisher} | Signature: {SignatureStatus} | Trust: {TrustStatus} | Identity: {Detail}";
}

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
    string Detail,
    int PortNumber,
    string LocalAddress,
    string Meaning,
    string Exposure,
    string NetworkAdapter,
    string NetworkZone,
    string ReachabilityTest,
    string HistoryStatus,
    string ExposureChange,
    string AppConfidence,
    string SuggestedAction,
    string Investigation)
{
    /// <summary>
    /// Gets the plain-English detail text for this listening port row.
    /// </summary>
    public string DetailText => $"Port: {Endpoint} | Meaning: {Meaning} | Exposure: {Exposure} | Adapter: {NetworkAdapter} | Zone: {NetworkZone} | Reachability test: {ReachabilityTest} | History: {HistoryStatus} | Exposure change: {ExposureChange} | App confidence: {AppConfidence} | Application: {ApplicationName} | Risk: {RiskStatus} | Trust: {TrustStatus} | First seen: {FirstSeen} | Last seen: {LastSeen} | Identity: {Detail} | Next: {SuggestedAction}";
}

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
    string Summary,
    string GroupKey = "Ungrouped",
    string Grouping = "Grouped by incident target.",
    string SeverityExplanation = "Severity explanation unavailable.",
    string Timeline = "Timeline unavailable.",
    string Evidence = "Evidence unavailable.",
    string RecommendedAction = "Review this incident.",
    string UserNotes = "",
    string ExportText = "Export unavailable.")
{
    /// <summary>
    /// Gets the plain-English detail text for this incident row.
    /// </summary>
    public string DetailText => $"Incident: {Title} | Group: {Grouping} | Target: {MainTarget} | Risk: {RiskLevel} | Severity: {SeverityExplanation} | Status: {Status} | Events: {EventCount} | Timeline: {Timeline} | Evidence: {Evidence} | Notes: {UserNotes} | Summary: {Summary} | Next: {RecommendedAction}";
}

/// <summary>
/// Represents a stored rule shown in the dashboard.
/// </summary>
public sealed record DashboardRuleItemViewModel(
    long RuleId,
    string Name,
    string Enabled,
    bool IsEnabled,
    string Action,
    string RiskLevel,
    string Scope,
    string Conditions,
    string Preview,
    string Duration,
    string QuietHours,
    string NetworkProfile,
    string ChangeDetection,
    string AiSummary,
    string Description,
    string ConditionJson,
    string Created,
    string Updated)
{
    /// <summary>
    /// Gets the plain-English detail text for this rule row.
    /// </summary>
    public string DetailText => $"Rule: {Name} | State: {Enabled} | Action: {Action} | Risk: {RiskLevel} | Scope: {Scope} | Conditions: {Conditions} | Duration: {Duration} | Quiet hours: {QuietHours} | Network profile: {NetworkProfile} | Change detection: {ChangeDetection} | Summary: {AiSummary} | Description: {Description}";
}
/// <summary>
/// Represents a dashboard settings choice.
/// </summary>
public sealed record DashboardSettingsOptionViewModel(string Value, string Name, string Summary);
