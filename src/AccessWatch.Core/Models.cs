namespace AccessWatch.Core;

/// <summary>
/// Represents a device observed on the local network.
/// </summary>
public sealed record NetworkDevice
{
    /// <summary>Stable device identifier in the AccessWatch database.</summary>
    public long DeviceId { get; init; }

    /// <summary>Observed IP address.</summary>
    public string IpAddress { get; init; } = string.Empty;

    /// <summary>Observed MAC address when available.</summary>
    public string? MacAddress { get; init; }

    /// <summary>Resolved hostname when available.</summary>
    public string? Hostname { get; init; }

    /// <summary>User-friendly name assigned from the dashboard.</summary>
    public string? UserAlias { get; init; }

    /// <summary>MAC vendor when available.</summary>
    public string? Vendor { get; init; }

    /// <summary>Best-effort device type guess.</summary>
    public string? DeviceTypeGuess { get; init; }

    /// <summary>First observation time.</summary>
    public DateTimeOffset FirstSeenUtc { get; init; }

    /// <summary>Most recent observation time.</summary>
    public DateTimeOffset LastSeenUtc { get; init; }

    /// <summary>Most recent confirmation time.</summary>
    public DateTimeOffset? LastConfirmedUtc { get; init; }

    /// <summary>User or system trust status.</summary>
    public TrustStatus TrustStatus { get; init; } = TrustStatus.Unknown;

    /// <summary>Current risk status.</summary>
    public RiskStatus RiskStatus { get; init; } = RiskStatus.Normal;

    /// <summary>Operator notes.</summary>
    public string? Notes { get; init; }
}
/// <summary>
/// Represents an application observed by AccessWatch.
/// </summary>
public sealed record ApplicationIdentity
{
    /// <summary>Stable application identifier in the AccessWatch database.</summary>
    public long ApplicationId { get; init; }

    /// <summary>User-friendly display name.</summary>
    public string DisplayName { get; init; } = "Unknown application";

    /// <summary>Process executable name.</summary>
    public string ProcessName { get; init; } = "unknown";

    /// <summary>Full executable path when accessible.</summary>
    public string? FilePath { get; init; }

    /// <summary>Publisher or signing subject when known.</summary>
    public string? Publisher { get; init; }

    /// <summary>Product name from file metadata.</summary>
    public string? ProductName { get; init; }

    /// <summary>File description from version metadata.</summary>
    public string? FileDescription { get; init; }

    /// <summary>Digital signature status.</summary>
    public SignatureStatus SignatureStatus { get; init; } = SignatureStatus.Unknown;

    /// <summary>SHA256 hash of the executable file when readable.</summary>
    public string? HashSha256 { get; init; }

    /// <summary>Executable install folder.</summary>
    public string? InstallFolder { get; init; }

    /// <summary>Parent process name when available.</summary>
    public string? ParentProcessName { get; init; }

    /// <summary>First observation time.</summary>
    public DateTimeOffset FirstSeenUtc { get; init; }

    /// <summary>Most recent observation time.</summary>
    public DateTimeOffset LastSeenUtc { get; init; }

    /// <summary>User or system trust status.</summary>
    public TrustStatus TrustStatus { get; init; } = TrustStatus.Unknown;

    /// <summary>Operator notes.</summary>
    public string? Notes { get; init; }
}

/// <summary>
/// Represents a local listening TCP port.
/// </summary>
public sealed record ListeningPort
{
    /// <summary>Stable port row identifier in the AccessWatch database.</summary>
    public long PortId { get; init; }

    /// <summary>Local port number.</summary>
    public int PortNumber { get; init; }

    /// <summary>Network protocol.</summary>
    public string Protocol { get; init; } = "TCP";

    /// <summary>Local bind address.</summary>
    public string LocalAddress { get; init; } = "0.0.0.0";

    /// <summary>Whether the listener is network reachable.</summary>
    public PortReachability Reachability { get; init; } = PortReachability.Unknown;

    /// <summary>Owning process identifier when available.</summary>
    public int? OwningProcessId { get; init; }

    /// <summary>Resolved owning application.</summary>
    public ApplicationIdentity? Application { get; init; }

    /// <summary>First observation time.</summary>
    public DateTimeOffset FirstSeenUtc { get; init; }

    /// <summary>Most recent observation time.</summary>
    public DateTimeOffset LastSeenUtc { get; init; }

    /// <summary>User or system trust status.</summary>
    public TrustStatus TrustStatus { get; init; } = TrustStatus.Unknown;

    /// <summary>Current risk status.</summary>
    public RiskStatus RiskStatus { get; init; } = RiskStatus.Normal;
}

/// <summary>
/// Represents active access to a sensitive local sensor such as camera or microphone.
/// </summary>
public sealed record SensorAccessObservation
{
    /// <summary>Event type created when this access is observed.</summary>
    public string EventType { get; init; } = string.Empty;

    /// <summary>User-facing sensor name.</summary>
    public string SensorName { get; init; } = string.Empty;

    /// <summary>Stable application key from the operating system privacy store.</summary>
    public string ApplicationKey { get; init; } = string.Empty;

    /// <summary>User-friendly application display name.</summary>
    public string DisplayName { get; init; } = "Unknown application";

    /// <summary>Process executable name when known.</summary>
    public string ProcessName { get; init; } = "unknown";

    /// <summary>Full executable path when known.</summary>
    public string? FilePath { get; init; }

    /// <summary>When the current sensor access session began.</summary>
    public DateTimeOffset StartedUtc { get; init; }
}
/// <summary>
/// Represents an AccessWatch network event.
/// </summary>
public sealed record NetworkEvent
{
    /// <summary>Stable event identifier.</summary>
    public long EventId { get; init; }

    /// <summary>Event type, such as NewListeningPort.</summary>
    public string EventType { get; init; } = string.Empty;

    /// <summary>Source IP address when relevant.</summary>
    public string? SourceIp { get; init; }

    /// <summary>Source device identifier when known.</summary>
    public long? SourceDeviceId { get; init; }

    /// <summary>Destination IP address when relevant.</summary>
    public string? DestinationIp { get; init; }

    /// <summary>Destination port when relevant.</summary>
    public int? DestinationPort { get; init; }

    /// <summary>Network protocol.</summary>
    public string Protocol { get; init; } = "TCP";

    /// <summary>Traffic direction or observation direction.</summary>
    public string Direction { get; init; } = "Inbound";

    /// <summary>Related application identifier.</summary>
    public long? ApplicationId { get; init; }

    /// <summary>Event risk level.</summary>
    public RiskLevel RiskLevel { get; init; }

    /// <summary>Short user-facing summary.</summary>
    public string Summary { get; init; } = string.Empty;

    /// <summary>Structured details as JSON.</summary>
    public string DetailsJson { get; init; } = "{}";

    /// <summary>Whether the user was notified.</summary>
    public bool WasUserNotified { get; init; }

    /// <summary>Event creation time.</summary>
    public DateTimeOffset CreatedUtc { get; init; }
}

/// <summary>
/// Represents the risk result for a detected listening port.
/// </summary>
public sealed record PortRiskAssessment(
    RiskLevel RiskLevel,
    RiskStatus RiskStatus,
    NotificationAction Action,
    string Summary,
    string WhyItMatters,
    string SuggestedAction);

/// <summary>
/// Represents app connection trust confidence for MVP local logic.
/// </summary>
public sealed record TrustConfidence(double Score, string Reason);

/// <summary>
/// Represents a user or system trust decision for an observed target.
/// </summary>
public sealed record TrustDecision
{
    /// <summary>Stable trust decision identifier.</summary>
    public long TrustDecisionId { get; init; }

    /// <summary>Target kind, such as Application, Port, or Device.</summary>
    public string TargetType { get; init; } = string.Empty;

    /// <summary>Target row identifier.</summary>
    public long TargetId { get; init; }

    /// <summary>Trust decision to apply.</summary>
    public TrustStatus Decision { get; init; } = TrustStatus.Unknown;

    /// <summary>Optional expiration time.</summary>
    public DateTimeOffset? ExpiresUtc { get; init; }

    /// <summary>Reason shown in future UI.</summary>
    public string Reason { get; init; } = string.Empty;

    /// <summary>Decision creation time.</summary>
    public DateTimeOffset CreatedUtc { get; init; }
}

/// <summary>
/// Represents the stored result for one device observation during a scan.
/// </summary>
/// <param name="Device">The device observation that was persisted.</param>
/// <param name="DeviceId">The database device identifier.</param>
/// <param name="ActiveTrustStatus">The active trust decision applied to this device, when one exists.</param>
public sealed record DevicePersistenceResult(NetworkDevice Device, long DeviceId, TrustStatus? ActiveTrustStatus);

/// <summary>
/// Represents the stored result for one application observation during a scan.
/// </summary>
/// <param name="Application">The application observation that was persisted.</param>
/// <param name="ApplicationId">The database application identifier.</param>
/// <param name="ActiveTrustStatus">The active trust decision applied to this application, when one exists.</param>
public sealed record ApplicationPersistenceResult(ApplicationIdentity Application, long ApplicationId, TrustStatus? ActiveTrustStatus);

/// <summary>
/// Represents a listening port write requested by a scan.
/// </summary>
/// <param name="Port">The scored listening port observation.</param>
/// <param name="ApplicationId">The owning application identifier, when known.</param>
public sealed record PortPersistenceRequest(ListeningPort Port, long? ApplicationId);

/// <summary>
/// Represents the stored result for one listening port observation during a scan.
/// </summary>
/// <param name="Port">The listening port observation that was persisted.</param>
/// <param name="ApplicationId">The owning application identifier, when known.</param>
/// <param name="PreviousApplicationId">The previously stored application identifier, when known.</param>
/// <param name="IsNewPort">Whether this port identity was newly inserted.</param>
public sealed record PortPersistenceResult(ListeningPort Port, long? ApplicationId, long? PreviousApplicationId, bool IsNewPort);
/// <summary>
/// Represents AccessWatch behavior settings.
/// </summary>
public sealed record AccessWatchSettings
{
    /// <summary>Protection mode that controls notification action in the MVP.</summary>
    public ProtectionMode ProtectionMode { get; set; } = ProtectionMode.Balanced;

    /// <summary>AI assistance mode.</summary>
    public AiMode AiMode { get; set; } = AiMode.ManualChatGptCopy;

    /// <summary>Local support bridge endpoint for in-app AI review.</summary>
    public string SupportBridgeEndpoint { get; set; } = "http://127.0.0.1:7331/accesswatch/investigations";
}


/// <summary>
/// Represents an AI investigation request sent to an approved local bridge.
/// </summary>
public sealed record AiInvestigationRequest(
    string Source,
    string TargetType,
    string Title,
    string RiskLevel,
    string Status,
    string ContextJson,
    string Prompt);

/// <summary>
/// Represents an AI investigation result returned by an approved local bridge.
/// </summary>
public sealed record AiInvestigationResult(
    bool Succeeded,
    string Provider,
    string Summary,
    string RecommendedAction,
    string Confidence,
    string RawResponse)
{
    /// <summary>Creates an unavailable result with an operator-friendly reason.</summary>
    public static AiInvestigationResult Unavailable(string provider, string reason) =>
        new(false, provider, reason, "Check the bridge connection, then retry.", "Unavailable", string.Empty);
}

/// <summary>
/// Represents grouped related security events.
/// </summary>
public sealed record Incident
{
    /// <summary>Stable incident identifier.</summary>
    public long IncidentId { get; init; }

    /// <summary>User-facing incident title.</summary>
    public string Title { get; init; } = string.Empty;

    /// <summary>Incident summary.</summary>
    public string Summary { get; init; } = string.Empty;

    /// <summary>Main related device identifier.</summary>
    public long? MainDeviceId { get; init; }

    /// <summary>Main related application identifier.</summary>
    public long? MainApplicationId { get; init; }

    /// <summary>Incident risk level.</summary>
    public RiskLevel RiskLevel { get; init; }

    /// <summary>Incident lifecycle status.</summary>
    public IncidentStatus Status { get; init; } = IncidentStatus.Open;

    /// <summary>Number of related events.</summary>
    public int EventCount { get; init; }

    /// <summary>Incident start time.</summary>
    public DateTimeOffset StartedUtc { get; init; }

    /// <summary>Most recent incident update time.</summary>
    public DateTimeOffset LastUpdatedUtc { get; init; }

    /// <summary>Incident resolution time.</summary>
    public DateTimeOffset? ResolvedUtc { get; init; }

    /// <summary>User notes.</summary>
    public string? UserNotes { get; init; }
}

/// <summary>
/// Represents a stored AccessWatch rule.
/// </summary>
public sealed record AccessWatchRule
{
    /// <summary>Stable rule identifier.</summary>
    public long RuleId { get; init; }

    /// <summary>Rule name.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Rule description.</summary>
    public string Description { get; init; } = string.Empty;

    /// <summary>Structured rule condition JSON.</summary>
    public string ConditionJson { get; init; } = "{}";

    /// <summary>Risk level assigned when the rule matches.</summary>
    public RiskLevel RiskLevel { get; init; }

    /// <summary>Notification or future enforcement action.</summary>
    public NotificationAction Action { get; init; } = NotificationAction.SilentLog;

    /// <summary>Whether the rule is active.</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>Rule creation time.</summary>
    public DateTimeOffset CreatedUtc { get; init; }

    /// <summary>Rule update time.</summary>
    public DateTimeOffset UpdatedUtc { get; init; }
}
