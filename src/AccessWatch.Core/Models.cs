namespace AccessWatch.Core;

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
/// Represents AccessWatch behavior settings.
/// </summary>
public sealed record AccessWatchSettings
{
    /// <summary>Protection mode that controls notification action in the MVP.</summary>
    public ProtectionMode ProtectionMode { get; init; } = ProtectionMode.Balanced;

    /// <summary>AI assistance mode.</summary>
    public AiMode AiMode { get; init; } = AiMode.ManualChatGptCopy;
}
