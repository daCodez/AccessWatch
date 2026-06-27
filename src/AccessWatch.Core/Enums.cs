namespace AccessWatch.Core;

/// <summary>
/// Describes whether AccessWatch should trust, watch, or block an observed target.
/// </summary>
public enum TrustStatus
{
    /// <summary>A target the user or system trusts.</summary>
    Trusted,
    /// <summary>A target that is familiar but should remain visible.</summary>
    KnownWatched,
    /// <summary>A guest device or application with limited trust.</summary>
    Guest,
    /// <summary>A target AccessWatch has not learned yet.</summary>
    Unknown,
    /// <summary>A target that should be blocked once blocking is implemented.</summary>
    Blocked
}

/// <summary>
/// Describes the current risk posture of an observed target.
/// </summary>
public enum RiskStatus
{
    /// <summary>No notable risk.</summary>
    Normal,
    /// <summary>Worth watching but not alarming.</summary>
    Watched,
    /// <summary>Unusual enough to deserve review.</summary>
    Suspicious,
    /// <summary>Likely enough to interrupt the user.</summary>
    HighRisk,
    /// <summary>Severe risk that may eventually justify automatic action.</summary>
    Critical
}

/// <summary>
/// Describes the severity of an event or incident.
/// </summary>
public enum RiskLevel
{
    /// <summary>Record only.</summary>
    Low,
    /// <summary>Friendly notification is acceptable.</summary>
    Medium,
    /// <summary>User should be asked before continuing once enforcement exists.</summary>
    High,
    /// <summary>Automatic blocking may be appropriate in lockdown mode.</summary>
    Critical
}

/// <summary>
/// Describes how AccessWatch should notify or act on a risk.
/// </summary>
public enum NotificationAction
{
    /// <summary>Save the event without interrupting the user.</summary>
    SilentLog,
    /// <summary>Show a low-noise informational notification.</summary>
    SoftNotify,
    /// <summary>Ask the user what to do before future enforcement.</summary>
    AskBeforeAllow,
    /// <summary>Prepare for automatic blocking; MVP does not block yet.</summary>
    AutoBlock
}

/// <summary>
/// Describes whether a listening port appears reachable from the network.
/// </summary>
public enum PortReachability
{
    /// <summary>The listener is bound to loopback only.</summary>
    LocalOnly,
    /// <summary>The listener is bound to an address that can be reached on the local network.</summary>
    NetworkReachable,
    /// <summary>The listener reachability could not be determined.</summary>
    Unknown
}

/// <summary>
/// Describes the digital signature status for an application file.
/// </summary>
public enum SignatureStatus
{
    /// <summary>The file has a trusted signature.</summary>
    TrustedSigned,
    /// <summary>The file is signed, but trust could not be fully verified.</summary>
    SignedUnknown,
    /// <summary>The file is not signed.</summary>
    Unsigned,
    /// <summary>The file has a signature that failed validation.</summary>
    InvalidSignature,
    /// <summary>Signature status could not be determined.</summary>
    Unknown
}

/// <summary>
/// Describes how assertive AccessWatch should be.
/// </summary>
public enum ProtectionMode
{
    /// <summary>Minimize interruptions.</summary>
    Quiet,
    /// <summary>Balanced low-noise default.</summary>
    Balanced,
    /// <summary>Notify more often about uncertain activity.</summary>
    Strict,
    /// <summary>Prepare for strongest enforcement once safe blocking exists.</summary>
    Lockdown
}

/// <summary>
/// Describes the AI assistance mode.
/// </summary>
public enum AiMode
{
    /// <summary>No AI assistance.</summary>
    Off,
    /// <summary>Manual copy and paste into ChatGPT.</summary>
    ManualChatGptCopy,
    /// <summary>Future local model support.</summary>
    LocalAi,
    /// <summary>Future OpenAI API support.</summary>
    OpenAiApi
}
