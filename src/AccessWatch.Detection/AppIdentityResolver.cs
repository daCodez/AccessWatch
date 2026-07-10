using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AccessWatch.Core;

namespace AccessWatch.Detection;

/// <summary>
/// Resolves application identity from Windows process and file metadata.
/// </summary>
public sealed class AppIdentityResolver : IAppIdentityResolver
{
    private static readonly IReadOnlyDictionary<string, string> KnownApplicationNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["code"] = "Visual Studio Code",
        ["devenv"] = "Visual Studio",
        ["ms-teams"] = "Microsoft Teams",
        ["skype"] = "Skype",
        ["skypeapp"] = "Skype",
        ["teams"] = "Microsoft Teams"
    };

    private readonly IProcessMetadataReader processMetadataReader;
    private readonly IFileIdentityReader fileIdentityReader;

    /// <summary>
    /// Initializes a new resolver using Windows metadata readers.
    /// </summary>
    public AppIdentityResolver()
        : this(new WindowsProcessMetadataReader(), new WindowsFileIdentityReader())
    {
    }

    /// <summary>
    /// Initializes a new resolver using supplied metadata readers.
    /// </summary>
    /// <param name="processMetadataReader">Process metadata reader.</param>
    /// <param name="fileIdentityReader">File identity reader.</param>
    public AppIdentityResolver(IProcessMetadataReader processMetadataReader, IFileIdentityReader fileIdentityReader)
    {
        this.processMetadataReader = processMetadataReader;
        this.fileIdentityReader = fileIdentityReader;
    }

    /// <inheritdoc />
    public ApplicationIdentity Resolve(int processId)
    {
        var now = DateTimeOffset.UtcNow;
        var process = processMetadataReader.Read(processId);
        if (process is null)
        {
            return new ApplicationIdentity
            {
                DisplayName = $"Unknown process {processId}",
                ProcessName = $"pid-{processId}",
                SignatureStatus = SignatureStatus.Unknown,
                FirstSeenUtc = now,
                LastSeenUtc = now,
                TrustStatus = TrustStatus.Unknown
            };
        }

        var file = process.FilePath is null ? FileIdentityMetadata.Unknown : fileIdentityReader.Read(process.FilePath);
        return new ApplicationIdentity
        {
            DisplayName = ChooseDisplayName(process.ProcessName, file.ProductName, file.FileDescription, process.FilePath, file.Publisher, file.SignatureStatus),
            ProcessName = process.ProcessName,
            FilePath = process.FilePath,
            Publisher = file.Publisher,
            ProductName = file.ProductName,
            FileDescription = file.FileDescription,
            SignatureStatus = file.SignatureStatus,
            HashSha256 = file.HashSha256,
            InstallFolder = process.FilePath is null ? null : Path.GetDirectoryName(process.FilePath),
            ParentProcessName = process.ParentProcessName,
            FirstSeenUtc = now,
            LastSeenUtc = now,
            TrustStatus = TrustStatus.Unknown
        };
    }

    /// <summary>
    /// Creates a friendly display name from process and version metadata.
    /// </summary>
    /// <param name="processName">The process name.</param>
    /// <param name="productName">Product name from file metadata.</param>
    /// <param name="fileDescription">File description from file metadata.</param>
    /// <returns>A display name suitable for user-facing alerts.</returns>
    public string ChooseDisplayName(string processName, string? productName, string? fileDescription)
    {
        return ChooseDisplayName(processName, productName, fileDescription, null, null, SignatureStatus.Unknown);
    }

    /// <summary>
    /// Creates a friendly display name from process, version, path, publisher, and signature metadata.
    /// </summary>
    /// <param name="processName">The process name.</param>
    /// <param name="productName">Product name from file metadata.</param>
    /// <param name="fileDescription">File description from file metadata.</param>
    /// <param name="filePath">Executable path when available.</param>
    /// <param name="publisher">Publisher or signing subject when available.</param>
    /// <param name="signatureStatus">Digital signature status.</param>
    /// <returns>A display name suitable for user-facing alerts.</returns>
    public string ChooseDisplayName(
        string processName,
        string? productName,
        string? fileDescription,
        string? filePath,
        string? publisher,
        SignatureStatus signatureStatus)
    {
        return EmptyToNull(productName)
            ?? EmptyToNull(fileDescription)
            ?? KnownApplicationName(processName)
            ?? BuildContextualFallback(processName, filePath, publisher, signatureStatus);
    }

    private static string? KnownApplicationName(string processName)
    {
        return KnownApplicationNames.TryGetValue(processName.Trim(), out var friendlyName) ? friendlyName : null;
    }

    private static string BuildContextualFallback(string processName, string? filePath, string? publisher, SignatureStatus signatureStatus)
    {
        var trustedPublisher = EmptyToNull(publisher);
        if (EmptyToNull(filePath) is { } path)
        {
            var context = trustedPublisher ?? SignatureLabel(signatureStatus);
            return $"{processName.Trim()} ({context}, {path})";
        }

        return $"{processName.Trim()} (identity limited; executable path unavailable)";
    }

    private static string SignatureLabel(SignatureStatus signatureStatus)
    {
        return signatureStatus switch
        {
            SignatureStatus.TrustedSigned => "trusted signed",
            SignatureStatus.SignedUnknown => "signed, trust unknown",
            SignatureStatus.Unsigned => "unsigned",
            SignatureStatus.InvalidSignature => "invalid signature",
            SignatureStatus.Unknown => "signature unknown",
            _ => "signature unknown"
        };
    }

    [ExcludeFromCodeCoverage]
    private readonly record struct FileIdentityFingerprint(DateTime LastWriteUtc, long Length);

    [ExcludeFromCodeCoverage]
    private sealed record FileIdentityCacheEntry(DateTime LastWriteUtc, long Length, FileIdentityMetadata Metadata)
    {
        public bool Matches(FileIdentityFingerprint fingerprint)
        {
            return LastWriteUtc == fingerprint.LastWriteUtc && Length == fingerprint.Length;
        }
    }

    private static string? EmptyToNull(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }
}

/// <summary>
/// Represents safe process metadata used for application identity mapping.
/// </summary>
/// <param name="ProcessName">Process executable name.</param>
/// <param name="FilePath">Full executable path when available.</param>
/// <param name="ParentProcessName">Parent process name when available.</param>
public sealed record ProcessMetadata(string ProcessName, string? FilePath, string? ParentProcessName);

/// <summary>
/// Represents file metadata used for application identity mapping.
/// </summary>
/// <param name="ProductName">Product name from version metadata.</param>
/// <param name="FileDescription">File description from version metadata.</param>
/// <param name="Publisher">Publisher or signing subject.</param>
/// <param name="SignatureStatus">Digital signature status.</param>
/// <param name="HashSha256">SHA256 hash when available.</param>
public sealed record FileIdentityMetadata(
    string? ProductName,
    string? FileDescription,
    string? Publisher,
    SignatureStatus SignatureStatus,
    string? HashSha256)
{
    /// <summary>Unknown file identity metadata.</summary>
    public static FileIdentityMetadata Unknown { get; } = new(null, null, null, SignatureStatus.Unknown, null);
}

/// <summary>
/// Reads process metadata for app identity resolution.
/// </summary>
public interface IProcessMetadataReader
{
    /// <summary>
    /// Reads safe metadata for a process.
    /// </summary>
    /// <param name="processId">Process identifier.</param>
    /// <returns>Process metadata, or null when inaccessible.</returns>
    ProcessMetadata? Read(int processId);
}

/// <summary>
/// Reads executable file identity metadata.
/// </summary>
public interface IFileIdentityReader
{
    /// <summary>
    /// Reads metadata for an executable file.
    /// </summary>
    /// <param name="filePath">Executable path.</param>
    /// <returns>File identity metadata.</returns>
    FileIdentityMetadata Read(string filePath);
}

/// <summary>
/// Windows process metadata reader.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Thin Windows process boundary; AppIdentityResolver mapping is covered with deterministic reader fakes.")]
public sealed class WindowsProcessMetadataReader : IProcessMetadataReader
{
    /// <inheritdoc />
    public ProcessMetadata? Read(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            var processName = Safe(() => process.ProcessName) ?? $"pid-{processId}";
            var filePath = Safe(() => process.MainModule?.FileName);
            var parentProcessName = ResolveParentProcessName(processId);
            return new ProcessMetadata(processName, filePath, parentProcessName);
        }
        catch
        {
            return null;
        }
    }

    private static string? ResolveParentProcessName(int processId)
    {
        var parentProcessId = FindParentProcessId(processId);
        if (parentProcessId is null)
        {
            return null;
        }

        return Safe(() =>
        {
            using var parent = Process.GetProcessById(parentProcessId.Value);
            return parent.ProcessName;
        });
    }

    private static int? FindParentProcessId(int processId)
    {
        if (processId < 0)
        {
            return null;
        }

        // Use a live process snapshot so the MVP does not depend on Windows Event Logs for identity context.
        var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == InvalidHandleValue)
        {
            return null;
        }

        try
        {
            var entry = new ProcessEntry32
            {
                Size = (uint)Marshal.SizeOf<ProcessEntry32>()
            };

            if (!Process32First(snapshot, ref entry))
            {
                return null;
            }

            do
            {
                if (entry.ProcessId == processId)
                {
                    return entry.ParentProcessId == 0 ? null : (int)entry.ParentProcessId;
                }
            }
            while (Process32Next(snapshot, ref entry));

            return null;
        }
        finally
        {
            _ = CloseHandle(snapshot);
        }
    }

    private static T? Safe<T>(Func<T> action)
    {
        try
        {
            return action();
        }
        catch
        {
            return default;
        }
    }

    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    private static readonly nint InvalidHandleValue = new(-1);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Process32First(nint snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Process32Next(nint snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint handle);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint UsageCount;
        public uint ProcessId;
        public nint DefaultHeapId;
        public uint ModuleId;
        public uint ThreadCount;
        public uint ParentProcessId;
        public int PriClassBase;
        public uint Flags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExeFile;
    }
}

/// <summary>
/// Windows executable file identity reader.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Thin Windows file and signature boundary; identity mapping is covered with deterministic reader fakes.")]
public sealed class WindowsFileIdentityReader : IFileIdentityReader
{
    private readonly ConcurrentDictionary<string, FileIdentityCacheEntry> cache = new(StringComparer.OrdinalIgnoreCase);
    /// <inheritdoc />
    public FileIdentityMetadata Read(string filePath)
    {
        var versionInfo = Safe(() => FileVersionInfo.GetVersionInfo(filePath));
        var signature = ResolveSignature(filePath);
        var hash = Safe(() => ComputeSha256(filePath));
        return new FileIdentityMetadata(
            EmptyToNull(versionInfo?.ProductName),
            EmptyToNull(versionInfo?.FileDescription),
            signature.publisher,
            signature.status,
            hash);
    }

    private static FileIdentityFingerprint? ReadFingerprint(string filePath)
    {
        return Safe(() =>
        {
            var info = new FileInfo(filePath);
            return info.Exists ? new FileIdentityFingerprint(info.LastWriteTimeUtc, info.Length) : (FileIdentityFingerprint?)null;
        });
    }
    private static (SignatureStatus status, string? publisher) ResolveSignature(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return (SignatureStatus.Unknown, null);
        }

        try
        {
#pragma warning disable SYSLIB0057
            // The MVP needs the signer embedded in a Windows PE file; .NET has not exposed a direct replacement for this API.
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
#pragma warning restore SYSLIB0057
            using var chain = new X509Chain();
            var isTrusted = chain.Build(certificate);
            return (isTrusted ? SignatureStatus.TrustedSigned : SignatureStatus.SignedUnknown, certificate.GetNameInfo(X509NameType.SimpleName, false));
        }
        catch (CryptographicException)
        {
            return (SignatureStatus.Unsigned, null);
        }
        catch
        {
            return (SignatureStatus.Unknown, null);
        }
    }

    private static string ComputeSha256(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash);
    }

    [ExcludeFromCodeCoverage]
    private readonly record struct FileIdentityFingerprint(DateTime LastWriteUtc, long Length);

    [ExcludeFromCodeCoverage]
    private sealed record FileIdentityCacheEntry(DateTime LastWriteUtc, long Length, FileIdentityMetadata Metadata)
    {
        public bool Matches(FileIdentityFingerprint fingerprint)
        {
            return LastWriteUtc == fingerprint.LastWriteUtc && Length == fingerprint.Length;
        }
    }

    private static string? EmptyToNull(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    private static T? Safe<T>(Func<T> action)
    {
        try
        {
            return action();
        }
        catch
        {
            return default;
        }
    }
}
