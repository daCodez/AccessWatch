using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AccessWatch.Core;

namespace AccessWatch.Detection;

/// <summary>
/// Resolves application identity from Windows process and file metadata.
/// </summary>
public sealed class AppIdentityResolver : IAppIdentityResolver
{
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
            DisplayName = ChooseDisplayName(process.ProcessName, file.ProductName, file.FileDescription),
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
        return EmptyToNull(productName)
            ?? EmptyToNull(fileDescription)
            ?? processName;
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
            return new ProcessMetadata(processName, filePath, null);
        }
        catch
        {
            return null;
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
}

/// <summary>
/// Windows executable file identity reader.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Thin Windows file and signature boundary; identity mapping is covered with deterministic reader fakes.")]
public sealed class WindowsFileIdentityReader : IFileIdentityReader
{
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
