using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AccessWatch.Core;

namespace AccessWatch.Detection;

/// <summary>
/// Resolves application identity from Windows process and file metadata.
/// </summary>
public sealed class AppIdentityResolver : IAppIdentityResolver
{
    /// <inheritdoc />
    public ApplicationIdentity Resolve(int processId)
    {
        var now = DateTimeOffset.UtcNow;

        try
        {
            using var process = Process.GetProcessById(processId);
            var processName = Safe(() => process.ProcessName) ?? $"pid-{processId}";
            var filePath = Safe(() => process.MainModule?.FileName);
            var versionInfo = filePath is null ? null : Safe(() => FileVersionInfo.GetVersionInfo(filePath));
            var signature = ResolveSignature(filePath);
            var hash = filePath is null ? null : Safe(() => ComputeSha256(filePath));

            return new ApplicationIdentity
            {
                DisplayName = ChooseDisplayName(processName, versionInfo),
                ProcessName = processName,
                FilePath = filePath,
                Publisher = signature.publisher,
                ProductName = EmptyToNull(versionInfo?.ProductName),
                FileDescription = EmptyToNull(versionInfo?.FileDescription),
                SignatureStatus = signature.status,
                HashSha256 = hash,
                InstallFolder = filePath is null ? null : Path.GetDirectoryName(filePath),
                ParentProcessName = null,
                FirstSeenUtc = now,
                LastSeenUtc = now,
                TrustStatus = TrustStatus.Unknown
            };
        }
        catch
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
    }

    /// <summary>
    /// Creates a friendly display name from process and version metadata.
    /// </summary>
    /// <param name="processName">The process name.</param>
    /// <param name="versionInfo">Optional file version metadata.</param>
    /// <returns>A display name suitable for user-facing alerts.</returns>
    public string ChooseDisplayName(string processName, FileVersionInfo? versionInfo)
    {
        return EmptyToNull(versionInfo?.ProductName)
            ?? EmptyToNull(versionInfo?.FileDescription)
            ?? processName;
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
