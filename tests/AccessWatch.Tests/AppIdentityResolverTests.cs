using AccessWatch.Core;
using AccessWatch.Detection;

namespace AccessWatch.Tests;

/// <summary>
/// Tests Windows app identity resolution behavior.
/// </summary>
public sealed class AppIdentityResolverTests
{
    /// <summary>
    /// Verifies inaccessible process metadata produces a safe fallback identity.
    /// </summary>
    [Fact]
    public void Resolve_ReturnsSafeUnknownIdentity_WhenProcessCannotBeRead()
    {
        var resolver = new AppIdentityResolver(new FakeProcessReader(null), new FakeFileReader(FileIdentityMetadata.Unknown));

        var identity = resolver.Resolve(int.MaxValue);

        Assert.Equal("Unknown process 2147483647", identity.DisplayName);
        Assert.Equal("pid-2147483647", identity.ProcessName);
    }

    /// <summary>
    /// Verifies rich process and file metadata maps into a friendly application identity.
    /// </summary>
    [Fact]
    public void Resolve_MapsFileIdentityIntoApplicationIdentity()
    {
        var process = new ProcessMetadata("Update", "C:\\Apps\\Discord\\Update.exe", "explorer");
        var file = new FileIdentityMetadata("Discord", "Discord updater", "Discord Inc.", SignatureStatus.TrustedSigned, "ABC123");
        var resolver = new AppIdentityResolver(new FakeProcessReader(process), new FakeFileReader(file));

        var identity = resolver.Resolve(42);

        Assert.Equal("Discord", identity.DisplayName);
        Assert.Equal("Update", identity.ProcessName);
        Assert.Equal("C:\\Apps\\Discord\\Update.exe", identity.FilePath);
        Assert.Equal("Discord Inc.", identity.Publisher);
        Assert.Equal("Discord", identity.ProductName);
        Assert.Equal("Discord updater", identity.FileDescription);
        Assert.Equal(SignatureStatus.TrustedSigned, identity.SignatureStatus);
        Assert.Equal("ABC123", identity.HashSha256);
        Assert.Equal("C:\\Apps\\Discord", identity.InstallFolder);
        Assert.Equal("explorer", identity.ParentProcessName);
    }

    /// <summary>
    /// Verifies accessible processes without file paths still map safely.
    /// </summary>
    [Fact]
    public void Resolve_MapsProcessWithoutFilePath()
    {
        var process = new ProcessMetadata("System", null, null);
        var resolver = new AppIdentityResolver(new FakeProcessReader(process), new FakeFileReader(FileIdentityMetadata.Unknown));

        var identity = resolver.Resolve(4);

        Assert.Equal("System (identity limited; executable path unavailable)", identity.DisplayName);
        Assert.Null(identity.FilePath);
        Assert.Null(identity.InstallFolder);
        Assert.Equal(SignatureStatus.Unknown, identity.SignatureStatus);
    }

    /// <summary>
    /// Verifies missing friendly metadata falls back to path and signature context.
    /// </summary>
    [Fact]
    public void Resolve_AddsPathAndSignatureContext_WhenFriendlyMetadataIsMissing()
    {
        var process = new ProcessMetadata("tool", "C:\\Tools\\tool.exe", null);
        var file = new FileIdentityMetadata(null, null, null, SignatureStatus.Unsigned, "ABC123");
        var resolver = new AppIdentityResolver(new FakeProcessReader(process), new FakeFileReader(file));

        var identity = resolver.Resolve(88);

        Assert.Equal("tool (unsigned, C:\\Tools\\tool.exe)", identity.DisplayName);
    }

    /// <summary>
    /// Verifies publisher context is preferred over signature labels when friendly metadata is missing.
    /// </summary>
    [Fact]
    public void Resolve_AddsPublisherContext_WhenFriendlyMetadataIsMissing()
    {
        var process = new ProcessMetadata("agent", "C:\\Vendor\\agent.exe", null);
        var file = new FileIdentityMetadata(null, null, "Vendor LLC", SignatureStatus.TrustedSigned, "ABC123");
        var resolver = new AppIdentityResolver(new FakeProcessReader(process), new FakeFileReader(file));

        var identity = resolver.Resolve(89);

        Assert.Equal("agent (Vendor LLC, C:\\Vendor\\agent.exe)", identity.DisplayName);
    }

    /// <summary>
    /// Verifies signature labels provide context when publisher metadata is missing.
    /// </summary>
    /// <param name="signatureStatus">Signature status to label.</param>
    /// <param name="expectedLabel">Expected label in the display name.</param>
    [Theory]
    [InlineData(SignatureStatus.TrustedSigned, "trusted signed")]
    [InlineData(SignatureStatus.SignedUnknown, "signed, trust unknown")]
    [InlineData(SignatureStatus.InvalidSignature, "invalid signature")]
    [InlineData(SignatureStatus.Unknown, "signature unknown")]
    [InlineData((SignatureStatus)999, "signature unknown")]
    public void ChooseDisplayName_AddsSignatureContext_WhenPublisherIsMissing(SignatureStatus signatureStatus, string expectedLabel)
    {
        var resolver = new AppIdentityResolver(new FakeProcessReader(null), new FakeFileReader(FileIdentityMetadata.Unknown));

        var displayName = resolver.ChooseDisplayName("agent", null, null, "C:\\Tools\\agent.exe", null, signatureStatus);

        Assert.Equal($"agent ({expectedLabel}, C:\\Tools\\agent.exe)", displayName);
    }

    /// <summary>
    /// Verifies file description is used when product name is blank.
    /// </summary>
    [Fact]
    public void ChooseDisplayName_UsesFileDescriptionBeforeProcessName()
    {
        var resolver = new AppIdentityResolver(new FakeProcessReader(null), new FakeFileReader(FileIdentityMetadata.Unknown));

        var displayName = resolver.ChooseDisplayName("raw", " ", "Friendly app");

        Assert.Equal("Friendly app", displayName);
    }

    /// <summary>
    /// Verifies known application process names use friendly product names when file metadata is sparse.
    /// </summary>
    [Theory]
    [InlineData("devenv", "Visual Studio")]
    [InlineData("Skype", "Skype")]
    [InlineData("Teams", "Microsoft Teams")]
    public void ChooseDisplayName_UsesKnownApplicationName_WhenFriendlyMetadataIsMissing(string processName, string expectedName)
    {
        var resolver = new AppIdentityResolver(new FakeProcessReader(null), new FakeFileReader(FileIdentityMetadata.Unknown));

        var displayName = resolver.ChooseDisplayName(processName, null, null, null, null, SignatureStatus.Unknown);

        Assert.Equal(expectedName, displayName);
    }
    /// <summary>
    /// Verifies process name is the final display-name fallback.
    /// </summary>
    [Fact]
    public void ChooseDisplayName_UsesProcessNameWhenMetadataIsBlank()
    {
        var resolver = new AppIdentityResolver(new FakeProcessReader(null), new FakeFileReader(FileIdentityMetadata.Unknown));

        var displayName = resolver.ChooseDisplayName("raw", null, "");

        Assert.Equal("raw (identity limited; executable path unavailable)", displayName);
    }

    private sealed class FakeProcessReader : IProcessMetadataReader
    {
        private readonly ProcessMetadata? process;

        public FakeProcessReader(ProcessMetadata? process)
        {
            this.process = process;
        }

        public ProcessMetadata? Read(int processId)
        {
            return process;
        }
    }

    private sealed class FakeFileReader : IFileIdentityReader
    {
        private readonly FileIdentityMetadata file;

        public FakeFileReader(FileIdentityMetadata file)
        {
            this.file = file;
        }

        public FileIdentityMetadata Read(string filePath)
        {
            return file;
        }
    }
}

