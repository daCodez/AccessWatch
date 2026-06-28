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

        Assert.Equal("System", identity.DisplayName);
        Assert.Null(identity.FilePath);
        Assert.Null(identity.InstallFolder);
        Assert.Equal(SignatureStatus.Unknown, identity.SignatureStatus);
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
    /// Verifies process name is the final display-name fallback.
    /// </summary>
    [Fact]
    public void ChooseDisplayName_UsesProcessNameWhenMetadataIsBlank()
    {
        var resolver = new AppIdentityResolver(new FakeProcessReader(null), new FakeFileReader(FileIdentityMetadata.Unknown));

        var displayName = resolver.ChooseDisplayName("raw", null, "");

        Assert.Equal("raw", displayName);
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
