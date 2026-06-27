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
        var resolver = new AppIdentityResolver();

        var identity = resolver.Resolve(int.MaxValue);

        Assert.Equal("Unknown process 2147483647", identity.DisplayName);
        Assert.Equal("pid-2147483647", identity.ProcessName);
    }
}
