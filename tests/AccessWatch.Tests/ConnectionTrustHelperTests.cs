using AccessWatch.Core;
using AccessWatch.Detection;
using ApplicationIdentity = AccessWatch.Core.ApplicationIdentity;

namespace AccessWatch.Tests;

/// <summary>
/// Tests local connection trust confidence behavior.
/// </summary>
public sealed class ConnectionTrustHelperTests
{
    /// <summary>
    /// Verifies trusted applications receive high confidence.
    /// </summary>
    [Fact]
    public void Estimate_ReturnsHighConfidenceForTrustedApp()
    {
        var helper = new ConnectionTrustHelper();

        var confidence = helper.Estimate(new ApplicationIdentity { TrustStatus = TrustStatus.Trusted });

        Assert.Equal(0.95, confidence.Score);
        Assert.Contains("explicitly trusted", confidence.Reason);
    }

    /// <summary>
    /// Verifies trusted signed publishers receive elevated confidence.
    /// </summary>
    [Fact]
    public void Estimate_ReturnsElevatedConfidenceForSignedPublisher()
    {
        var helper = new ConnectionTrustHelper();

        var confidence = helper.Estimate(new ApplicationIdentity { SignatureStatus = SignatureStatus.TrustedSigned, Publisher = "Vendor" });

        Assert.Equal(0.75, confidence.Score);
    }

    /// <summary>
    /// Verifies unsigned applications receive low confidence.
    /// </summary>
    [Fact]
    public void Estimate_ReturnsLowConfidenceForUnsignedApp()
    {
        var helper = new ConnectionTrustHelper();

        var confidence = helper.Estimate(new ApplicationIdentity { SignatureStatus = SignatureStatus.Unsigned });

        Assert.Equal(0.25, confidence.Score);
    }

    /// <summary>
    /// Verifies unknown applications receive neutral confidence.
    /// </summary>
    [Fact]
    public void Estimate_ReturnsNeutralConfidenceForUnknownApp()
    {
        var helper = new ConnectionTrustHelper();

        var confidence = helper.Estimate(new ApplicationIdentity());

        Assert.Equal(0.5, confidence.Score);
    }
}
