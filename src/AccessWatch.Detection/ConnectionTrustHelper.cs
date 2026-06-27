using AccessWatch.Core;

namespace AccessWatch.Detection;

/// <summary>
/// Provides simple local trust confidence checks for observed connections.
/// </summary>
public sealed class ConnectionTrustHelper
{
    /// <summary>
    /// Estimates local trust confidence from app identity metadata.
    /// </summary>
    /// <param name="application">The application identity to score.</param>
    /// <returns>A local trust confidence score and reason.</returns>
    public TrustConfidence Estimate(ApplicationIdentity application)
    {
        if (application.TrustStatus == TrustStatus.Trusted)
        {
            return new TrustConfidence(0.95, "Application is explicitly trusted.");
        }

        if (application.SignatureStatus == SignatureStatus.TrustedSigned && !string.IsNullOrWhiteSpace(application.Publisher))
        {
            return new TrustConfidence(0.75, "Application is signed by a trusted publisher.");
        }

        if (application.SignatureStatus == SignatureStatus.Unsigned)
        {
            return new TrustConfidence(0.25, "Application is unsigned.");
        }

        return new TrustConfidence(0.5, "AccessWatch has limited local history for this application.");
    }
}
