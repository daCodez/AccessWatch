using System.Runtime.Versioning;
using AccessWatch.Detection;

namespace AccessWatch.Tests;

/// <summary>
/// Tests Windows camera and microphone privacy telemetry mapping.
/// </summary>
public sealed class WindowsSensorAccessScannerTests
{
    /// <summary>
    /// Verifies the default scanner can be constructed on Windows.
    /// </summary>
    [SupportedOSPlatform("windows")]
    [Fact]
    public void Constructor_WithDefaultPrivacyStore_CreatesScanner()
    {
        var scanner = new WindowsSensorAccessScanner();

        Assert.NotNull(scanner);
    }

    /// <summary>
    /// Verifies unusual application keys fall back to readable names.
    /// </summary>
    /// <param name="applicationKey">Windows privacy store application key.</param>
    /// <param name="expectedDisplayName">Expected display name.</param>
    [Theory]
    [InlineData("C", "C")]
    [InlineData("C:#", "C:")]
    [InlineData("1:#Odd#Odd.exe", "1: Odd Odd.exe")]
    [InlineData("C-#Odd#Odd.exe", "C- Odd Odd.exe")]
    [InlineData("C:Odd.exe", "C:Odd.exe")]
    public void DescribeApplication_WithNonPathKey_ReturnsReadableFallback(string applicationKey, string expectedDisplayName)
    {
        var application = WindowsSensorAccessScanner.DescribeApplication(applicationKey);

        Assert.Equal(expectedDisplayName, application.DisplayName);
        Assert.Equal(expectedDisplayName, application.ProcessName);
        Assert.Null(application.FilePath);
    }

    /// <summary>
    /// Verifies slash-separated executable paths are recognized too.
    /// </summary>
    [Fact]
    public void DescribeApplication_WithSlashPath_ReturnsExecutableName()
    {
        var application = WindowsSensorAccessScanner.DescribeApplication("C:/Tools/SlashApp.exe");

        Assert.Equal("SlashApp", application.DisplayName);
        Assert.Equal("SlashApp", application.ProcessName);
        Assert.Equal("C:/Tools/SlashApp.exe", application.FilePath);
    }

    private static readonly DateTimeOffset StartedUtc = new(2026, 7, 5, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// Verifies active camera and microphone privacy records become user-facing observations.
    /// </summary>
    [Fact]
    public async Task ScanAsync_ReturnsActiveCameraAndMicrophoneObservations()
    {
        var reader = new FakeSensorPrivacyStoreReader(
            [new SensorPrivacyRecord(@"C:#Program Files#VideoApp#VideoApp.exe", StartedUtc.ToFileTime(), 0)],
            [new SensorPrivacyRecord("ContosoCommunicationSuite", StartedUtc.ToFileTime(), StartedUtc.AddMinutes(-1).ToFileTime())]);
        var scanner = new WindowsSensorAccessScanner(reader);

        var observations = await scanner.ScanAsync(CancellationToken.None);

        Assert.Collection(
            observations,
            camera =>
            {
                Assert.Equal("CameraActivated", camera.EventType);
                Assert.Equal("Camera", camera.SensorName);
                Assert.Equal("VideoApp", camera.DisplayName);
                Assert.Equal("VideoApp", camera.ProcessName);
                Assert.Equal(@"C:\Program Files\VideoApp\VideoApp.exe", camera.FilePath);
                Assert.Equal(StartedUtc, camera.StartedUtc);
            },
            microphone =>
            {
                Assert.Equal("MicrophoneActivated", microphone.EventType);
                Assert.Equal("Microphone", microphone.SensorName);
                Assert.Equal("ContosoCommunicationSuite", microphone.DisplayName);
                Assert.Equal("ContosoCommunicationSuite", microphone.ProcessName);
                Assert.Null(microphone.FilePath);
                Assert.Equal(StartedUtc, microphone.StartedUtc);
            });
    }

    /// <summary>
    /// Verifies stopped privacy records are ignored.
    /// </summary>
    [Fact]
    public async Task ScanAsync_SkipsInactiveSensorRecords()
    {
        var reader = new FakeSensorPrivacyStoreReader(
            [new SensorPrivacyRecord(@"C:#Camera#Camera.exe", StartedUtc.ToFileTime(), StartedUtc.AddMinutes(1).ToFileTime())],
            [new SensorPrivacyRecord("MutedApp", 0, 0)]);
        var scanner = new WindowsSensorAccessScanner(reader);

        var observations = await scanner.ScanAsync(CancellationToken.None);

        Assert.Empty(observations);
    }

    /// <summary>
    /// Verifies cancelled scans stop before reading privacy telemetry.
    /// </summary>
    [Fact]
    public async Task ScanAsync_WhenCancelled_Throws()
    {
        using var source = new CancellationTokenSource();
        await source.CancelAsync();
        var scanner = new WindowsSensorAccessScanner(new FakeSensorPrivacyStoreReader([], []));

        await Assert.ThrowsAsync<OperationCanceledException>(() => scanner.ScanAsync(source.Token));
    }

    /// <summary>
    /// Verifies application names are safe when Windows provides no usable key.
    /// </summary>
    [Fact]
    public void DescribeApplication_WithBlankKey_ReturnsUnknownApplication()
    {
        var application = WindowsSensorAccessScanner.DescribeApplication("   ");

        Assert.Equal("Unknown application", application.DisplayName);
        Assert.Equal("Unknown application", application.ProcessName);
        Assert.Null(application.FilePath);
    }

    /// <summary>
    /// Verifies malformed Windows timestamps do not break sensor scanning.
    /// </summary>
    [Fact]
    public async Task ScanAsync_WithInvalidWindowsTimestamp_UsesCurrentTimeFallback()
    {
        var before = DateTimeOffset.UtcNow.AddSeconds(-1);
        var reader = new FakeSensorPrivacyStoreReader([new SensorPrivacyRecord("BrokenTimeApp", long.MaxValue, 0)], []);
        var scanner = new WindowsSensorAccessScanner(reader);

        var observation = Assert.Single(await scanner.ScanAsync(CancellationToken.None));

        Assert.Equal("BrokenTimeApp", observation.DisplayName);
        Assert.InRange(observation.StartedUtc, before, DateTimeOffset.UtcNow.AddSeconds(1));
    }

    /// <summary>
    /// Verifies the active-session rules match Windows start and stop timestamps.
    /// </summary>
    /// <param name="start">Last start timestamp.</param>
    /// <param name="stop">Last stop timestamp.</param>
    /// <param name="expected">Expected active state.</param>
    [Theory]
    [InlineData(10, 0, true)]
    [InlineData(10, -1, true)]
    [InlineData(10, 5, true)]
    [InlineData(10, 10, false)]
    [InlineData(0, 0, false)]
    public void IsActive_ReturnsExpectedState(long start, long stop, bool expected)
    {
        Assert.Equal(expected, WindowsSensorAccessScanner.IsActive(new SensorPrivacyRecord("app", start, stop)));
    }

    private sealed class FakeSensorPrivacyStoreReader : ISensorPrivacyStoreReader
    {
        private readonly IReadOnlyList<SensorPrivacyRecord> webcamRecords;
        private readonly IReadOnlyList<SensorPrivacyRecord> microphoneRecords;

        public FakeSensorPrivacyStoreReader(IReadOnlyList<SensorPrivacyRecord> webcamRecords, IReadOnlyList<SensorPrivacyRecord> microphoneRecords)
        {
            this.webcamRecords = webcamRecords;
            this.microphoneRecords = microphoneRecords;
        }

        public IReadOnlyList<SensorPrivacyRecord> Read(string capability)
        {
            return capability == "webcam" ? webcamRecords : microphoneRecords;
        }
    }
}



