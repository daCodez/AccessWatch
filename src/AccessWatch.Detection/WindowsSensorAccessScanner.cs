using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;
using AccessWatch.Core;
using Microsoft.Win32;

namespace AccessWatch.Detection;

/// <summary>
/// Reads Windows privacy telemetry for active camera and microphone usage.
/// </summary>
public sealed class WindowsSensorAccessScanner : ISensorAccessScanner
{
    private readonly ISensorPrivacyStoreReader privacyStoreReader;

    /// <summary>
    /// Initializes a scanner backed by the current user's Windows privacy store.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public WindowsSensorAccessScanner()
        : this(new RegistrySensorPrivacyStoreReader())
    {
    }

    internal WindowsSensorAccessScanner(ISensorPrivacyStoreReader privacyStoreReader)
    {
        this.privacyStoreReader = privacyStoreReader;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<SensorAccessObservation>> ScanAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var observations = new List<SensorAccessObservation>();
        AddActiveObservations(observations, "webcam", "Camera", "CameraActivated");
        AddActiveObservations(observations, "microphone", "Microphone", "MicrophoneActivated");

        return Task.FromResult<IReadOnlyList<SensorAccessObservation>>(
            observations
                .OrderBy(static observation => observation.EventType, StringComparer.Ordinal)
                .ThenBy(static observation => observation.ApplicationKey, StringComparer.OrdinalIgnoreCase)
                .ToArray());
    }

    private void AddActiveObservations(List<SensorAccessObservation> observations, string capability, string sensorName, string eventType)
    {
        foreach (var record in privacyStoreReader.Read(capability))
        {
            if (!IsActive(record))
            {
                continue;
            }

            var application = DescribeApplication(record.ApplicationKey);
            observations.Add(new SensorAccessObservation
            {
                EventType = eventType,
                SensorName = sensorName,
                ApplicationKey = record.ApplicationKey,
                DisplayName = application.DisplayName,
                ProcessName = application.ProcessName,
                FilePath = application.FilePath,
                StartedUtc = ConvertWindowsFileTime(record.LastUsedTimeStart)
            });
        }
    }

    internal static bool IsActive(SensorPrivacyRecord record)
    {
        return record.LastUsedTimeStart > 0 && (record.LastUsedTimeStop <= 0 || record.LastUsedTimeStop < record.LastUsedTimeStart);
    }

    internal static SensorApplicationDescription DescribeApplication(string applicationKey)
    {
        var filePath = NormalizeNonPackagedPath(applicationKey);
        if (!string.IsNullOrWhiteSpace(filePath))
        {
            var processName = Path.GetFileNameWithoutExtension(filePath);
            if (!string.IsNullOrWhiteSpace(processName))
            {
                return new SensorApplicationDescription(processName, processName, filePath);
            }
        }

        var displayName = applicationKey.Replace('#', ' ').Replace('_', ' ').Trim();
        if (string.IsNullOrWhiteSpace(displayName))
        {
            displayName = "Unknown application";
        }

        return new SensorApplicationDescription(displayName, displayName, null);
    }

    private static string? NormalizeNonPackagedPath(string applicationKey)
    {
        var candidate = applicationKey.Replace('#', Path.DirectorySeparatorChar);
        return candidate.Length >= 3 && char.IsLetter(candidate[0]) && candidate[1] == ':' && IsDirectorySeparator(candidate[2])
            ? candidate
            : null;
    }

    private static bool IsDirectorySeparator(char value)
    {
        return value is '\\' or '/';
    }

    private static DateTimeOffset ConvertWindowsFileTime(long value)
    {
        try
        {
            return DateTimeOffset.FromFileTime(value);
        }
        catch (ArgumentOutOfRangeException)
        {
            return DateTimeOffset.UtcNow;
        }
    }
}

internal sealed record SensorPrivacyRecord(string ApplicationKey, long LastUsedTimeStart, long LastUsedTimeStop);

internal sealed record SensorApplicationDescription(string DisplayName, string ProcessName, string? FilePath);

internal interface ISensorPrivacyStoreReader
{
    IReadOnlyList<SensorPrivacyRecord> Read(string capability);
}

[SupportedOSPlatform("windows")]
[ExcludeFromCodeCoverage(Justification = "Thin Windows privacy store boundary; sensor mapping is covered with deterministic reader fakes.")]
internal sealed class RegistrySensorPrivacyStoreReader : ISensorPrivacyStoreReader
{
    private const string ConsentStorePath = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    public IReadOnlyList<SensorPrivacyRecord> Read(string capability)
    {
        using var capabilityKey = Registry.CurrentUser.OpenSubKey($@"{ConsentStorePath}\{capability}");
        if (capabilityKey is null)
        {
            return [];
        }

        var records = new List<SensorPrivacyRecord>();
        ReadChildRecords(capabilityKey, records);
        using var nonPackagedKey = capabilityKey.OpenSubKey("NonPackaged");
        if (nonPackagedKey is not null)
        {
            ReadChildRecords(nonPackagedKey, records);
        }

        return records;
    }

    private static void ReadChildRecords(RegistryKey parentKey, List<SensorPrivacyRecord> records)
    {
        foreach (var childName in parentKey.GetSubKeyNames())
        {
            using var childKey = parentKey.OpenSubKey(childName);
            if (childKey is null)
            {
                continue;
            }

            var start = ReadInt64(childKey.GetValue("LastUsedTimeStart"));
            var stop = ReadInt64(childKey.GetValue("LastUsedTimeStop"));
            if (start != 0 || stop != 0)
            {
                records.Add(new SensorPrivacyRecord(childName, start, stop));
            }
        }
    }

    private static long ReadInt64(object? value)
    {
        return value switch
        {
            long longValue => longValue,
            int intValue => intValue,
            string stringValue when long.TryParse(stringValue, out var parsed) => parsed,
            _ => 0L
        };
    }
}


