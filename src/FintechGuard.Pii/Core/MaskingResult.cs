namespace FintechGuard.Pii.Core;

/// <summary>
/// Detailed record of a single piece of PII detected and masked during processing.
/// </summary>
public record PiiDetection
{
    public required PiiType Type { get; init; }
    public required string RecognizerName { get; init; }
    public required double Confidence { get; init; }
    public string? JsonPath { get; init; }
    public string? FullJsonPath { get; init; }
}

/// <summary>
/// The output of an audited masking operation, containing the safe string and detailed telemetry.
/// </summary>
public record MaskingResult
{
    /// <summary>
    /// The final safe JSON or text string with all PII masked.
    /// </summary>
    public required string Output { get; init; }

    /// <summary>
    /// Collection of all specific PII fields detected and masked.
    /// </summary>
    public required IReadOnlyList<PiiDetection> Detections { get; init; }

    /// <summary>
    /// True if any PII was detected and masked.
    /// </summary>
    public required bool HasPii { get; init; }

    /// <summary>
    /// Elapsed processing duration in milliseconds.
    /// </summary>
    public double DurationMs { get; init; }

    /// <summary>
    /// The number of distinct PII elements masked.
    /// </summary>
    public int PiiFieldCount => Detections.Count;
}
