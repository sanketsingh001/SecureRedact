namespace FintechGuard.Pii.Core;

/// <summary>
/// Represents a detected PII match in a value or text fragment.
/// </summary>
public record PiiMatch
{
    public required string RawValue { get; init; }
    public required PiiType Type { get; init; }
    public string TypeName { get; init; } = string.Empty;
    public double Confidence { get; init; } = 1.0;
    public int Index { get; init; }
    public int Length { get; init; }
    public string? NormalizedValue { get; init; }
    public Dictionary<string, string>? Metadata { get; init; }
}
