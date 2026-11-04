using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Defines a recognizer capable of identifying specific PII in raw text or field values.
/// </summary>
public interface IPiiRecognizer
{
    /// <summary>
    /// The unique name of the recognizer.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// The PII category/type this recognizer detects.
    /// </summary>
    PiiType PiiType { get; }

    /// <summary>
    /// Scans a text fragment and returns any detected PII matches.
    /// </summary>
    IEnumerable<PiiMatch> Recognize(string text);

    /// <summary>
    /// Scans a text fragment with contextual hints (like JSON property name) to optimize ML inference.
    /// </summary>
    IEnumerable<PiiMatch> Recognize(string text, RecognitionContext context) => Recognize(text);
}

/// <summary>
/// Provides context about where a string came from to help ML recognizers optimize their processing.
/// </summary>
public record RecognitionContext
{
    public string? PropertyName { get; init; }
    public string? ContentType { get; init; }
}
