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
    /// Scans a text fragment with contextual hints (like JSON property name) to optimize detection.
    /// </summary>
    IEnumerable<PiiMatch> Recognize(string text, RecognitionContext context) => Recognize(text);
}

/// <summary>
/// High-throughput zero-allocation recognizer contract allowing fast feature gating and writing directly
/// into a pooled <see cref="List{PiiMatch}"/>.
/// </summary>
public interface IFastPiiRecognizer : IPiiRecognizer
{
    bool MightMatch(in TextFeatures features);
    void RecognizeInto(string text, in RecognitionContext context, in TextFeatures features, List<PiiMatch> destination);
}

/// <summary>
/// Provides context about where a string came from to help contextual and ML recognizers optimize processing.
/// </summary>
public record RecognitionContext
{
    public string? PropertyName { get; init; }
    public string? FullJsonPath { get; init; }
    public string? ContentType { get; init; }
}
