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
}
