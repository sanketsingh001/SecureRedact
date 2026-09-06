namespace FintechGuard.Pii.Core;

/// <summary>
/// Core contract for PII scanning, masking, and reversible unmasking.
/// </summary>
public interface IPiiEngine
{
    /// <summary>
    /// Scans a text fragment and returns detected PII matches.
    /// </summary>
    IReadOnlyList<PiiMatch> Scan(string text);

    /// <summary>
    /// Masks a single scalar value. If hintType is not provided, the value is scanned dynamically across all registered recognizers.
    /// </summary>
    string MaskValue(string value, PiiType? hintType = null);

    /// <summary>
    /// Unmasks a format-preserving or encrypted token back to its original value.
    /// </summary>
    string UnmaskValue(string maskedValue);

    /// <summary>
    /// Attempts to unmask a value. Returns false if the value is not a reversible token or cannot be decrypted.
    /// </summary>
    bool TryUnmaskValue(string maskedValue, out string? unmaskedValue);

    /// <summary>
    /// Scans an arbitrary, nested JSON string (regardless of key names) and masks detected PII according to default options.
    /// </summary>
    string MaskJson(string json);

    /// <summary>
    /// Scans a JSON string with fine-grained developer control over which PII types, keys, or strategies to apply.
    /// Ideal for preparing payloads before sending to a database or third-party service.
    /// </summary>
    string MaskJson(string json, JsonMaskingScope? scope);

    /// <summary>
    /// Scans a JSON string with fine-grained developer control configured via an inline lambda.
    /// </summary>
    string MaskJson(string json, Action<JsonMaskingScope> configureScope);

    /// <summary>
    /// Traverses a masked JSON string and restores all reversible tokens to their original plaintext values.
    /// </summary>
    string UnmaskJson(string maskedJson);

    /// <summary>
    /// High-throughput streaming scanner for large JSON payloads via Utf8JsonReader and Utf8JsonWriter.
    /// Operates with low memory allocation.
    /// </summary>
    void MaskJsonStream(Stream inputUtf8Json, Stream outputUtf8Json, JsonMaskingScope? scope = null);

    /// <summary>
    /// High-throughput streaming unmasker for large JSON payloads via Utf8JsonReader and Utf8JsonWriter.
    /// </summary>
    void UnmaskJsonStream(Stream inputUtf8Json, Stream outputUtf8Json);
}
