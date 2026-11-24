using System.Buffers;

namespace FintechGuard.Pii.Core;

/// <summary>
/// Core contract for PII scanning, masking, and reversible unmasking.
/// </summary>
public interface IPiiEngine : IDisposable
{
    /// <summary>
    /// Scans a text fragment and returns detected PII matches.
    /// </summary>
    IReadOnlyList<PiiMatch> Scan(string text, string? propertyName = null);

    /// <summary>
    /// Masks a single scalar value. If hintType is not provided, the value is scanned dynamically across all registered recognizers.
    /// </summary>
    string MaskValue(string value, PiiType? hintType = null);

    /// <summary>
    /// Masks a single scalar value with optional strategy and mask character overrides.
    /// </summary>
    string MaskValue(string value, PiiType? hintType, MaskingStrategy? strategyOverride, char? maskCharOverride = null)
        => MaskValue(value, hintType);

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
    /// </summary>
    string MaskJson(string json, JsonMaskingScope? scope);

    /// <summary>
    /// Scans a JSON string with fine-grained developer control configured via an inline lambda.
    /// </summary>
    string MaskJson(string json, Action<JsonMaskingScope> configureScope);

    /// <summary>
    /// Evaluates a JSON string and returns a detailed audit result containing the safe payload
    /// along with telemetry of exactly what PII fields were detected and masked.
    /// </summary>
    MaskingResult MaskJsonWithAudit(string json, JsonMaskingScope? scope = null);

    /// <summary>
    /// Traverses a masked JSON string and restores all reversible tokens to their original plaintext values.
    /// </summary>
    string UnmaskJson(string maskedJson);

    /// <summary>
    /// High-throughput streaming scanner for large JSON payloads via Utf8JsonReader and Utf8JsonWriter.
    /// </summary>
    void MaskJsonStream(Stream inputUtf8Json, Stream outputUtf8Json, JsonMaskingScope? scope = null);

    /// <summary>
    /// High-throughput streaming unmasker for large JSON payloads via Utf8JsonReader and Utf8JsonWriter.
    /// </summary>
    void UnmaskJsonStream(Stream inputUtf8Json, Stream outputUtf8Json);

    /// <summary>
    /// Zero-copy UTF-8 JSON masking directly from <see cref="ReadOnlySpan{Byte}"/> into an <see cref="IBufferWriter{Byte}"/>.
    /// </summary>
    void MaskJsonUtf8(ReadOnlySpan<byte> inputUtf8, IBufferWriter<byte> outputUtf8, JsonMaskingScope? scope = null);

    /// <summary>
    /// Zero-copy UTF-8 JSON unmasking directly from <see cref="ReadOnlySpan{Byte}"/> into an <see cref="IBufferWriter{Byte}"/>.
    /// </summary>
    void UnmaskJsonUtf8(ReadOnlySpan<byte> inputUtf8, IBufferWriter<byte> outputUtf8);

    /// <summary>
    /// Streams newline-delimited JSON (NDJSON / multijson) in constant O(line-size) memory.
    /// </summary>
    void MaskNdjsonStream(Stream inputUtf8Ndjson, Stream outputUtf8Ndjson, JsonMaskingScope? scope = null);

    /// <summary>
    /// Asynchronously masks a UTF-8 JSON stream without blocking thread-pool threads on stream I/O.
    /// </summary>
    Task MaskJsonStreamAsync(Stream inputUtf8Json, Stream outputUtf8Json, JsonMaskingScope? scope = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously masks a newline-delimited JSON (NDJSON / multijson) stream in constant O(line-size) memory.
    /// </summary>
    Task MaskNdjsonStreamAsync(Stream inputUtf8Ndjson, Stream outputUtf8Ndjson, JsonMaskingScope? scope = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously unmasks a UTF-8 JSON stream without blocking thread-pool threads on stream I/O.
    /// </summary>
    Task UnmaskJsonStreamAsync(Stream inputUtf8Json, Stream outputUtf8Json, CancellationToken cancellationToken = default);
}
