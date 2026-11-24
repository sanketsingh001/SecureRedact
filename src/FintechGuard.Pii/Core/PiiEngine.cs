using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using FintechGuard.Pii.Context;
using FintechGuard.Pii.Crypto;
using FintechGuard.Pii.Diagnostics;
using FintechGuard.Pii.Masking;
using FintechGuard.Pii.Recognizers;

namespace FintechGuard.Pii.Core;

public sealed partial class PiiEngine : IPiiEngine, IDisposable
{
    private static readonly byte[] RedactedFallbackBytes =
        Encoding.UTF8.GetBytes(@"{""error"":""[REDACTED_DUE_TO_PROCESSING_ERROR]""}");

    private readonly PiiEngineOptions _options;
    private readonly IPiiRecognizer[] _recognizers;
    private readonly IReversibleCrypto? _crypto;
    private readonly byte[]? _hashKey;
    private readonly SemaphoreSlim? _concurrencyGate;
    private readonly TimeSpan _acquireTimeout;
    private volatile bool _disposed;

    [GeneratedRegex(@"(?:XXXX[ -]XXXX[ -]\d{4}|\d{4}[ -][^\s\d]{4}[ -][^\s\d]{4}[ -]\d{4}|[^\s,;:""'()<>\[\]=]+)#fp\[([a-zA-Z0-9_\-]+)\]", RegexOptions.Compiled, matchTimeoutMilliseconds: 100)]
    private static partial Regex FormatPreservingPattern();

    [GeneratedRegex(@"ENC\{([a-zA-Z0-9_]+):([a-zA-Z0-9_\-]+)\}", RegexOptions.Compiled, matchTimeoutMilliseconds: 100)]
    private static partial Regex ExplicitEncPattern();

    private struct JsonFrame
    {
        public bool IsArray;
        public string? PropertyName;
        public int ArrayIndex;
    }

    public PiiEngine(PiiEngineOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _recognizers = options.Recognizers.ToArray();
        _crypto = options.CryptoProvider;

        if (options.MaxConcurrentOperations > 0)
        {
            _concurrencyGate = new SemaphoreSlim(options.MaxConcurrentOperations, options.MaxConcurrentOperations);
            _acquireTimeout = options.ConcurrencyAcquireTimeout;
        }

        if (options.HashKey is { Length: > 0 })
        {
            _hashKey = (byte[])options.HashKey.Clone();
        }
        else if (_crypto is AesGcmReversibleCrypto aesCrypto)
        {
            _hashKey = aesCrypto.DerivedHashKey.ToArray();
        }
    }

    /// <summary>
    /// Creates a production-ready PII engine with default Indian &amp; global fintech recognizers in a single call.
    /// Uses AES-256-GCM FormatPreservingReversible tokenization when <paramref name="masterKey"/> is provided,
    /// or safe OneWayRedaction when omitted.
    /// </summary>
    public static IPiiEngine CreateDefault(
        string? masterKey = null,
        int maxCpuPercent = 0,
        PiiErrorBehavior errorBehavior = PiiErrorBehavior.Redact)
    {
        var builder = PiiEngineBuilder.Create()
            .AddDefaultRecognizers()
            .WithErrorBehavior(errorBehavior);

        if (!string.IsNullOrWhiteSpace(masterKey))
        {
            builder.WithMasterKey(masterKey)
                .SetDefaultStrategy(MaskingStrategy.FormatPreservingReversible);
        }
        else
        {
            builder.SetDefaultStrategy(MaskingStrategy.OneWayRedaction);
        }

        if (maxCpuPercent > 0)
            builder.WithMaxCpuUsage(maxCpuPercent);

        return builder.Build();
    }

    /// <summary>
    /// Creates a production PII engine configured with a KMS/Vault key ring for zero-downtime key rotation.
    /// </summary>
    public static IPiiEngine CreateWithKeyRing(
        string activeKeyId,
        IReadOnlyDictionary<string, byte[]> keyRing,
        int maxCpuPercent = 0,
        PiiErrorBehavior errorBehavior = PiiErrorBehavior.Redact)
    {
        var builder = PiiEngineBuilder.Create()
            .WithKeyRing(activeKeyId, keyRing)
            .AddDefaultRecognizers()
            .SetDefaultStrategy(MaskingStrategy.FormatPreservingReversible)
            .WithErrorBehavior(errorBehavior);

        if (maxCpuPercent > 0)
            builder.WithMaxCpuUsage(maxCpuPercent);

        return builder.Build();
    }

    /// <summary>
    /// Creates a zero-key, one-way redaction PII engine (masks sensitive fields permanently without an encryption key).
    /// </summary>
    public static IPiiEngine CreateOneWay(
        int maxCpuPercent = 0,
        PiiErrorBehavior errorBehavior = PiiErrorBehavior.Redact)
        => CreateDefault(masterKey: null, maxCpuPercent: maxCpuPercent, errorBehavior: errorBehavior);

    public IReadOnlyList<PiiMatch> Scan(string text, string? propertyName = null)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Array.Empty<PiiMatch>();

        bool acquired = false;
        try
        {
            acquired = TryAcquireConcurrencySlot();
            var matches = new List<PiiMatch>(4);
            var features = TextFeatures.Analyze(text.AsSpan());
            ScanInto(text, propertyName, fullJsonPath: null, in features, matches);
            SortMatchesInPlace(matches);
            return matches;
        }
        catch (TimeoutException ex)
        {
            PiiMetrics.ProcessingErrors.Add(1, new KeyValuePair<string, object?>("error_type", ex.GetType().Name));
            throw new PiiProcessingException("Timed out waiting for a PII engine CPU concurrency slot.", ex);
        }
        finally
        {
            if (acquired) _concurrencyGate!.Release();
        }
    }

    private void ScanInto(
        string text,
        string? propertyName,
        string? fullJsonPath,
        in TextFeatures features,
        List<PiiMatch> destination)
    {
        RecognitionContext? lazyContext = null;

        for (int i = 0; i < _recognizers.Length; i++)
        {
            var recognizer = _recognizers[i];
            if (recognizer is IFastPiiRecognizer fast)
            {
                if (!fast.MightMatch(in features))
                    continue;

                RecognitionContext ctx = lazyContext ??= new RecognitionContext
                {
                    PropertyName = propertyName,
                    FullJsonPath = fullJsonPath,
                    ContentType = "json"
                };
                fast.RecognizeInto(text, in ctx, in features, destination);
            }
            else
            {
                lazyContext ??= new RecognitionContext
                {
                    PropertyName = propertyName,
                    FullJsonPath = fullJsonPath,
                    ContentType = "json"
                };
                var detected = recognizer.Recognize(text, lazyContext);
                if (detected is ICollection<PiiMatch> col)
                {
                    if (col.Count > 0) destination.AddRange(col);
                }
                else
                {
                    foreach (var m in detected)
                        destination.Add(m);
                }
            }
        }
    }

    public string MaskValue(string value, PiiType? hintType = null)
    {
        return MaskValue(value, hintType, scope: null, strategyOverride: null, maskCharOverride: null);
    }

    public string MaskValue(string value, PiiType? hintType, MaskingStrategy? strategyOverride, char? maskCharOverride = null)
    {
        return MaskValue(value, hintType, scope: null, strategyOverride: strategyOverride, maskCharOverride: maskCharOverride);
    }

    public string MaskValue(string value, PiiType? hintType, JsonMaskingScope? scope)
    {
        return MaskValue(value, hintType, scope, scope?.StrategyOverride, maskCharOverride: null);
    }

    internal string MaskValue(
        string value,
        PiiType? hintType,
        JsonMaskingScope? scope,
        MaskingStrategy? strategyOverride,
        char? maskCharOverride)
    {
        if (string.IsNullOrEmpty(value))
            return value;

        MaskingStrategy? effectiveStrategy = strategyOverride ?? scope?.StrategyOverride;

        if (!hintType.HasValue && string.IsNullOrWhiteSpace(value))
            return value;

        bool acquired = false;
        try
        {
            acquired = TryAcquireConcurrencySlot();

            if (hintType.HasValue)
            {
                if (scope?.ExcludeTypes != null && scope.ExcludeTypes.Contains(hintType.Value))
                    return value;

                if (scope?.IncludeTypes != null && !scope.IncludeTypes.Contains(hintType.Value))
                    return value;

                return ApplyMask(value, hintType.Value, effectiveStrategy, maskCharOverride);
            }

            var matches = new List<PiiMatch>(4);
            var filtered = new List<PiiMatch>(4);
            var features = TextFeatures.Analyze(value.AsSpan());
            ScanInto(value, propertyName: null, fullJsonPath: null, in features, matches);

            if (matches.Count == 0)
                return value;

            FilterAndResolveMatches(
                matches,
                filtered,
                propertyName: null,
                scope: scope,
                applyKeyHints: false);

            if (filtered.Count == 0)
                return value;

            return ApplyMatches(value, filtered, effectiveStrategy, maskCharOverride);
        }
        catch (TimeoutException ex)
        {
            PiiMetrics.ProcessingErrors.Add(1, new KeyValuePair<string, object?>("error_type", ex.GetType().Name));
            throw new PiiProcessingException("Timed out waiting for a PII engine CPU concurrency slot.", ex);
        }
        finally
        {
            if (acquired) _concurrencyGate!.Release();
        }
    }

    internal string ProtectCustomMatch(string rawValue, string visualMask, PiiType type, MaskingStrategy? strategyOverride)
    {
        var strategy = strategyOverride ?? _options.GetStrategy(type);
        switch (strategy)
        {
            case MaskingStrategy.OneWayRedaction:
                return visualMask;

            case MaskingStrategy.FormatPreservingReversible:
                if (_crypto == null)
                    throw new InvalidOperationException("Reversible masking requires a CryptoProvider (such as AES-GCM Master Key) to be configured.");
                return $"{visualMask}{FormatHelper.FormatPreservingPrefix}{_crypto.Encrypt(rawValue)}{FormatHelper.FormatPreservingSuffix}";

            case MaskingStrategy.ReversibleCryptoToken:
                if (_crypto == null)
                    throw new InvalidOperationException("Reversible masking requires a CryptoProvider (such as AES-GCM Master Key) to be configured.");
                return $"ENC{{{type}:{_crypto.Encrypt(rawValue)}}}";

            case MaskingStrategy.Hash:
                return ComputeHashToken(rawValue, type);

            default:
                return visualMask;
        }
    }

    private string ApplyMatches(string value, List<PiiMatch> matches, MaskingStrategy? strategyOverride, char? maskCharOverride = null)
    {
        if (matches.Count == 0)
            return value;

        if (matches.Count == 1)
        {
            var m = matches[0];
            if (m.Index == 0 && m.Length == value.Length)
                return ApplyMask(m.RawValue, m.Type, strategyOverride, maskCharOverride);
        }

        var sb = new StringBuilder(value);
        for (int i = matches.Count - 1; i >= 0; i--)
        {
            var match = matches[i];
            string masked = ApplyMask(match.RawValue, match.Type, strategyOverride, maskCharOverride);
            sb.Remove(match.Index, match.Length);
            sb.Insert(match.Index, masked);
        }

        return sb.ToString();
    }

    private string ApplyMask(string rawValue, PiiType type, MaskingStrategy? strategyOverride = null, char? maskCharOverride = null)
    {
        var strategy = strategyOverride ?? _options.GetStrategy(type);
        char maskChar = maskCharOverride ?? _options.MaskCharacter;

        switch (strategy)
        {
            case MaskingStrategy.OneWayRedaction:
                return FormatHelper.CreateMask(type, rawValue, maskChar);

            case MaskingStrategy.FormatPreservingReversible:
                if (_crypto == null)
                    throw new InvalidOperationException("Reversible masking requires a CryptoProvider (such as AES-GCM Master Key) to be configured.");

                string visual = FormatHelper.CreateMask(type, rawValue, maskChar);
                string token = _crypto.Encrypt(rawValue);
                return $"{visual}{FormatHelper.FormatPreservingPrefix}{token}{FormatHelper.FormatPreservingSuffix}";

            case MaskingStrategy.ReversibleCryptoToken:
                if (_crypto == null)
                    throw new InvalidOperationException("Reversible masking requires a CryptoProvider (such as AES-GCM Master Key) to be configured.");

                string directToken = _crypto.Encrypt(rawValue);
                return $"ENC{{{type}:{directToken}}}";

            case MaskingStrategy.Hash:
                return ComputeHashToken(rawValue, type);

            default:
                return FormatHelper.CreateMask(type, rawValue, maskChar);
        }
    }

    private string ComputeHashToken(string rawValue, PiiType type)
    {
        int maxBytes = Encoding.UTF8.GetMaxByteCount(rawValue.Length);
        byte[]? rented = null;
        Span<byte> digest = stackalloc byte[32];

        try
        {
            Span<byte> plainBuf = maxBytes <= 256
                ? stackalloc byte[256]
                : (rented = ArrayPool<byte>.Shared.Rent(maxBytes));

            int plainLen = Encoding.UTF8.GetBytes(rawValue.AsSpan(), plainBuf);
            ReadOnlySpan<byte> plainSpan = plainBuf[..plainLen];

            if (_hashKey != null)
            {
                HMACSHA256.HashData(_hashKey, plainSpan, digest);
            }
            else
            {
                SHA256.HashData(plainSpan, digest);
            }

            string encoded = AesGcmReversibleCrypto.Base64UrlEncode(digest);
            return $"HASH{{{type}:{encoded}}}";
        }
        finally
        {
            if (rented != null) ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }

    public string UnmaskValue(string maskedValue)
    {
        if (TryUnmaskValue(maskedValue, out string? unmasked))
            return unmasked!;
        return maskedValue;
    }

    public bool TryUnmaskValue(string maskedValue, out string? unmaskedValue)
    {
        unmaskedValue = null;
        if (string.IsNullOrEmpty(maskedValue) || _crypto == null)
            return false;

        // 1. Direct shortcut if whole string is a single #fp[...] token
        int fpTagIndex = maskedValue.IndexOf(FormatHelper.FormatPreservingPrefix, StringComparison.Ordinal);
        if (fpTagIndex >= 0 && maskedValue.EndsWith(FormatHelper.FormatPreservingSuffix))
        {
            int tokenStart = fpTagIndex + FormatHelper.FormatPreservingPrefix.Length;
            int tokenLen = maskedValue.Length - 1 - tokenStart;
            if (tokenLen > 0 && maskedValue.IndexOf(FormatHelper.FormatPreservingPrefix, tokenStart, StringComparison.Ordinal) < 0)
            {
                string cipherToken = maskedValue.Substring(tokenStart, tokenLen);
                if (_crypto.TryDecrypt(cipherToken, out string? plain))
                {
                    unmaskedValue = plain;
                    return true;
                }
            }
        }

        // 2. Direct shortcut if whole string is a single ENC{TYPE:token}
        if (maskedValue.StartsWith("ENC{", StringComparison.Ordinal) &&
            maskedValue.EndsWith('}') &&
            maskedValue.IndexOf("ENC{", 4, StringComparison.Ordinal) < 0)
        {
            int colonIdx = maskedValue.IndexOf(':', 4);
            if (colonIdx > 4 && colonIdx < maskedValue.Length - 2)
            {
                string cipherToken = maskedValue.Substring(colonIdx + 1, maskedValue.Length - colonIdx - 2);
                if (_crypto.TryDecrypt(cipherToken, out string? plain))
                {
                    unmaskedValue = plain;
                    return true;
                }
            }
        }

        bool modified = false;
        string current = maskedValue;

        // 3. Embedded #fp[...] replacement
        if (fpTagIndex >= 0)
        {
            current = FormatPreservingPattern().Replace(current, match =>
            {
                string cipherToken = match.Groups[1].Value;
                if (_crypto.TryDecrypt(cipherToken, out string? plain))
                {
                    modified = true;
                    return plain!;
                }
                return match.Value;
            });
        }

        // 4. Embedded ENC{TYPE:token} replacement (runs on updated string so mixed tokens both unmask!)
        if (current.Contains("ENC{", StringComparison.Ordinal))
        {
            current = ExplicitEncPattern().Replace(current, match =>
            {
                string cipherToken = match.Groups[2].Value;
                if (_crypto.TryDecrypt(cipherToken, out string? plain))
                {
                    modified = true;
                    return plain!;
                }
                return match.Value;
            });
        }

        if (modified)
        {
            unmaskedValue = current;
            return true;
        }

        return false;
    }

    public string MaskJson(string json) => MaskJson(json, (JsonMaskingScope?)null);

    public string MaskJson(string json, Action<JsonMaskingScope> configureScope)
    {
        var scope = new JsonMaskingScope();
        configureScope(scope);
        return MaskJson(json, scope);
    }

    public string MaskJson(string json, JsonMaskingScope? scope)
    {
        if (string.IsNullOrWhiteSpace(json))
            return json;

        return ProcessJsonString(json, isMasking: true, scope: scope, detections: null, out _);
    }

    public MaskingResult MaskJsonWithAudit(string json, JsonMaskingScope? scope = null)
    {
        if (string.IsNullOrWhiteSpace(json))
            return new MaskingResult { Output = json, Detections = Array.Empty<PiiDetection>(), HasPii = false, DurationMs = 0 };

        var detections = new List<PiiDetection>(4);
        string output = ProcessJsonString(json, isMasking: true, scope: scope, detections: detections, out double durationMs);

        return new MaskingResult
        {
            Output = output,
            Detections = detections.AsReadOnly(),
            HasPii = detections.Count > 0,
            DurationMs = durationMs
        };
    }

    public string UnmaskJson(string maskedJson)
    {
        if (string.IsNullOrWhiteSpace(maskedJson))
            return maskedJson;

        return ProcessJsonString(maskedJson, isMasking: false, scope: null, detections: null, out _);
    }

    private string ProcessJsonString(
        string json,
        bool isMasking,
        JsonMaskingScope? scope,
        List<PiiDetection>? detections,
        out double durationMs)
    {
        int maxInputBytes = Encoding.UTF8.GetMaxByteCount(json.Length);
        byte[]? rentedInput = ArrayPool<byte>.Shared.Rent(maxInputBytes);
        using var outputBuffer = new PooledByteBufferWriter(Math.Max(256, maxInputBytes + 256));

        long startTs = Stopwatch.GetTimestamp();
        using var activity = PiiTracing.Source.StartActivity("ProcessJsonString");
        PiiMetrics.PayloadsProcessed.Add(1);

        int utf8Len = 0;
        bool acquired = false;
        try
        {
            utf8Len = Encoding.UTF8.GetBytes(json.AsSpan(), rentedInput);
            acquired = TryAcquireConcurrencySlot();
            ProcessJsonBytes(rentedInput.AsSpan(0, utf8Len), outputBuffer, isMasking, scope, detections);
            return Encoding.UTF8.GetString(outputBuffer.WrittenSpan);
        }
        catch (JsonException ex)
        {
            HandleBufferError(rentedInput.AsSpan(0, utf8Len), outputBuffer, ex, "Malformed JSON encountered during processing.");
            return Encoding.UTF8.GetString(outputBuffer.WrittenSpan);
        }
        catch (RegexMatchTimeoutException ex)
        {
            HandleBufferError(rentedInput.AsSpan(0, utf8Len), outputBuffer, ex, "Catastrophic regex backtracking timeout detected.");
            return Encoding.UTF8.GetString(outputBuffer.WrittenSpan);
        }
        catch (TimeoutException ex)
        {
            HandleBufferError(rentedInput.AsSpan(0, utf8Len), outputBuffer, ex, "Timed out waiting for a PII engine CPU concurrency slot.");
            return Encoding.UTF8.GetString(outputBuffer.WrittenSpan);
        }
        finally
        {
            if (acquired) _concurrencyGate!.Release();
            durationMs = GetElapsedMs(startTs);
            PiiMetrics.ProcessingDurationMs.Record(durationMs);
            ArrayPool<byte>.Shared.Return(rentedInput);
        }
    }

    public void MaskJsonStream(Stream inputUtf8Json, Stream outputUtf8Json)
    {
        ProcessJsonStream(inputUtf8Json, outputUtf8Json, isMasking: true, scope: null, detections: null);
    }

    public void MaskJsonStream(Stream inputUtf8Json, Stream outputUtf8Json, JsonMaskingScope? scope = null)
    {
        ProcessJsonStream(inputUtf8Json, outputUtf8Json, isMasking: true, scope: scope, detections: null);
    }

    public void UnmaskJsonStream(Stream inputUtf8Json, Stream outputUtf8Json)
    {
        ProcessJsonStream(inputUtf8Json, outputUtf8Json, isMasking: false, scope: null, detections: null);
    }

    public void MaskJsonUtf8(ReadOnlySpan<byte> inputUtf8, IBufferWriter<byte> outputUtf8, JsonMaskingScope? scope = null)
    {
        ProcessJsonUtf8Core(inputUtf8, outputUtf8, isMasking: true, scope: scope);
    }

    public void UnmaskJsonUtf8(ReadOnlySpan<byte> inputUtf8, IBufferWriter<byte> outputUtf8)
    {
        ProcessJsonUtf8Core(inputUtf8, outputUtf8, isMasking: false, scope: null);
    }

    private void ProcessJsonUtf8Core(ReadOnlySpan<byte> inputUtf8, IBufferWriter<byte> outputUtf8, bool isMasking, JsonMaskingScope? scope)
    {
        long startTs = Stopwatch.GetTimestamp();
        using var activity = PiiTracing.Source.StartActivity("ProcessJsonUtf8");
        PiiMetrics.PayloadsProcessed.Add(1);

        if (_options.ErrorBehavior == PiiErrorBehavior.Throw)
        {
            bool acquiredThrow = false;
            try
            {
                acquiredThrow = TryAcquireConcurrencySlot();
                ProcessJsonBytes(inputUtf8, outputUtf8, isMasking, scope, detections: null);
            }
            catch (JsonException ex)
            {
                PiiMetrics.ProcessingErrors.Add(1, new KeyValuePair<string, object?>("error_type", ex.GetType().Name));
                throw new PiiProcessingException("Malformed JSON encountered during processing.", ex);
            }
            catch (RegexMatchTimeoutException ex)
            {
                PiiMetrics.ProcessingErrors.Add(1, new KeyValuePair<string, object?>("error_type", ex.GetType().Name));
                throw new PiiProcessingException("Catastrophic regex backtracking timeout detected.", ex);
            }
            catch (TimeoutException ex)
            {
                PiiMetrics.ProcessingErrors.Add(1, new KeyValuePair<string, object?>("error_type", ex.GetType().Name));
                throw new PiiProcessingException("Timed out waiting for a PII engine CPU concurrency slot.", ex);
            }
            finally
            {
                if (acquiredThrow) _concurrencyGate!.Release();
                PiiMetrics.ProcessingDurationMs.Record(GetElapsedMs(startTs));
            }
            return;
        }

        // Stage into pooled buffer if external writer so PassThrough/Redact never leaves partial corrupt JSON
        PooledByteBufferWriter? localStage = outputUtf8 as PooledByteBufferWriter;
        bool ownsStage = localStage == null;
        localStage ??= new PooledByteBufferWriter(Math.Max(256, inputUtf8.Length + 256));
        bool acquiredStage = false;

        try
        {
            acquiredStage = TryAcquireConcurrencySlot();
            ProcessJsonBytes(inputUtf8, localStage, isMasking, scope, detections: null);
            if (ownsStage)
                WriteSpanToBufferWriter(localStage.WrittenSpan, outputUtf8);
        }
        catch (JsonException ex)
        {
            HandleBufferError(inputUtf8, localStage, ex, "Malformed JSON encountered during processing.");
            if (ownsStage)
                WriteSpanToBufferWriter(localStage.WrittenSpan, outputUtf8);
        }
        catch (RegexMatchTimeoutException ex)
        {
            HandleBufferError(inputUtf8, localStage, ex, "Catastrophic regex backtracking timeout detected.");
            if (ownsStage)
                WriteSpanToBufferWriter(localStage.WrittenSpan, outputUtf8);
        }
        catch (TimeoutException ex)
        {
            HandleBufferError(inputUtf8, localStage, ex, "Timed out waiting for a PII engine CPU concurrency slot.");
            if (ownsStage)
                WriteSpanToBufferWriter(localStage.WrittenSpan, outputUtf8);
        }
        finally
        {
            if (acquiredStage) _concurrencyGate!.Release();
            PiiMetrics.ProcessingDurationMs.Record(GetElapsedMs(startTs));
            if (ownsStage)
                localStage.Dispose();
        }
    }

    public async Task MaskJsonStreamAsync(
        Stream inputUtf8Json,
        Stream outputUtf8Json,
        JsonMaskingScope? scope = null,
        CancellationToken cancellationToken = default)
    {
        await ProcessJsonStreamAsync(inputUtf8Json, outputUtf8Json, isMasking: true, scope: scope, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    public async Task UnmaskJsonStreamAsync(
        Stream inputUtf8Json,
        Stream outputUtf8Json,
        CancellationToken cancellationToken = default)
    {
        await ProcessJsonStreamAsync(inputUtf8Json, outputUtf8Json, isMasking: false, scope: null, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    public void MaskNdjsonStream(Stream inputUtf8Ndjson, Stream outputUtf8Ndjson, JsonMaskingScope? scope = null)
    {
        ArgumentNullException.ThrowIfNull(inputUtf8Ndjson);
        ArgumentNullException.ThrowIfNull(outputUtf8Ndjson);

        if (inputUtf8Ndjson.CanSeek) inputUtf8Ndjson.Position = 0;

        byte[] readChunk = ArrayPool<byte>.Shared.Rent(16384);
        using var lineBuf = new PooledByteBufferWriter(4096);
        using var outBuf = new PooledByteBufferWriter(4096);

        try
        {
            int bytesRead;
            while ((bytesRead = inputUtf8Ndjson.Read(readChunk, 0, readChunk.Length)) > 0)
            {
                ReadOnlySpan<byte> span = readChunk.AsSpan(0, bytesRead);
                while (!span.IsEmpty)
                {
                    int nl = span.IndexOf((byte)'\n');
                    if (nl >= 0)
                    {
                        var seg = span[..nl];
                        if (!seg.IsEmpty)
                        {
                            var dst = lineBuf.GetSpan(seg.Length);
                            seg.CopyTo(dst);
                            lineBuf.Advance(seg.Length);
                        }

                        FlushNdjsonLine(lineBuf.WrittenSpan, outBuf, outputUtf8Ndjson, scope, emitNewline: true);
                        lineBuf.Clear();
                        span = span[(nl + 1)..];
                    }
                    else
                    {
                        var dst = lineBuf.GetSpan(span.Length);
                        span.CopyTo(dst);
                        lineBuf.Advance(span.Length);
                        break;
                    }
                }
            }

            if (lineBuf.WrittenCount > 0)
            {
                FlushNdjsonLine(lineBuf.WrittenSpan, outBuf, outputUtf8Ndjson, scope, emitNewline: false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(readChunk);
        }
    }

    public async Task MaskNdjsonStreamAsync(
        Stream inputUtf8Ndjson,
        Stream outputUtf8Ndjson,
        JsonMaskingScope? scope = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inputUtf8Ndjson);
        ArgumentNullException.ThrowIfNull(outputUtf8Ndjson);

        if (inputUtf8Ndjson.CanSeek) inputUtf8Ndjson.Position = 0;

        byte[] readChunk = ArrayPool<byte>.Shared.Rent(16384);
        using var lineBuf = new PooledByteBufferWriter(4096);
        using var outBuf = new PooledByteBufferWriter(4096);

        try
        {
            int bytesRead;
            while ((bytesRead = await inputUtf8Ndjson.ReadAsync(readChunk.AsMemory(), cancellationToken).ConfigureAwait(false)) > 0)
            {
                ProcessNdjsonChunkSync(readChunk, bytesRead, lineBuf, outBuf, scope);
                if (outBuf.WrittenCount > 0)
                {
                    await outputUtf8Ndjson.WriteAsync(outBuf.WrittenMemory, cancellationToken).ConfigureAwait(false);
                    outBuf.Clear();
                }
            }

            if (lineBuf.WrittenCount > 0)
            {
                FlushTrailingNdjsonLineSync(lineBuf, outBuf, scope);
                if (outBuf.WrittenCount > 0)
                {
                    await outputUtf8Ndjson.WriteAsync(outBuf.WrittenMemory, cancellationToken).ConfigureAwait(false);
                    outBuf.Clear();
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(readChunk);
        }
    }

    private void ProcessNdjsonChunkSync(
        byte[] readChunk,
        int bytesRead,
        PooledByteBufferWriter lineBuf,
        PooledByteBufferWriter outBuf,
        JsonMaskingScope? scope)
    {
        ReadOnlySpan<byte> span = readChunk.AsSpan(0, bytesRead);
        while (!span.IsEmpty)
        {
            int nl = span.IndexOf((byte)'\n');
            if (nl >= 0)
            {
                if (nl > 0)
                {
                    var seg = span[..nl];
                    seg.CopyTo(lineBuf.GetSpan(seg.Length));
                    lineBuf.Advance(seg.Length);
                }

                ProcessNdjsonLineToBuffer(lineBuf.WrittenSpan, outBuf, scope, emitNewline: true);
                lineBuf.Clear();
                span = span[(nl + 1)..];
            }
            else
            {
                span.CopyTo(lineBuf.GetSpan(span.Length));
                lineBuf.Advance(span.Length);
                break;
            }
        }
    }

    private void FlushTrailingNdjsonLineSync(
        PooledByteBufferWriter lineBuf,
        PooledByteBufferWriter outBuf,
        JsonMaskingScope? scope)
    {
        ProcessNdjsonLineToBuffer(lineBuf.WrittenSpan, outBuf, scope, emitNewline: false);
    }

    private void FlushNdjsonLine(
        ReadOnlySpan<byte> line,
        PooledByteBufferWriter outBuf,
        Stream output,
        JsonMaskingScope? scope,
        bool emitNewline)
    {
        ProcessNdjsonLineToBuffer(line, outBuf, scope, emitNewline);
        if (outBuf.WrittenCount > 0)
        {
            output.Write(outBuf.WrittenSpan);
            outBuf.Clear();
        }
    }

    private void ProcessNdjsonLineToBuffer(
        ReadOnlySpan<byte> rawLine,
        PooledByteBufferWriter outBuf,
        JsonMaskingScope? scope,
        bool emitNewline)
    {
        bool hadCr = rawLine.Length > 0 && rawLine[^1] == (byte)'\r';
        ReadOnlySpan<byte> trimmed = rawLine.Trim((byte)' ').Trim((byte)'\t').Trim((byte)'\r');
        if (trimmed.IsEmpty)
        {
            if (emitNewline)
            {
                var s = outBuf.GetSpan(1);
                s[0] = (byte)'\n';
                outBuf.Advance(1);
            }
            return;
        }

        ProcessJsonUtf8Core(trimmed, outBuf, isMasking: true, scope: scope);
        if (emitNewline)
        {
            if (hadCr)
            {
                var s = outBuf.GetSpan(2);
                s[0] = (byte)'\r';
                s[1] = (byte)'\n';
                outBuf.Advance(2);
            }
            else
            {
                var s = outBuf.GetSpan(1);
                s[0] = (byte)'\n';
                outBuf.Advance(1);
            }
        }
    }

    private void ProcessJsonStream(Stream input, Stream output, bool isMasking, JsonMaskingScope? scope = null, List<PiiDetection>? detections = null)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);

        long startTs = Stopwatch.GetTimestamp();
        using var activity = PiiTracing.Source.StartActivity("ProcessJsonStream");
        PiiMetrics.PayloadsProcessed.Add(1);

        PooledByteBufferWriter? pooledInput = null;
        using var outputBuffer = new PooledByteBufferWriter(4096);
        ReadOnlySpan<byte> inputSpan = default;
        bool acquired = false;

        try
        {
            if (input is MemoryStream ms && ms.TryGetBuffer(out ArraySegment<byte> seg))
            {
                int pos = ms.CanSeek ? (int)ms.Position : 0;
                int count = Math.Max(0, seg.Count - pos);
                inputSpan = seg.AsSpan(pos, count);
                if (ms.CanSeek) ms.Position = ms.Length;
            }
            else
            {
                if (input.CanSeek) input.Position = 0;
                pooledInput = new PooledByteBufferWriter(4096);
                CopyStreamToPooledWriter(input, pooledInput);
                inputSpan = pooledInput.WrittenSpan;
            }

            acquired = TryAcquireConcurrencySlot();
            ProcessJsonBytes(inputSpan, outputBuffer, isMasking, scope, detections);
            output.Write(outputBuffer.WrittenSpan);
        }
        catch (JsonException ex)
        {
            HandleStreamError(inputSpan, outputBuffer, output, ex, "Malformed JSON encountered during processing.");
        }
        catch (RegexMatchTimeoutException ex)
        {
            HandleStreamError(inputSpan, outputBuffer, output, ex, "Catastrophic regex backtracking timeout detected.");
        }
        catch (TimeoutException ex)
        {
            HandleStreamError(inputSpan, outputBuffer, output, ex, "Timed out waiting for a PII engine CPU concurrency slot.");
        }
        finally
        {
            if (acquired) _concurrencyGate!.Release();
            PiiMetrics.ProcessingDurationMs.Record(GetElapsedMs(startTs));
            pooledInput?.Dispose();
        }
    }

    private async Task ProcessJsonStreamAsync(
        Stream input,
        Stream output,
        bool isMasking,
        JsonMaskingScope? scope,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);

        long startTs = Stopwatch.GetTimestamp();
        using var activity = PiiTracing.Source.StartActivity("ProcessJsonStreamAsync");
        PiiMetrics.PayloadsProcessed.Add(1);

        PooledByteBufferWriter? pooledInput = null;
        using var outputBuffer = new PooledByteBufferWriter(4096);
        bool acquired = false;

        try
        {
            ReadOnlyMemory<byte> inputMemory;
            if (input is MemoryStream ms && ms.TryGetBuffer(out ArraySegment<byte> seg))
            {
                int pos = ms.CanSeek ? (int)ms.Position : 0;
                int count = Math.Max(0, seg.Count - pos);
                inputMemory = seg.AsMemory(pos, count);
                if (ms.CanSeek) ms.Position = ms.Length;
            }
            else
            {
                if (input.CanSeek) input.Position = 0;
                pooledInput = new PooledByteBufferWriter(4096);
                await CopyStreamToPooledWriterAsync(input, pooledInput, cancellationToken).ConfigureAwait(false);
                inputMemory = pooledInput.WrittenMemory;
            }

            try
            {
                acquired = await TryAcquireConcurrencySlotAsync(cancellationToken).ConfigureAwait(false);
                ProcessMemoryIntoBufferWithErrorHandling(inputMemory, outputBuffer, isMasking, scope);
            }
            catch (TimeoutException ex)
            {
                HandleMemoryTimeoutError(inputMemory, outputBuffer, ex);
            }

            await output.WriteAsync(outputBuffer.WrittenMemory, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (acquired) _concurrencyGate!.Release();
            PiiMetrics.ProcessingDurationMs.Record(GetElapsedMs(startTs));
            pooledInput?.Dispose();
        }
    }

    private void HandleMemoryTimeoutError(ReadOnlyMemory<byte> inputMemory, PooledByteBufferWriter outputBuffer, TimeoutException ex)
    {
        HandleBufferError(inputMemory.Span, outputBuffer, ex, "Timed out waiting for a PII engine CPU concurrency slot.");
    }

    private void ProcessMemoryIntoBufferWithErrorHandling(
        ReadOnlyMemory<byte> inputMemory,
        PooledByteBufferWriter outputBuffer,
        bool isMasking,
        JsonMaskingScope? scope)
    {
        try
        {
            ProcessJsonBytes(inputMemory.Span, outputBuffer, isMasking, scope, detections: null);
        }
        catch (JsonException ex)
        {
            HandleBufferError(inputMemory.Span, outputBuffer, ex, "Malformed JSON encountered during processing.");
        }
        catch (RegexMatchTimeoutException ex)
        {
            HandleBufferError(inputMemory.Span, outputBuffer, ex, "Catastrophic regex backtracking timeout detected.");
        }
    }

    private void HandleBufferError(ReadOnlySpan<byte> inputBytes, PooledByteBufferWriter outputBuffer, Exception ex, string message)
    {
        PiiMetrics.ProcessingErrors.Add(1, new KeyValuePair<string, object?>("error_type", ex.GetType().Name));

        if (_options.ErrorBehavior == PiiErrorBehavior.Throw)
            throw new PiiProcessingException(message, ex);

        outputBuffer.Clear();
        if (_options.ErrorBehavior == PiiErrorBehavior.PassThrough)
        {
            if (!inputBytes.IsEmpty)
                WriteSpanToBufferWriter(inputBytes, outputBuffer);
        }
        else if (_options.ErrorBehavior == PiiErrorBehavior.Redact)
        {
            WriteSpanToBufferWriter(RedactedFallbackBytes, outputBuffer);
        }
    }

    private void HandleStreamError(ReadOnlySpan<byte> inputBytes, PooledByteBufferWriter outputBuffer, Stream output, Exception ex, string message)
    {
        HandleBufferError(inputBytes, outputBuffer, ex, message);
        if (output.CanSeek)
        {
            output.SetLength(0);
            output.Position = 0;
        }
        if (outputBuffer.WrittenCount > 0)
            output.Write(outputBuffer.WrittenSpan);
    }

    private void ProcessJsonBytes(
        ReadOnlySpan<byte> inputBytes,
        IBufferWriter<byte> output,
        bool isMasking,
        JsonMaskingScope? scope,
        List<PiiDetection>? detections)
    {
        var readerOptions = new JsonReaderOptions
        {
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip
        };

        var writerOptions = new JsonWriterOptions
        {
            Indented = false,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        var reader = new Utf8JsonReader(inputBytes, readerOptions);
        using var writer = new Utf8JsonWriter(output, writerOptions);

        var stack = new List<JsonFrame>(16);
        string? pendingProperty = null;

        // Reused per-document scratch lists — zero per-token List allocations
        var scratchMatches = new List<PiiMatch>(4);
        var scratchFiltered = new List<PiiMatch>(4);
        var sbScratch = new StringBuilder(64);
        Span<char> numChars = stackalloc char[32];

        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.StartObject:
                {
                    AdvanceParentArrayIndex(stack);
                    string? ownerProp = pendingProperty;
                    if (ownerProp == null && stack.Count > 0 && stack[^1].IsArray)
                        ownerProp = stack[^1].PropertyName;
                    stack.Add(new JsonFrame { IsArray = false, PropertyName = ownerProp, ArrayIndex = -1 });
                    pendingProperty = null;
                    writer.WriteStartObject();
                    break;
                }

                case JsonTokenType.EndObject:
                {
                    if (stack.Count > 0)
                        stack.RemoveAt(stack.Count - 1);
                    pendingProperty = null;
                    writer.WriteEndObject();
                    break;
                }

                case JsonTokenType.StartArray:
                {
                    AdvanceParentArrayIndex(stack);
                    string? ownerProp = pendingProperty;
                    if (ownerProp == null && stack.Count > 0 && stack[^1].IsArray)
                        ownerProp = stack[^1].PropertyName;
                    stack.Add(new JsonFrame { IsArray = true, PropertyName = ownerProp, ArrayIndex = -1 });
                    pendingProperty = null;
                    writer.WriteStartArray();
                    break;
                }

                case JsonTokenType.EndArray:
                {
                    if (stack.Count > 0)
                        stack.RemoveAt(stack.Count - 1);
                    pendingProperty = null;
                    writer.WriteEndArray();
                    break;
                }

                case JsonTokenType.PropertyName:
                {
                    pendingProperty = reader.GetString();
                    writer.WritePropertyName(pendingProperty!);
                    break;
                }

                case JsonTokenType.String:
                {
                    int arrIdx = AdvanceParentArrayIndex(stack);
                    string? leafProperty = ResolveLeafProperty(stack, pendingProperty);
                    pendingProperty = null;

                    if (isMasking)
                    {
                        if (ShouldSkipByScopeKeys(stack, leafProperty, scope))
                        {
                            if (reader.ValueSpan.IndexOf((byte)'\\') < 0)
                                writer.WriteStringValue(reader.ValueSpan);
                            else
                                writer.WriteStringValue(reader.GetString());
                            break;
                        }

                        string val = reader.GetString()!;
                        if (string.IsNullOrEmpty(val))
                        {
                            writer.WriteStringValue(val);
                            break;
                        }

                        string masked = MaskTextToken(
                            val,
                            stack,
                            leafProperty,
                            arrIdx,
                            scope,
                            detections,
                            scratchMatches,
                            scratchFiltered,
                            sbScratch,
                            out bool didMask);

                        if (didMask)
                            writer.WriteStringValue(masked);
                        else
                            writer.WriteStringValue(val);
                    }
                    else
                    {
                        // Fast zero-alloc UTF-8 check: only bypass GetString() when there are no tokens AND no JSON backslash escapes
                        ReadOnlySpan<byte> rawUtf8 = reader.ValueSpan;
                        if (rawUtf8.IndexOf("#fp["u8) < 0 &&
                            rawUtf8.IndexOf("ENC{"u8) < 0 &&
                            rawUtf8.IndexOf((byte)'\\') < 0)
                        {
                            writer.WriteStringValue(rawUtf8);
                        }
                        else
                        {
                            string val = reader.GetString()!;
                            if (TryUnmaskValue(val, out string? unmasked))
                                writer.WriteStringValue(unmasked);
                            else
                                writer.WriteStringValue(val);
                        }
                    }
                    break;
                }

                case JsonTokenType.Number:
                {
                    int arrIdx = AdvanceParentArrayIndex(stack);
                    string? leafProperty = ResolveLeafProperty(stack, pendingProperty);
                    pendingProperty = null;

                    if (isMasking && reader.TryGetInt64(out long numVal))
                    {
                        if (!ShouldSkipByScopeKeys(stack, leafProperty, scope) &&
                            numVal.TryFormat(numChars, out int charsWritten) &&
                            charsWritten >= 6)
                        {
                            string numStr = new string(numChars[..charsWritten]);
                            string masked = MaskTextToken(
                                numStr,
                                stack,
                                leafProperty,
                                arrIdx,
                                scope,
                                detections,
                                scratchMatches,
                                scratchFiltered,
                                sbScratch,
                                out bool didMask);

                            if (didMask)
                            {
                                writer.WriteStringValue(masked);
                                break;
                            }
                        }
                    }

                    writer.WriteRawValue(reader.ValueSpan, skipInputValidation: true);
                    break;
                }

                case JsonTokenType.True:
                    AdvanceParentArrayIndex(stack);
                    pendingProperty = null;
                    writer.WriteBooleanValue(true);
                    break;

                case JsonTokenType.False:
                    AdvanceParentArrayIndex(stack);
                    pendingProperty = null;
                    writer.WriteBooleanValue(false);
                    break;

                case JsonTokenType.Null:
                    AdvanceParentArrayIndex(stack);
                    pendingProperty = null;
                    writer.WriteNullValue();
                    break;
            }
        }

        writer.Flush();
    }

    private string MaskTextToken(
        string value,
        List<JsonFrame> stack,
        string? leafProperty,
        int arrayIndex,
        JsonMaskingScope? scope,
        List<PiiDetection>? detections,
        List<PiiMatch> scratchMatches,
        List<PiiMatch> scratchFiltered,
        StringBuilder sbScratch,
        out bool didMask)
    {
        didMask = false;
        scratchMatches.Clear();
        scratchFiltered.Clear();

        var features = TextFeatures.Analyze(value.AsSpan());
        string? fullPath = detections != null ? BuildFullJsonPath(stack, leafProperty, arrayIndex) : null;

        ScanInto(value, leafProperty, fullPath, in features, scratchMatches);

        if (scratchMatches.Count == 0)
            return value;

        FilterAndResolveMatches(
            scratchMatches,
            scratchFiltered,
            leafProperty,
            scope,
            applyKeyHints: leafProperty != null);

        if (scratchFiltered.Count == 0)
            return value;

        didMask = true;

        for (int i = 0; i < scratchFiltered.Count; i++)
        {
            var match = scratchFiltered[i];
            PiiMetrics.ElementsMasked.Add(1, new KeyValuePair<string, object?>("pii_type", match.Type.ToString()));

            if (detections != null)
            {
                detections.Add(new PiiDetection
                {
                    Type = match.Type,
                    Confidence = match.Confidence,
                    RecognizerName = match.TypeName,
                    JsonPath = leafProperty,
                    FullJsonPath = fullPath
                });
            }
        }

        if (scratchFiltered.Count == 1)
        {
            var m = scratchFiltered[0];
            if (m.Index == 0 && m.Length == value.Length)
                return ApplyMask(m.RawValue, m.Type, scope?.StrategyOverride);
        }

        sbScratch.Clear();
        sbScratch.EnsureCapacity(value.Length + 64);
        sbScratch.Append(value);

        for (int i = scratchFiltered.Count - 1; i >= 0; i--)
        {
            var match = scratchFiltered[i];
            string masked = ApplyMask(match.RawValue, match.Type, scope?.StrategyOverride);
            sbScratch.Remove(match.Index, match.Length);
            sbScratch.Insert(match.Index, masked);
        }

        return sbScratch.ToString();
    }

    private void FilterAndResolveMatches(
        List<PiiMatch> source,
        List<PiiMatch> resolved,
        string? propertyName,
        JsonMaskingScope? scope,
        bool applyKeyHints)
    {
        var includeTypes = scope?.IncludeTypes;
        var excludeTypes = scope?.ExcludeTypes;

        // 1. Scope filter + key hint boost + MinConfidence threshold in a single in-place pass
        int writeIdx = 0;
        for (int i = 0; i < source.Count; i++)
        {
            var m = source[i];
            if (includeTypes != null && !includeTypes.Contains(m.Type))
                continue;
            if (excludeTypes != null && excludeTypes.Contains(m.Type))
                continue;

            double conf = m.Confidence;
            if (applyKeyHints && propertyName != null)
            {
                double delta = _options.KeyHints.GetBoost(propertyName, m.Type);
                if (delta != 0.0)
                {
                    conf = Math.Clamp(conf + delta, 0.0, 1.0);
                    m = m with { Confidence = conf };
                }
            }

            if (conf < _options.MinConfidence)
                continue;

            source[writeIdx++] = m;
        }

        if (writeIdx == 0)
            return;

        if (writeIdx < source.Count)
            source.RemoveRange(writeIdx, source.Count - writeIdx);

        // 2. Sort once by Index ascending, Length descending
        SortMatchesInPlace(source);

        // 3. Resolve overlapping spans once
        for (int i = 0; i < source.Count; i++)
        {
            var m = source[i];
            bool overlaps = false;
            for (int j = 0; j < resolved.Count; j++)
            {
                var existing = resolved[j];
                if (m.Index < existing.Index + existing.Length && m.Index + m.Length > existing.Index)
                {
                    if (m.Confidence > existing.Confidence || (m.Confidence == existing.Confidence && m.Length > existing.Length))
                    {
                        resolved[j] = m;
                    }
                    overlaps = true;
                    break;
                }
            }

            if (!overlaps)
                resolved.Add(m);
        }

        if (resolved.Count > 1)
            SortMatchesInPlace(resolved);
    }

    private static void SortMatchesInPlace(List<PiiMatch> matches)
    {
        if (matches.Count <= 1)
            return;

        matches.Sort(static (a, b) =>
        {
            int idxCmp = a.Index.CompareTo(b.Index);
            return idxCmp != 0 ? idxCmp : b.Length.CompareTo(a.Length);
        });
    }

    private static int AdvanceParentArrayIndex(List<JsonFrame> stack)
    {
        if (stack.Count == 0)
            return -1;

        var top = stack[^1];
        if (!top.IsArray)
            return -1;

        top.ArrayIndex++;
        stack[^1] = top;
        return top.ArrayIndex;
    }

    private static string? ResolveLeafProperty(List<JsonFrame> stack, string? pendingProperty)
    {
        if (pendingProperty != null)
            return pendingProperty;

        if (stack.Count > 0 && stack[^1].IsArray)
            return stack[^1].PropertyName;

        return null;
    }

    private static bool ShouldSkipByScopeKeys(List<JsonFrame> stack, string? leafProperty, JsonMaskingScope? scope)
    {
        if (scope == null)
            return false;

        if (scope.ExcludeKeys != null)
        {
            if (leafProperty != null && scope.ExcludeKeys.Contains(leafProperty))
                return true;

            for (int i = 0; i < stack.Count; i++)
            {
                var frameProp = stack[i].PropertyName;
                if (frameProp != null && scope.ExcludeKeys.Contains(frameProp))
                    return true;
            }
        }

        if (scope.IncludeKeys != null)
        {
            if (leafProperty != null && scope.IncludeKeys.Contains(leafProperty))
                return false;

            for (int i = 0; i < stack.Count; i++)
            {
                var frameProp = stack[i].PropertyName;
                if (frameProp != null && scope.IncludeKeys.Contains(frameProp))
                    return false;
            }

            return true;
        }

        return false;
    }

    private static string BuildFullJsonPath(List<JsonFrame> stack, string? leafProperty, int arrayIndex)
    {
        var sb = new StringBuilder("$");
        for (int i = 0; i < stack.Count; i++)
        {
            var f = stack[i];
            if (!string.IsNullOrEmpty(f.PropertyName) && (i == 0 || !stack[i - 1].IsArray || f.PropertyName != stack[i - 1].PropertyName))
            {
                sb.Append('.').Append(f.PropertyName);
            }
            if (f.IsArray && f.ArrayIndex >= 0)
            {
                sb.Append('[').Append(f.ArrayIndex).Append(']');
            }
        }

        if (leafProperty != null && (stack.Count == 0 || !stack[^1].IsArray))
        {
            sb.Append('.').Append(leafProperty);
        }

        return sb.ToString();
    }

    private static void CopyStreamToPooledWriter(Stream input, PooledByteBufferWriter writer)
    {
        while (true)
        {
            Memory<byte> mem = writer.GetMemory(8192);
            int read = input.Read(mem.Span);
            if (read <= 0)
                break;
            writer.Advance(read);
        }
    }

    private static async Task CopyStreamToPooledWriterAsync(Stream input, PooledByteBufferWriter writer, CancellationToken cancellationToken)
    {
        while (true)
        {
            Memory<byte> mem = writer.GetMemory(8192);
            int read = await input.ReadAsync(mem, cancellationToken).ConfigureAwait(false);
            if (read <= 0)
                break;
            writer.Advance(read);
        }
    }

    private static void WriteSpanToBufferWriter(ReadOnlySpan<byte> data, IBufferWriter<byte> destination)
    {
        if (data.IsEmpty)
            return;
        Span<byte> dst = destination.GetSpan(data.Length);
        data.CopyTo(dst);
        destination.Advance(data.Length);
    }

    private static double GetElapsedMs(long startTimestamp)
    {
        return (Stopwatch.GetTimestamp() - startTimestamp) * 1000.0 / Stopwatch.Frequency;
    }

    private bool TryAcquireConcurrencySlot()
    {
        if (_concurrencyGate == null)
            return false;

        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_acquireTimeout == Timeout.InfiniteTimeSpan)
        {
            _concurrencyGate.Wait();
            return true;
        }

        if (!_concurrencyGate.Wait(_acquireTimeout))
            throw new TimeoutException($"Timed out after {_acquireTimeout.TotalMilliseconds:F0} ms waiting for a PII engine CPU concurrency slot.");

        return true;
    }

    private async ValueTask<bool> TryAcquireConcurrencySlotAsync(CancellationToken cancellationToken)
    {
        if (_concurrencyGate == null)
            return false;

        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_acquireTimeout == Timeout.InfiniteTimeSpan)
        {
            await _concurrencyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }

        if (!await _concurrencyGate.WaitAsync(_acquireTimeout, cancellationToken).ConfigureAwait(false))
            throw new TimeoutException($"Timed out after {_acquireTimeout.TotalMilliseconds:F0} ms waiting for a PII engine CPU concurrency slot.");

        return true;
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        _concurrencyGate?.Dispose();

        if (_crypto is IDisposable disposableCrypto)
            disposableCrypto.Dispose();

        for (int i = 0; i < _recognizers.Length; i++)
        {
            if (_recognizers[i] is IDisposable d)
                d.Dispose();
        }

        if (_hashKey != null)
            CryptographicOperations.ZeroMemory(_hashKey);
    }
}
