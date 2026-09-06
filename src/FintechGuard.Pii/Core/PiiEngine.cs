using System.Buffers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using FintechGuard.Pii.Crypto;
using FintechGuard.Pii.Masking;
using FintechGuard.Pii.Recognizers;

namespace FintechGuard.Pii.Core;

public sealed partial class PiiEngine : IPiiEngine
{
    private readonly PiiEngineOptions _options;
    private readonly IReadOnlyList<IPiiRecognizer> _recognizers;
    private readonly IReversibleCrypto? _crypto;

    [GeneratedRegex(@"(?:XXXX[ -]XXXX[ -]\d{4}|\d{4}[ -]\*{4}[ -]\*{4}[ -]\d{4}|[^\s,;:""'()<>\[\]]+)#fp\[([a-zA-Z0-9_\-]+)\]", RegexOptions.Compiled)]
    private static partial Regex FormatPreservingPattern();

    [GeneratedRegex(@"ENC\{([a-zA-Z0-9_]+):([a-zA-Z0-9_\-]+)\}", RegexOptions.Compiled)]
    private static partial Regex ExplicitEncPattern();

    public PiiEngine(PiiEngineOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _recognizers = options.Recognizers.ToList().AsReadOnly();
        _crypto = options.CryptoProvider;
    }

    public IReadOnlyList<PiiMatch> Scan(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Array.Empty<PiiMatch>();

        var matches = new List<PiiMatch>();
        foreach (var recognizer in _recognizers)
        {
            var detected = recognizer.Recognize(text);
            matches.AddRange(detected);
        }

        // Sort by start index ascending, then length descending
        return matches
            .OrderBy(m => m.Index)
            .ThenByDescending(m => m.Length)
            .ToList();
    }

    public string MaskValue(string value, PiiType? hintType = null)
    {
        return MaskValue(value, hintType, null);
    }

    public string MaskValue(string value, PiiType? hintType, JsonMaskingScope? scope)
    {
        if (string.IsNullOrEmpty(value))
            return value;

        if (hintType.HasValue)
        {
            if (scope?.ExcludeTypes != null && scope.ExcludeTypes.Contains(hintType.Value))
                return value;

            if (scope?.IncludeTypes != null && !scope.IncludeTypes.Contains(hintType.Value))
                return value;

            return ApplyMask(value, hintType.Value, scope?.StrategyOverride);
        }

        // Dynamic scanning: find PII matches in the value
        var matches = Scan(value);
        if (matches.Count == 0)
            return value;

        // Apply scope filters on detected matches
        if (scope?.IncludeTypes != null)
        {
            matches = matches.Where(m => scope.IncludeTypes.Contains(m.Type)).ToList();
        }

        if (scope?.ExcludeTypes != null)
        {
            matches = matches.Where(m => !scope.ExcludeTypes.Contains(m.Type)).ToList();
        }

        if (matches.Count == 0)
            return value;

        // Merge/resolve overlapping matches (take highest confidence / longest)
        var nonOverlapping = FilterOverlapping(matches);

        // Replace matches from right to left to preserve indices
        var sb = new StringBuilder(value);
        for (int i = nonOverlapping.Count - 1; i >= 0; i--)
        {
            var match = nonOverlapping[i];
            string masked = ApplyMask(match.RawValue, match.Type, scope?.StrategyOverride);
            sb.Remove(match.Index, match.Length);
            sb.Insert(match.Index, masked);
        }

        return sb.ToString();
    }

    private string ApplyMask(string rawValue, PiiType type, MaskingStrategy? strategyOverride = null)
    {
        var strategy = strategyOverride ?? _options.GetStrategy(type);

        switch (strategy)
        {
            case MaskingStrategy.OneWayRedaction:
                return FormatHelper.CreateMask(type, rawValue, _options.MaskCharacter);

            case MaskingStrategy.FormatPreservingReversible:
                if (_crypto == null)
                    throw new InvalidOperationException("Reversible masking requires a CryptoProvider (such as AES-GCM Master Key) to be configured.");

                string visual = FormatHelper.CreateMask(type, rawValue, _options.MaskCharacter);
                string token = _crypto.Encrypt(rawValue);
                return $"{visual}{FormatHelper.FormatPreservingPrefix}{token}{FormatHelper.FormatPreservingSuffix}";

            case MaskingStrategy.ReversibleCryptoToken:
                if (_crypto == null)
                    throw new InvalidOperationException("Reversible masking requires a CryptoProvider (such as AES-GCM Master Key) to be configured.");

                string directToken = _crypto.Encrypt(rawValue);
                return $"ENC{{{type}:{directToken}}}";

            default:
                return FormatHelper.CreateMask(type, rawValue, _options.MaskCharacter);
        }
    }

    public string UnmaskValue(string maskedValue)
    {
        if (TryUnmaskValue(maskedValue, out string? unmasked))
        {
            return unmasked!;
        }
        return maskedValue;
    }

    public bool TryUnmaskValue(string maskedValue, out string? unmaskedValue)
    {
        unmaskedValue = null;
        if (string.IsNullOrEmpty(maskedValue) || _crypto == null)
            return false;

        // 1. Direct check if whole string is a format-preserving masked token: e.g. 4532-****-****-0366#fp[token]
        int fpTagIndex = maskedValue.IndexOf(FormatHelper.FormatPreservingPrefix, StringComparison.Ordinal);
        if (fpTagIndex >= 0 && maskedValue.EndsWith(FormatHelper.FormatPreservingSuffix))
        {
            int tokenStart = fpTagIndex + FormatHelper.FormatPreservingPrefix.Length;
            int tokenLen = maskedValue.Length - 1 - tokenStart;
            if (tokenLen > 0)
            {
                string cipherToken = maskedValue.Substring(tokenStart, tokenLen);
                if (_crypto.TryDecrypt(cipherToken, out string? plain))
                {
                    unmaskedValue = plain;
                    return true;
                }
            }
        }

        // 2. Embedded replacement across text/sentence
        bool modified = false;
        string result = FormatPreservingPattern().Replace(maskedValue, match =>
        {
            string full = match.Value;
            string cipherToken = match.Groups[1].Value;
            if (_crypto.TryDecrypt(cipherToken, out string? plain))
            {
                modified = true;
                return plain!;
            }
            return match.Value;
        });

        if (modified)
        {
            unmaskedValue = result;
            return true;
        }

        // 3. Check Explicit Enc: ENC{TYPE:token}
        result = ExplicitEncPattern().Replace(maskedValue, match =>
        {
            string cipherToken = match.Groups[2].Value;
            if (_crypto.TryDecrypt(cipherToken, out string? plain))
            {
                modified = true;
                return plain!;
            }
            return match.Value;
        });

        if (modified)
        {
            unmaskedValue = result;
            return true;
        }

        return false;
    }

    public string MaskJson(string json)
    {
        return MaskJson(json, (JsonMaskingScope?)null);
    }

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

        using var inStream = new MemoryStream(Encoding.UTF8.GetBytes(json));
        using var outStream = new MemoryStream();
        MaskJsonStream(inStream, outStream, scope);
        return Encoding.UTF8.GetString(outStream.ToArray());
    }

    public string UnmaskJson(string maskedJson)
    {
        if (string.IsNullOrWhiteSpace(maskedJson))
            return maskedJson;

        using var inStream = new MemoryStream(Encoding.UTF8.GetBytes(maskedJson));
        using var outStream = new MemoryStream();
        UnmaskJsonStream(inStream, outStream);
        return Encoding.UTF8.GetString(outStream.ToArray());
    }

    public void MaskJsonStream(Stream inputUtf8Json, Stream outputUtf8Json)
    {
        ProcessJsonStream(inputUtf8Json, outputUtf8Json, isMasking: true, scope: null);
    }

    public void MaskJsonStream(Stream inputUtf8Json, Stream outputUtf8Json, JsonMaskingScope? scope = null)
    {
        ProcessJsonStream(inputUtf8Json, outputUtf8Json, isMasking: true, scope: scope);
    }

    public void UnmaskJsonStream(Stream inputUtf8Json, Stream outputUtf8Json)
    {
        ProcessJsonStream(inputUtf8Json, outputUtf8Json, isMasking: false, scope: null);
    }

    private void ProcessJsonStream(Stream input, Stream output, bool isMasking, JsonMaskingScope? scope = null)
    {
        // Read stream into byte buffer with support for arbitrary nesting depth
        // We use JsonDocument or chunked streaming
        var readerOptions = new JsonReaderOptions
        {
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip
        };

        var writerOptions = new JsonWriterOptions
        {
            Indented = false
        };

        // For utmost performance and flexibility across arbitrarily nested structures:
        using var memoryStream = new MemoryStream();
        input.CopyTo(memoryStream);
        byte[] inputBytes = memoryStream.ToArray();

        var reader = new Utf8JsonReader(inputBytes, readerOptions);
        using var writer = new Utf8JsonWriter(output, writerOptions);

        string? currentProperty = null;

        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.StartObject:
                    writer.WriteStartObject();
                    break;

                case JsonTokenType.EndObject:
                    writer.WriteEndObject();
                    break;

                case JsonTokenType.StartArray:
                    writer.WriteStartArray();
                    break;

                case JsonTokenType.EndArray:
                    writer.WriteEndArray();
                    break;

                case JsonTokenType.PropertyName:
                    currentProperty = reader.GetString();
                    writer.WritePropertyName(reader.ValueSpan);
                    break;

                case JsonTokenType.String:
                    string val = reader.GetString()!;
                    if (isMasking)
                    {
                        // Check property name exclusions/inclusions if configured
                        bool isExcluded = scope?.ExcludeKeys != null && currentProperty != null && scope.ExcludeKeys.Contains(currentProperty);
                        bool isNotIncluded = scope?.IncludeKeys != null && (currentProperty == null || !scope.IncludeKeys.Contains(currentProperty));

                        if (isExcluded || isNotIncluded)
                        {
                            writer.WriteStringValue(val);
                        }
                        else
                        {
                            string masked = MaskValue(val, hintType: null, scope: scope);
                            writer.WriteStringValue(masked);
                        }
                    }
                    else
                    {
                        if (TryUnmaskValue(val, out string? unmasked))
                        {
                            writer.WriteStringValue(unmasked);
                        }
                        else
                        {
                            writer.WriteStringValue(val);
                        }
                    }
                    break;

                case JsonTokenType.Number:
                    // Check if numeric field is a Credit Card or Aadhaar number formatted as a number
                    if (isMasking && reader.TryGetInt64(out long numVal))
                    {
                        bool isExcluded = scope?.ExcludeKeys != null && currentProperty != null && scope.ExcludeKeys.Contains(currentProperty);
                        if (!isExcluded)
                        {
                            string numStr = numVal.ToString();
                            var matches = Scan(numStr);
                            if (matches.Count > 0)
                            {
                                string masked = MaskValue(numStr, hintType: null, scope: scope);
                                writer.WriteStringValue(masked);
                                break;
                            }
                        }
                    }
                    writer.WriteRawValue(reader.ValueSpan, skipInputValidation: true);
                    break;

                case JsonTokenType.True:
                    writer.WriteBooleanValue(true);
                    break;

                case JsonTokenType.False:
                    writer.WriteBooleanValue(false);
                    break;

                case JsonTokenType.Null:
                    writer.WriteNullValue();
                    break;
            }
        }

        writer.Flush();
    }

    private static List<PiiMatch> FilterOverlapping(IReadOnlyList<PiiMatch> matches)
    {
        var result = new List<PiiMatch>();
        foreach (var m in matches)
        {
            bool overlaps = false;
            for (int i = 0; i < result.Count; i++)
            {
                var existing = result[i];
                if (m.Index < existing.Index + existing.Length && m.Index + m.Length > existing.Index)
                {
                    // Overlap detected: keep the one with higher confidence or greater length
                    if (m.Confidence > existing.Confidence || (m.Confidence == existing.Confidence && m.Length > existing.Length))
                    {
                        result[i] = m;
                    }
                    overlaps = true;
                    break;
                }
            }

            if (!overlaps)
            {
                result.Add(m);
            }
        }

        return result.OrderBy(m => m.Index).ToList();
    }
}
