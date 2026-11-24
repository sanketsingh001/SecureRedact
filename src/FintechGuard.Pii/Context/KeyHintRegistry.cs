using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Context;

/// <summary>
/// Maintains a registry of JSON key/property name heuristics using identifier-segment boundary matching
/// (snake_case, kebab-case, camelCase, dot/colon/slash delimiters) so substrings like "company" never
/// falsely match "pan", "shipping" never matches "ip", and "account" never matches "count".
/// </summary>
public class KeyHintRegistry
{
    private readonly Dictionary<string, List<(PiiType Type, double BoostDelta)>> _hints = new(StringComparer.OrdinalIgnoreCase);

    public KeyHintRegistry()
    {
        // Indian Identifiers
        AddHint("aadhaar", PiiType.Aadhaar, 0.30);
        AddHint("aadhar", PiiType.Aadhaar, 0.30);
        AddHint("uid", PiiType.Aadhaar, 0.25);
        AddHint("pan", PiiType.Pan, 0.25);
        AddHint("pan_number", PiiType.Pan, 0.30);
        AddHint("gstin", PiiType.Gstin, 0.30);
        AddHint("ifsc", PiiType.Ifsc, 0.25);
        AddHint("upi", PiiType.UpiId, 0.25);
        AddHint("vpa", PiiType.UpiId, 0.25);
        AddHint("passport", PiiType.IndianPassport, 0.20);
        AddHint("voter", PiiType.VoterId, 0.20);
        AddHint("epic", PiiType.VoterId, 0.20);

        // Global Financial
        AddHint("card", PiiType.CreditCard, 0.25);
        AddHint("card_number", PiiType.CreditCard, 0.30);
        AddHint("credit_card", PiiType.CreditCard, 0.30);
        AddHint("debit_card", PiiType.CreditCard, 0.30);
        AddHint("iban", PiiType.Iban, 0.30);
        AddHint("ssn", PiiType.UsSsn, 0.30);

        // PII Contact & Demographics
        AddHint("email", PiiType.Email, 0.20);
        AddHint("ip", PiiType.IpAddress, 0.20);
        AddHint("ip_address", PiiType.IpAddress, 0.20);
        AddHint("phone", PiiType.IndianMobile, 0.20);
        AddHint("phone", PiiType.GenericPhone, 0.20);
        AddHint("mobile", PiiType.IndianMobile, 0.20);
        AddHint("mobile", PiiType.GenericPhone, 0.20);
        AddHint("contact", PiiType.IndianMobile, 0.15);
        AddHint("contact", PiiType.GenericPhone, 0.15);
        AddHint("dob", PiiType.DateOfBirth, 0.35);
        AddHint("birth", PiiType.DateOfBirth, 0.35);
        AddHint("date_of_birth", PiiType.DateOfBirth, 0.35);

        // Unstructured / NER
        AddHint("name", PiiType.PersonName, 0.20);
        AddHint("customer_name", PiiType.PersonName, 0.25);
        AddHint("holder", PiiType.PersonName, 0.20);
        AddHint("beneficiary", PiiType.PersonName, 0.20);
        AddHint("address", PiiType.Address, 0.20);
        AddHint("street", PiiType.Address, 0.20);
        AddHint("residence", PiiType.Address, 0.20);

        // Penalize numeric/identifier keys commonly mistaken for PII
        AddNegativeAll("quantity", -0.50);
        AddNegativeAll("amount", -0.50);
        AddNegativeAll("count", -0.50);
        AddNegativeAll("timestamp", -0.45);
        AddNegativeAll("transaction_id", -0.40);
        AddNegativeAll("invoice_number", -0.40);
        AddNegativeAll("order_id", -0.40);
        AddNegativeAll("reference_id", -0.40);
        AddNegativeAll("id", -0.30);
    }

    private void AddNegativeAll(string key, double delta)
    {
        AddHint(key, PiiType.CreditCard, delta);
        AddHint(key, PiiType.IndianMobile, delta);
        AddHint(key, PiiType.IndianPassport, delta);
        AddHint(key, PiiType.VoterId, delta);
    }

    /// <summary>
    /// Adds or updates a hint for a specific key and PII type.
    /// </summary>
    public void AddHint(string key, PiiType targetType, double boostDelta)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        if (!_hints.TryGetValue(key, out var list))
        {
            list = new List<(PiiType, double)>(1);
            _hints[key] = list;
        }

        for (int i = 0; i < list.Count; i++)
        {
            if (list[i].Type == targetType)
            {
                list[i] = (targetType, boostDelta);
                return;
            }
        }

        list.Add((targetType, boostDelta));
    }

    /// <summary>
    /// Checks whether <paramref name="propertyName"/> matches any of the configured target keys
    /// either exactly or on identifier-segment boundaries.
    /// </summary>
    internal static bool MatchesAnyTargetKey(string? propertyName, string[] targetKeys)
    {
        if (string.IsNullOrWhiteSpace(propertyName) || targetKeys.Length == 0)
            return false;

        for (int i = 0; i < targetKeys.Length; i++)
        {
            if (MatchesIdentifierBoundary(propertyName, targetKeys[i]))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Retrieves the confidence boost delta for a given property name and detected PII type.
    /// </summary>
    public double GetBoost(string? propertyName, PiiType detectedType)
    {
        if (string.IsNullOrWhiteSpace(propertyName))
            return 0.0;

        // 1. Exact full-key match takes highest precedence
        if (TryGetDelta(_hints, propertyName, detectedType, out double exactDelta))
            return exactDelta;

        // 2. Tokenize propertyName on delimiters and camelCase boundaries using stackalloc ranges (zero heap allocation)
        Span<int> starts = stackalloc int[16];
        Span<int> lengths = stackalloc int[16];
        int segCount = ExtractSegments(propertyName.AsSpan(), starts, lengths);

        if (segCount == 0)
            return 0.0;

        ReadOnlySpan<char> propSpan = propertyName.AsSpan();
        Span<char> pairBuf = stackalloc char[64];

        // 2a. Check consecutive segment pairs (e.g., "card_number", "date_of_birth", "transaction_id")
        bool hasPositivePair = false;
        double bestPositivePair = 0.0;
        bool hasNegativePair = false;
        double bestNegativePair = 0.0;

        for (int i = 0; i + 1 < segCount; i++)
        {
            var s1 = propSpan.Slice(starts[i], lengths[i]);
            var s2 = propSpan.Slice(starts[i + 1], lengths[i + 1]);
            int pairLen = s1.Length + 1 + s2.Length;
            if (pairLen <= pairBuf.Length)
            {
                s1.CopyTo(pairBuf);
                pairBuf[s1.Length] = '_';
                s2.CopyTo(pairBuf.Slice(s1.Length + 1));
                string pairKey = pairBuf[..pairLen].ToString();

                if (TryGetDelta(_hints, pairKey, detectedType, out double delta))
                {
                    if (delta >= 0)
                    {
                        hasPositivePair = true;
                        if (delta > bestPositivePair) bestPositivePair = delta;
                    }
                    else
                    {
                        hasNegativePair = true;
                        if (delta < bestNegativePair) bestNegativePair = delta;
                    }
                }
            }
        }

        if (hasPositivePair)
            return bestPositivePair;
        if (hasNegativePair)
            return bestNegativePair;

        // 2b. Check individual segments (e.g. "customer_pan" -> ["customer", "pan"])
        bool hasPositiveSeg = false;
        double bestPositiveSeg = 0.0;
        bool hasNegativeSeg = false;
        double bestNegativeSeg = 0.0;

        for (int i = 0; i < segCount; i++)
        {
            string seg = propertyName.Substring(starts[i], lengths[i]);
            if (TryGetDelta(_hints, seg, detectedType, out double delta))
            {
                if (delta >= 0)
                {
                    hasPositiveSeg = true;
                    if (delta > bestPositiveSeg) bestPositiveSeg = delta;
                }
                else
                {
                    hasNegativeSeg = true;
                    if (delta < bestNegativeSeg) bestNegativeSeg = delta;
                }
            }
        }

        if (hasPositiveSeg)
            return bestPositiveSeg;
        if (hasNegativeSeg)
            return bestNegativeSeg;

        return 0.0;
    }

    private static bool TryGetDelta(
        Dictionary<string, List<(PiiType Type, double BoostDelta)>> hints,
        string key,
        PiiType detectedType,
        out double delta)
    {
        if (hints.TryGetValue(key, out var list))
        {
            for (int i = 0; i < list.Count; i++)
            {
                if (list[i].Type == detectedType)
                {
                    delta = list[i].BoostDelta;
                    return true;
                }
            }
        }

        delta = 0.0;
        return false;
    }

    private static bool MatchesIdentifierBoundary(string propertyName, string targetKey)
    {
        if (string.Equals(propertyName, targetKey, StringComparison.OrdinalIgnoreCase))
            return true;

        Span<int> starts = stackalloc int[16];
        Span<int> lengths = stackalloc int[16];
        int segCount = ExtractSegments(propertyName.AsSpan(), starts, lengths);
        ReadOnlySpan<char> propSpan = propertyName.AsSpan();
        ReadOnlySpan<char> targetSpan = targetKey.AsSpan();

        for (int i = 0; i < segCount; i++)
        {
            if (propSpan.Slice(starts[i], lengths[i]).Equals(targetSpan, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        Span<char> pairBuf = stackalloc char[64];
        for (int i = 0; i + 1 < segCount; i++)
        {
            var s1 = propSpan.Slice(starts[i], lengths[i]);
            var s2 = propSpan.Slice(starts[i + 1], lengths[i + 1]);
            int pairLen = s1.Length + 1 + s2.Length;
            if (pairLen <= pairBuf.Length)
            {
                s1.CopyTo(pairBuf);
                pairBuf[s1.Length] = '_';
                s2.CopyTo(pairBuf.Slice(s1.Length + 1));
                if (((ReadOnlySpan<char>)pairBuf[..pairLen]).Equals(targetSpan, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        return false;
    }

    private static int ExtractSegments(ReadOnlySpan<char> text, Span<int> starts, Span<int> lengths)
    {
        int count = 0;
        int len = text.Length;
        int segStart = -1;

        for (int i = 0; i < len && count < starts.Length; i++)
        {
            char c = text[i];
            bool isSep = c == '_' || c == '-' || c == '.' || c == ':' || c == '/' || char.IsWhiteSpace(c);

            if (isSep)
            {
                if (segStart >= 0)
                {
                    starts[count] = segStart;
                    lengths[count] = i - segStart;
                    count++;
                    segStart = -1;
                }
                continue;
            }

            if (segStart < 0)
            {
                segStart = i;
                continue;
            }

            // camelCase boundary: lower -> upper, or digit <-> letter transitions
            char prev = text[i - 1];
            bool camelSplit = char.IsLower(prev) && char.IsUpper(c);
            if (camelSplit)
            {
                starts[count] = segStart;
                lengths[count] = i - segStart;
                count++;
                segStart = i;
            }
        }

        if (segStart >= 0 && count < starts.Length)
        {
            starts[count] = segStart;
            lengths[count] = len - segStart;
            count++;
        }

        return count;
    }
}
