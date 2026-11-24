using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes Indian Mobile Numbers (+91, 0 prefix, or context-gated 10-digit numbers starting with 6-9)
/// using a zero-backtracking linear scanner.
/// </summary>
public sealed class IndianMobileRecognizer : IFastPiiRecognizer
{
    public string Name => "Indian_Mobile";
    public PiiType PiiType => PiiType.IndianMobile;

    private static readonly string[] InlineContextWords =
        ["mobile", "phone", "mob", "contact", "whatsapp", "call", "tel"];

    public bool MightMatch(in TextFeatures features) => features.DigitCount >= 10;

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Array.Empty<PiiMatch>();

        var features = TextFeatures.Analyze(text.AsSpan());
        if (!MightMatch(in features))
            return Array.Empty<PiiMatch>();

        var list = new List<PiiMatch>(1);
        var ctx = new RecognitionContext();
        RecognizeInto(text, in ctx, in features, list);
        return list;
    }

    public void RecognizeInto(string text, in RecognitionContext context, in TextFeatures features, List<PiiMatch> destination)
    {
        if (!MightMatch(in features) || string.IsNullOrWhiteSpace(text))
            return;

        ReadOnlySpan<char> span = text.AsSpan();
        int len = span.Length;
        int i = 0;

        while (i < len)
        {
            // Case 1: +91 prefix
            if (span[i] == '+' && i + 12 < len && span[i + 1] == '9' && span[i + 2] == '1')
            {
                if (i == 0 || !char.IsDigit(span[i - 1]))
                {
                    int p = i + 3;
                    if (p < len && (span[p] == '-' || span[p] == ' '))
                        p++;

                    if (p + 10 <= len && TryRead10DigitMobile(span, p) &&
                        (p + 10 == len || !char.IsDigit(span[p + 10])))
                    {
                        int matchLen = (p + 10) - i;
                        destination.Add(new PiiMatch
                        {
                            RawValue = text.Substring(i, matchLen),
                            Type = PiiType.IndianMobile,
                            TypeName = nameof(PiiType.IndianMobile),
                            Confidence = 0.95,
                            Index = i,
                            Length = matchLen
                        });
                        i = p + 10;
                        continue;
                    }
                }
            }

            // Case 2: 0-prefixed 11-digit or bare 10-digit [6-9]\d{9}
            if ((uint)(span[i] - '0') <= 9)
            {
                if (i > 0 && (char.IsDigit(span[i - 1]) || span[i - 1] == '+'))
                {
                    while (i < len && char.IsDigit(span[i])) i++;
                    continue;
                }

                // 0 + [6-9]\d{9}
                if (span[i] == '0' && i + 11 <= len && TryRead10DigitMobile(span, i + 1) &&
                    (i + 11 == len || !char.IsDigit(span[i + 11])))
                {
                    destination.Add(new PiiMatch
                    {
                        RawValue = text.Substring(i, 11),
                        Type = PiiType.IndianMobile,
                        TypeName = nameof(PiiType.IndianMobile),
                        Confidence = 0.85,
                        Index = i,
                        Length = 11
                    });
                    i += 11;
                    continue;
                }

                // Bare 10-digit [6-9]\d{9}
                if (i + 10 <= len && TryRead10DigitMobile(span, i) &&
                    (i + 10 == len || !char.IsDigit(span[i + 10])))
                {
                    // Check for adjacent word/dash (avoid matching inside IDs like ABC9876543210)
                    bool leftWord = i > 0 && (char.IsLetter(span[i - 1]) || span[i - 1] == '_' || span[i - 1] == '-');
                    bool rightWord = i + 10 < len && (char.IsLetter(span[i + 10]) || span[i + 10] == '_');
                    if (!leftWord && !rightWord)
                    {
                        double conf = HasInlineContext(span, i, 10, InlineContextWords) ? 0.90 : 0.75;
                        destination.Add(new PiiMatch
                        {
                            RawValue = text.Substring(i, 10),
                            Type = PiiType.IndianMobile,
                            TypeName = nameof(PiiType.IndianMobile),
                            Confidence = conf,
                            Index = i,
                            Length = 10
                        });
                        i += 10;
                        continue;
                    }
                }

                while (i < len && char.IsDigit(span[i])) i++;
                continue;
            }

            i++;
        }
    }

    private static bool TryRead10DigitMobile(ReadOnlySpan<char> span, int offset)
    {
        char first = span[offset];
        if (first < '6' || first > '9')
            return false;

        for (int k = 1; k < 10; k++)
        {
            char c = span[offset + k];
            if (c < '0' || c > '9')
                return false;
        }
        return true;
    }

    internal static bool HasInlineContext(ReadOnlySpan<char> span, int matchIndex, int matchLength, string[] keywords)
    {
        int ctxStart = Math.Max(0, matchIndex - 24);
        int ctxEnd = Math.Min(span.Length, matchIndex + matchLength + 24);
        ReadOnlySpan<char> window = span.Slice(ctxStart, ctxEnd - ctxStart);

        for (int i = 0; i < keywords.Length; i++)
        {
            if (window.Contains(keywords[i].AsSpan(), StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
