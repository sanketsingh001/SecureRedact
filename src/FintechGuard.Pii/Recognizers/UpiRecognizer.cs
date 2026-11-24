using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes Indian Unified Payments Interface (UPI) Virtual Payment Addresses (VPA)
/// using a strict O(n) @-anchored scanner and verified NPCI PSP handle lookup (no backtracking or DFA size limits).
/// </summary>
public sealed class UpiRecognizer : IFastPiiRecognizer
{
    public string Name => "Indian_UPI";
    public PiiType PiiType => PiiType.UpiId;

    private static readonly HashSet<string> KnownHandles = new(StringComparer.OrdinalIgnoreCase)
    {
        "okhdfcbank", "okaxis", "oksbi", "okicici", "paytm", "ptyes", "ptaxis", "pthdfc", "ptsbi",
        "ybl", "ibl", "axl", "upi", "apl", "yapl", "rapl", "icici", "hdfcbank", "sbi", "kotak",
        "barodampay", "waaxis", "wahdfcbank", "waicici", "wasbi", "idfcbank", "fbl", "indus",
        "federal", "jio", "airtel", "freecharge", "slice", "jupiteraxis", "naviaxis", "pingpay",
        "postbank", "cnrb", "pnb", "uboi", "mahb", "yesbank"
    };

    public bool MightMatch(in TextFeatures features) => features.HasAt && features.Length >= 5;

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
        int cursor = 0;

        while (cursor < span.Length)
        {
            int rel = span[cursor..].IndexOf('@');
            if (rel < 0)
                break;

            int atIdx = cursor + rel;

            int userStart = atIdx;
            while (userStart > 0 && IsUpiUserChar(span[userStart - 1]))
                userStart--;

            while (userStart < atIdx && (span[userStart] == '.' || span[userStart] == '-'))
                userStart++;

            int userLen = atIdx - userStart;
            bool validLeft = userLen >= 2 && userLen <= 64 &&
                (userStart == 0 || !(char.IsLetterOrDigit(span[userStart - 1]) || span[userStart - 1] == '_'));

            if (!validLeft)
            {
                cursor = atIdx + 1;
                continue;
            }

            int handleEnd = atIdx + 1;
            while (handleEnd < span.Length && char.IsAsciiLetter(span[handleEnd]))
                handleEnd++;

            int handleLen = handleEnd - (atIdx + 1);
            bool validRight = handleLen >= 2 && handleLen <= 24 &&
                (handleEnd == span.Length || !(char.IsLetterOrDigit(span[handleEnd]) || span[handleEnd] == '_'));
            bool looksLikeDomain = handleEnd + 1 < span.Length && span[handleEnd] == '.' && char.IsAsciiLetter(span[handleEnd + 1]);

            if (validRight && !looksLikeDomain && KnownHandles.Contains(text.Substring(atIdx + 1, handleLen)))
            {
                int totalLen = handleEnd - userStart;
                destination.Add(new PiiMatch
                {
                    RawValue = text.Substring(userStart, totalLen),
                    Type = PiiType.UpiId,
                    TypeName = nameof(PiiType.UpiId),
                    Confidence = 0.98,
                    Index = userStart,
                    Length = totalLen
                });
                cursor = handleEnd;
            }
            else
            {
                cursor = Math.Max(atIdx + 1, handleEnd);
            }
        }
    }

    private static bool IsUpiUserChar(char c) =>
        char.IsAsciiLetterOrDigit(c) || c == '.' || c == '-' || c == '_';
}
