using FintechGuard.Pii.Algorithms;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes Credit and Debit card numbers using a linear O(n) digit-run scanner + IIN/BIN range check + Luhn Mod-10 verification.
/// Eliminates regex backtracking (ReDoS) and cuts random 16-digit false positives dramatically.
/// </summary>
public sealed class LuhnCreditCardRecognizer : IFastPiiRecognizer
{
    public string Name => "CreditCard_Luhn";
    public PiiType PiiType => PiiType.CreditCard;

    public bool MightMatch(in TextFeatures features) => features.DigitCount >= 13;

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Array.Empty<PiiMatch>();

        var features = TextFeatures.Analyze(text.AsSpan());
        if (!MightMatch(in features))
            return Array.Empty<PiiMatch>();

        var list = new List<PiiMatch>(2);
        var ctx = new RecognitionContext();
        RecognizeInto(text, in ctx, in features, list);
        return list;
    }

    public void RecognizeInto(string text, in RecognitionContext context, in TextFeatures features, List<PiiMatch> destination)
    {
        if (!MightMatch(in features) || string.IsNullOrWhiteSpace(text))
            return;

        ReadOnlySpan<char> span = text.AsSpan();
        Span<char> digits = stackalloc char[20];
        int len = span.Length;
        int i = 0;

        while (i < len)
        {
            char c = span[i];
            if ((uint)(c - '0') > 9)
            {
                i++;
                continue;
            }

            if (i > 0 && IsWordChar(span[i - 1]))
            {
                while (i < len && IsWordChar(span[i])) i++;
                continue;
            }

            int start = i;
            int digitCount = 0;
            int groupDigits = 0;
            char sepChar = '\0';
            bool lastWasSep = false;

            int bestEnd = -1;
            int bestDigitCount = 0;
            int j = i;

            while (j < len)
            {
                char ch = span[j];
                if ((uint)(ch - '0') <= 9)
                {
                    if (digitCount >= 19)
                    {
                        digitCount++;
                        break;
                    }

                    digits[digitCount++] = ch;
                    groupDigits++;
                    lastWasSep = false;
                    int candidateEnd = j + 1;

                    if (digitCount >= 13 &&
                        (candidateEnd == len || !IsWordChar(span[candidateEnd])))
                    {
                        // Separated formats must have >= 3 digits in the trailing group
                        if (sepChar == '\0' || groupDigits >= 3)
                        {
                            ReadOnlySpan<char> slice = digits[..digitCount];
                            if (LuhnValidator.IsValidCardIin(slice) && LuhnValidator.Validate(slice))
                            {
                                bestEnd = candidateEnd;
                                bestDigitCount = digitCount;
                            }
                        }
                    }

                    j++;
                }
                else if ((ch == ' ' || ch == '-') && !lastWasSep && digitCount > 0)
                {
                    // First group before a separator must have >= 4 digits; subsequent groups >= 3
                    if (sepChar == '\0')
                    {
                        if (groupDigits < 4)
                            break;
                        sepChar = ch;
                    }
                    else if (ch != sepChar || groupDigits < 3)
                    {
                        break;
                    }

                    lastWasSep = true;
                    groupDigits = 0;
                    j++;
                }
                else
                {
                    break;
                }
            }

            // Reject if contiguous digits ran past 19 without a non-word boundary
            if (digitCount > 19 && sepChar == '\0')
            {
                bestEnd = -1;
            }

            if (bestEnd > start)
            {
                destination.Add(new PiiMatch
                {
                    RawValue = text.Substring(start, bestEnd - start),
                    Type = PiiType.CreditCard,
                    TypeName = nameof(PiiType.CreditCard),
                    Confidence = 0.99,
                    Index = start,
                    Length = bestEnd - start
                });
                i = bestEnd;
            }
            else
            {
                while (i < len && (uint)(span[i] - '0') <= 9) i++;
                if (i == start) i++;
            }
        }
    }

    private static bool IsWordChar(char c) => char.IsLetterOrDigit(c) || c == '_';
}
