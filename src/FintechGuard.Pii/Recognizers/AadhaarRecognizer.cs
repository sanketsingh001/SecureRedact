using System.Text.RegularExpressions;
using FintechGuard.Pii.Algorithms;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes 12-digit Indian Aadhaar numbers using UIDAI Verhoeff algorithm.
/// </summary>
public sealed partial class AadhaarRecognizer : IFastPiiRecognizer
{
    public string Name => "Indian_Aadhaar";
    public PiiType PiiType => PiiType.Aadhaar;

    [GeneratedRegex(@"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b", RegexOptions.NonBacktracking, matchTimeoutMilliseconds: 1000)]
    private static partial Regex AadhaarPattern();

    public bool MightMatch(in TextFeatures features) => features.DigitCount >= 12;

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

        Span<char> digits = stackalloc char[12];
        foreach (ValueMatch vm in AadhaarPattern().EnumerateMatches(text.AsSpan()))
        {
            ReadOnlySpan<char> candidateSpan = text.AsSpan(vm.Index, vm.Length);
            int count = 0;

            for (int i = 0; i < candidateSpan.Length; i++)
            {
                char c = candidateSpan[i];
                if (char.IsDigit(c))
                {
                    if (count < 12)
                        digits[count++] = c;
                }
            }

            if (count == 12 && VerhoeffValidator.Validate(digits))
            {
                destination.Add(new PiiMatch
                {
                    RawValue = text.Substring(vm.Index, vm.Length),
                    Type = PiiType.Aadhaar,
                    TypeName = nameof(PiiType.Aadhaar),
                    Confidence = 0.99,
                    Index = vm.Index,
                    Length = vm.Length
                });
            }
        }
    }
}
