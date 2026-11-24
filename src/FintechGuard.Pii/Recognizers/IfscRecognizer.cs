using System.Text.RegularExpressions;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes Indian Financial System Code (IFSC) used for NEFT, RTGS, IMPS.
/// Format: 4 letters, 5th character '0', 6 alphanumeric characters.
/// </summary>
public sealed partial class IfscRecognizer : IFastPiiRecognizer
{
    public string Name => "Indian_IFSC";
    public PiiType PiiType => PiiType.Ifsc;

    [GeneratedRegex(@"\b[A-Z]{4}0[A-Z0-9]{6}\b", RegexOptions.NonBacktracking, matchTimeoutMilliseconds: 1000)]
    private static partial Regex IfscPattern();

    public bool MightMatch(in TextFeatures features) =>
        features.Length >= 11 && features.DigitCount >= 1 && features.HasAsciiUpper;

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

        foreach (ValueMatch vm in IfscPattern().EnumerateMatches(text.AsSpan()))
        {
            destination.Add(new PiiMatch
            {
                RawValue = text.Substring(vm.Index, vm.Length),
                Type = PiiType.Ifsc,
                TypeName = nameof(PiiType.Ifsc),
                Confidence = 0.95,
                Index = vm.Index,
                Length = vm.Length
            });
        }
    }
}
