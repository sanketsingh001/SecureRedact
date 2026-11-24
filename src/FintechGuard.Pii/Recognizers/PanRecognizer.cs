using System.Text.RegularExpressions;
using FintechGuard.Pii.Algorithms;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes Indian Income Tax Permanent Account Number (PAN).
/// </summary>
public sealed partial class PanRecognizer : IFastPiiRecognizer
{
    public string Name => "Indian_PAN";
    public PiiType PiiType => PiiType.Pan;

    [GeneratedRegex(@"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b", RegexOptions.NonBacktracking, matchTimeoutMilliseconds: 1000)]
    private static partial Regex PanPattern();

    public bool MightMatch(in TextFeatures features) =>
        features.Length >= 10 && features.DigitCount >= 4 && features.HasAsciiUpper;

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

        foreach (ValueMatch vm in PanPattern().EnumerateMatches(text.AsSpan()))
        {
            if (PanValidator.Validate(text.AsSpan(vm.Index, vm.Length)))
            {
                destination.Add(new PiiMatch
                {
                    RawValue = text.Substring(vm.Index, vm.Length),
                    Type = PiiType.Pan,
                    TypeName = nameof(PiiType.Pan),
                    Confidence = 0.98,
                    Index = vm.Index,
                    Length = vm.Length
                });
            }
        }
    }
}
