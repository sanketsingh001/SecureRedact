using System.Text.RegularExpressions;
using FintechGuard.Pii.Algorithms;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes Indian GSTIN (Goods and Services Tax Identification Number) with Modulo-36 checksum validation.
/// </summary>
public sealed partial class GstinRecognizer : IFastPiiRecognizer
{
    public string Name => "Indian_GSTIN";
    public PiiType PiiType => PiiType.Gstin;

    [GeneratedRegex(@"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b", RegexOptions.NonBacktracking, matchTimeoutMilliseconds: 1000)]
    private static partial Regex GstinPattern();

    public bool MightMatch(in TextFeatures features) =>
        features.Length >= 15 && features.DigitCount >= 6 && features.HasAsciiUpper;

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

        foreach (ValueMatch vm in GstinPattern().EnumerateMatches(text.AsSpan()))
        {
            if (GstinValidator.Validate(text.AsSpan(vm.Index, vm.Length)))
            {
                destination.Add(new PiiMatch
                {
                    RawValue = text.Substring(vm.Index, vm.Length),
                    Type = PiiType.Gstin,
                    TypeName = nameof(PiiType.Gstin),
                    Confidence = 0.99,
                    Index = vm.Index,
                    Length = vm.Length
                });
            }
        }
    }
}
