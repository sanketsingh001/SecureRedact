using System.Text.RegularExpressions;
using FintechGuard.Pii.Algorithms;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes Indian GSTIN (Goods and Services Tax Identification Number).
/// </summary>
public sealed partial class GstinRecognizer : IPiiRecognizer
{
    public string Name => "Indian_GSTIN";
    public PiiType PiiType => PiiType.Gstin;

    [GeneratedRegex(@"\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b", RegexOptions.Compiled)]
    private static partial Regex GstinPattern();

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            yield break;

        var matches = GstinPattern().Matches(text);
        foreach (Match match in matches)
        {
            if (GstinValidator.Validate(match.ValueSpan))
            {
                yield return new PiiMatch
                {
                    RawValue = match.Value,
                    Type = PiiType.Gstin,
                    TypeName = nameof(PiiType.Gstin),
                    Confidence = 0.99,
                    Index = match.Index,
                    Length = match.Length
                };
            }
        }
    }
}
