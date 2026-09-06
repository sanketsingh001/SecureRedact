using System.Text.RegularExpressions;
using FintechGuard.Pii.Algorithms;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes Indian Income Tax Permanent Account Number (PAN).
/// </summary>
public sealed partial class PanRecognizer : IPiiRecognizer
{
    public string Name => "Indian_PAN";
    public PiiType PiiType => PiiType.Pan;

    [GeneratedRegex(@"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b", RegexOptions.Compiled)]
    private static partial Regex PanPattern();

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            yield break;

        var matches = PanPattern().Matches(text);
        foreach (Match match in matches)
        {
            if (PanValidator.Validate(match.ValueSpan))
            {
                yield return new PiiMatch
                {
                    RawValue = match.Value,
                    Type = PiiType.Pan,
                    TypeName = nameof(PiiType.Pan),
                    Confidence = 0.98,
                    Index = match.Index,
                    Length = match.Length
                };
            }
        }
    }
}
