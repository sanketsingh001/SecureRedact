using System.Text.RegularExpressions;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes Indian Financial System Code (IFSC) used for NEFT, RTGS, IMPS.
/// Format: 4 letters, 5th character '0', 6 alphanumeric characters.
/// </summary>
public sealed partial class IfscRecognizer : IPiiRecognizer
{
    public string Name => "Indian_IFSC";
    public PiiType PiiType => PiiType.Ifsc;

    [GeneratedRegex(@"\b[A-Z]{4}0[A-Z0-9]{6}\b", RegexOptions.Compiled)]
    private static partial Regex IfscPattern();

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            yield break;

        var matches = IfscPattern().Matches(text);
        foreach (Match match in matches)
        {
            yield return new PiiMatch
            {
                RawValue = match.Value,
                Type = PiiType.Ifsc,
                TypeName = nameof(PiiType.Ifsc),
                Confidence = 0.95,
                Index = match.Index,
                Length = match.Length
            };
        }
    }
}
