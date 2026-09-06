using System.Text.RegularExpressions;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes Indian Mobile Numbers (+91 or 0 prefix, starting with 6, 7, 8, 9).
/// </summary>
public sealed partial class IndianMobileRecognizer : IPiiRecognizer
{
    public string Name => "Indian_Mobile";
    public PiiType PiiType => PiiType.IndianMobile;

    [GeneratedRegex(@"(?<!\d)(?:\+91[- ]?|0)?[6-9]\d{9}(?!\d)", RegexOptions.Compiled)]
    private static partial Regex MobilePattern();

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            yield break;

        var matches = MobilePattern().Matches(text);
        foreach (Match match in matches)
        {
            yield return new PiiMatch
            {
                RawValue = match.Value,
                Type = PiiType.IndianMobile,
                TypeName = nameof(PiiType.IndianMobile),
                Confidence = 0.90,
                Index = match.Index,
                Length = match.Length
            };
        }
    }
}
