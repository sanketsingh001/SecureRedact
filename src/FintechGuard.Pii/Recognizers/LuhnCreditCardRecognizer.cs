using System.Text.RegularExpressions;
using FintechGuard.Pii.Algorithms;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes Credit and Debit card numbers using pattern matching + Luhn Modulo 10 verification.
/// </summary>
public sealed partial class LuhnCreditCardRecognizer : IPiiRecognizer
{
    public string Name => "CreditCard_Luhn";
    public PiiType PiiType => PiiType.CreditCard;

    [GeneratedRegex(@"\b(?:\d[ -]*?){13,19}\b", RegexOptions.Compiled)]
    private static partial Regex CardPattern();

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            yield break;

        var matches = CardPattern().Matches(text);
        foreach (Match match in matches)
        {
            string candidate = match.Value;
            if (LuhnValidator.ValidateWithSeparators(candidate.AsSpan()))
            {
                yield return new PiiMatch
                {
                    RawValue = candidate,
                    Type = PiiType.CreditCard,
                    TypeName = nameof(PiiType.CreditCard),
                    Confidence = 0.99,
                    Index = match.Index,
                    Length = match.Length
                };
            }
        }
    }
}
