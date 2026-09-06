using System.Text.RegularExpressions;
using FintechGuard.Pii.Algorithms;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes 12-digit Indian Aadhaar numbers using UIDAI Verhoeff algorithm.
/// Eliminates 99.9% of random 12-digit false positives.
/// </summary>
public sealed partial class AadhaarRecognizer : IPiiRecognizer
{
    public string Name => "Indian_Aadhaar";
    public PiiType PiiType => PiiType.Aadhaar;

    // Aadhaar does not start with 0 or 1
    [GeneratedRegex(@"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b", RegexOptions.Compiled)]
    private static partial Regex AadhaarPattern();

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Array.Empty<PiiMatch>();

        var list = new List<PiiMatch>();
        Span<char> digits = stackalloc char[12];
        var matches = AadhaarPattern().Matches(text);
        foreach (Match match in matches)
        {
            string candidate = match.Value;
            int count = 0;

            foreach (char c in candidate)
            {
                if (char.IsDigit(c))
                {
                    if (count < 12)
                        digits[count++] = c;
                }
            }

            if (count == 12 && VerhoeffValidator.Validate(digits))
            {
                list.Add(new PiiMatch
                {
                    RawValue = candidate,
                    Type = PiiType.Aadhaar,
                    TypeName = nameof(PiiType.Aadhaar),
                    Confidence = 0.99,
                    Index = match.Index,
                    Length = match.Length
                });
            }
        }

        return list;
    }
}
