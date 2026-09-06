using System.Text.RegularExpressions;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes Indian Driving Licenses.
/// Standard structure: 2 letter state code + 2 digit RTO code + 4 digit year + 7 digits.
/// </summary>
public sealed partial class DrivingLicenseRecognizer : IPiiRecognizer
{
    public string Name => "Indian_DrivingLicense";
    public PiiType PiiType => PiiType.DrivingLicense;

    [GeneratedRegex(@"\b[A-Z]{2}[0-9]{2}[ -]?(?:19|20)[0-9]{2}[0-9]{7}\b", RegexOptions.Compiled)]
    private static partial Regex DlPattern();

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            yield break;

        var matches = DlPattern().Matches(text);
        foreach (Match match in matches)
        {
            yield return new PiiMatch
            {
                RawValue = match.Value,
                Type = PiiType.DrivingLicense,
                TypeName = nameof(PiiType.DrivingLicense),
                Confidence = 0.95,
                Index = match.Index,
                Length = match.Length
            };
        }
    }
}

/// <summary>
/// Recognizes Indian Voter ID (EPIC - Electors Photo Identity Card).
/// Format: 3 letters + 7 digits.
/// </summary>
public sealed partial class VoterIdRecognizer : IPiiRecognizer
{
    public string Name => "Indian_VoterId";
    public PiiType PiiType => PiiType.VoterId;

    [GeneratedRegex(@"\b[A-Z]{3}[0-9]{7}\b", RegexOptions.Compiled)]
    private static partial Regex VoterIdPattern();

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            yield break;

        var matches = VoterIdPattern().Matches(text);
        foreach (Match match in matches)
        {
            yield return new PiiMatch
            {
                RawValue = match.Value,
                Type = PiiType.VoterId,
                TypeName = nameof(PiiType.VoterId),
                Confidence = 0.85,
                Index = match.Index,
                Length = match.Length
            };
        }
    }
}

/// <summary>
/// Recognizes Indian Passport numbers.
/// Format: 1 letter (A-Z except Q, X, Z) + 7 digits.
/// </summary>
public sealed partial class PassportRecognizer : IPiiRecognizer
{
    public string Name => "Indian_Passport";
    public PiiType PiiType => PiiType.IndianPassport;

    [GeneratedRegex(@"\b[A-PR-WYa-pr-wy][1-9][0-9]{6}\b", RegexOptions.Compiled)]
    private static partial Regex PassportPattern();

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            yield break;

        var matches = PassportPattern().Matches(text);
        foreach (Match match in matches)
        {
            yield return new PiiMatch
            {
                RawValue = match.Value,
                Type = PiiType.IndianPassport,
                TypeName = nameof(PiiType.IndianPassport),
                Confidence = 0.85,
                Index = match.Index,
                Length = match.Length
            };
        }
    }
}
