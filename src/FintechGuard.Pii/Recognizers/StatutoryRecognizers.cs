using System.Text.RegularExpressions;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes Indian Driving Licenses.
/// Standard structure: 2 letter state code + 2 digit RTO code + 4 digit year + 7 digits.
/// </summary>
public sealed partial class DrivingLicenseRecognizer : IFastPiiRecognizer
{
    public string Name => "Indian_DrivingLicense";
    public PiiType PiiType => PiiType.DrivingLicense;

    [GeneratedRegex(@"\b[A-Z]{2}[0-9]{2}[ -]?(?:19|20)[0-9]{2}[0-9]{7}\b", RegexOptions.NonBacktracking, matchTimeoutMilliseconds: 1000)]
    private static partial Regex DlPattern();

    public bool MightMatch(in TextFeatures features) =>
        features.Length >= 15 && features.DigitCount >= 13 && features.HasAsciiUpper;

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

        foreach (ValueMatch vm in DlPattern().EnumerateMatches(text.AsSpan()))
        {
            destination.Add(new PiiMatch
            {
                RawValue = text.Substring(vm.Index, vm.Length),
                Type = PiiType.DrivingLicense,
                TypeName = nameof(PiiType.DrivingLicense),
                Confidence = 0.95,
                Index = vm.Index,
                Length = vm.Length
            });
        }
    }
}

/// <summary>
/// Recognizes Indian Voter ID (EPIC - Electors Photo Identity Card).
/// Format: 3 uppercase letters + 7 digits. Base confidence 0.75 (boosted via voter/epic key hint or inline context).
/// </summary>
public sealed partial class VoterIdRecognizer : IFastPiiRecognizer
{
    public string Name => "Indian_VoterId";
    public PiiType PiiType => PiiType.VoterId;

    [GeneratedRegex(@"\b[A-Z]{3}[0-9]{7}\b", RegexOptions.NonBacktracking, matchTimeoutMilliseconds: 1000)]
    private static partial Regex VoterIdPattern();

    private static readonly string[] InlineContextWords = ["voter", "epic", "elector"];

    public bool MightMatch(in TextFeatures features) =>
        features.Length >= 10 && features.DigitCount >= 7 && features.HasAsciiUpper;

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

        ReadOnlySpan<char> span = text.AsSpan();
        foreach (ValueMatch vm in VoterIdPattern().EnumerateMatches(span))
        {
            double conf = IndianMobileRecognizer.HasInlineContext(span, vm.Index, vm.Length, InlineContextWords)
                ? 0.95
                : 0.75;

            destination.Add(new PiiMatch
            {
                RawValue = text.Substring(vm.Index, vm.Length),
                Type = PiiType.VoterId,
                TypeName = nameof(PiiType.VoterId),
                Confidence = conf,
                Index = vm.Index,
                Length = vm.Length
            });
        }
    }
}

/// <summary>
/// Recognizes Indian Passport numbers.
/// Format: 1 uppercase letter (A-Z except Q, X, Z) + 7 digits (1-9 followed by 6 digits).
/// Base confidence 0.75 (boosted via passport key hint or inline context).
/// </summary>
public sealed partial class PassportRecognizer : IFastPiiRecognizer
{
    public string Name => "Indian_Passport";
    public PiiType PiiType => PiiType.IndianPassport;

    [GeneratedRegex(@"\b[A-PR-WY][1-9][0-9]{6}\b", RegexOptions.NonBacktracking, matchTimeoutMilliseconds: 1000)]
    private static partial Regex PassportPattern();

    private static readonly string[] InlineContextWords = ["passport"];

    public bool MightMatch(in TextFeatures features) =>
        features.Length >= 8 && features.DigitCount >= 7 && features.HasAsciiUpper;

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

        ReadOnlySpan<char> span = text.AsSpan();
        foreach (ValueMatch vm in PassportPattern().EnumerateMatches(span))
        {
            double conf = IndianMobileRecognizer.HasInlineContext(span, vm.Index, vm.Length, InlineContextWords)
                ? 0.95
                : 0.75;

            destination.Add(new PiiMatch
            {
                RawValue = text.Substring(vm.Index, vm.Length),
                Type = PiiType.IndianPassport,
                TypeName = nameof(PiiType.IndianPassport),
                Confidence = conf,
                Index = vm.Index,
                Length = vm.Length
            });
        }
    }
}
