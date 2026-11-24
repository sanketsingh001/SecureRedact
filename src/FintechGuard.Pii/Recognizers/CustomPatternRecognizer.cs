using System.Text.RegularExpressions;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Allows consumers to register custom patterns, fintech entity codes, loan IDs, or custom rules
/// with an enforced ReDoS match timeout.
/// </summary>
public sealed class CustomPatternRecognizer : IFastPiiRecognizer
{
    private readonly Regex _regex;
    private readonly Func<string, bool>? _validator;

    public string Name { get; }
    public PiiType PiiType { get; }
    public string CustomTypeName { get; }
    public double Confidence { get; }

    public CustomPatternRecognizer(
        string name,
        string pattern,
        PiiType piiType = PiiType.Custom,
        string? customTypeName = null,
        Func<string, bool>? validator = null,
        RegexOptions options = RegexOptions.Compiled,
        double confidence = 0.95,
        TimeSpan? matchTimeout = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(pattern);

        Name = name;
        _regex = new Regex(pattern, options, matchTimeout ?? TimeSpan.FromMilliseconds(100));
        PiiType = piiType;
        CustomTypeName = customTypeName ?? name;
        _validator = validator;
        Confidence = confidence;
    }

    public bool MightMatch(in TextFeatures features) => features.Length > 0;

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Array.Empty<PiiMatch>();

        var list = new List<PiiMatch>();
        var ctx = new RecognitionContext();
        RecognizeInto(text, in ctx, TextFeatures.Analyze(text.AsSpan()), list);
        return list;
    }

    public void RecognizeInto(string text, in RecognitionContext context, in TextFeatures features, List<PiiMatch> destination)
    {
        if (string.IsNullOrWhiteSpace(text))
            return;

        var matches = _regex.Matches(text);
        foreach (Match match in matches)
        {
            if (_validator == null || _validator(match.Value))
            {
                destination.Add(new PiiMatch
                {
                    RawValue = match.Value,
                    Type = PiiType,
                    TypeName = CustomTypeName,
                    Confidence = Confidence,
                    Index = match.Index,
                    Length = match.Length
                });
            }
        }
    }
}
