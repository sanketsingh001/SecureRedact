using System.Text.RegularExpressions;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Allows consumers to register custom patterns, fintech entity codes, loan IDs, or custom rules.
/// </summary>
public sealed class CustomPatternRecognizer : IPiiRecognizer
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
        double confidence = 0.95)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(pattern);

        Name = name;
        _regex = new Regex(pattern, options);
        PiiType = piiType;
        CustomTypeName = customTypeName ?? name;
        _validator = validator;
        Confidence = confidence;
    }

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            yield break;

        var matches = _regex.Matches(text);
        foreach (Match match in matches)
        {
            if (_validator == null || _validator(match.Value))
            {
                yield return new PiiMatch
                {
                    RawValue = match.Value,
                    Type = PiiType,
                    TypeName = CustomTypeName,
                    Confidence = Confidence,
                    Index = match.Index,
                    Length = match.Length
                };
            }
        }
    }
}
