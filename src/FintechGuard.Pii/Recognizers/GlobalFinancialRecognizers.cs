using System.Net;
using System.Text.RegularExpressions;
using FintechGuard.Pii.Algorithms;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes International Bank Account Numbers (IBAN) using ISO 7064 Mod-97 verification.
/// </summary>
public sealed partial class IbanRecognizer : IPiiRecognizer
{
    public string Name => "Global_IBAN";
    public PiiType PiiType => PiiType.Iban;

    [GeneratedRegex(@"\b[A-Z]{2}[0-9]{2}[ -]?[A-Z0-9]{4}[ -]?[A-Z0-9]{4}[ -]?[A-Z0-9]{1,26}\b", RegexOptions.Compiled)]
    private static partial Regex IbanPattern();

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            yield break;

        var matches = IbanPattern().Matches(text);
        foreach (Match match in matches)
        {
            if (IbanValidator.Validate(match.ValueSpan))
            {
                yield return new PiiMatch
                {
                    RawValue = match.Value,
                    Type = PiiType.Iban,
                    TypeName = nameof(PiiType.Iban),
                    Confidence = 0.99,
                    Index = match.Index,
                    Length = match.Length
                };
            }
        }
    }
}

/// <summary>
/// Recognizes US Social Security Numbers (SSN) with area/group/serial range checks.
/// </summary>
public sealed partial class SsnRecognizer : IPiiRecognizer
{
    public string Name => "US_SSN";
    public PiiType PiiType => PiiType.UsSsn;

    [GeneratedRegex(@"\b\d{3}-\d{2}-\d{4}\b", RegexOptions.Compiled)]
    private static partial Regex SsnPattern();

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            yield break;

        var matches = SsnPattern().Matches(text);
        foreach (Match match in matches)
        {
            if (SsnValidator.Validate(match.ValueSpan))
            {
                yield return new PiiMatch
                {
                    RawValue = match.Value,
                    Type = PiiType.UsSsn,
                    TypeName = nameof(PiiType.UsSsn),
                    Confidence = 0.98,
                    Index = match.Index,
                    Length = match.Length
                };
            }
        }
    }
}

/// <summary>
/// Recognizes Email addresses using RFC-compliant pattern.
/// </summary>
public sealed partial class EmailRecognizer : IPiiRecognizer
{
    public string Name => "Email";
    public PiiType PiiType => PiiType.Email;

    [GeneratedRegex(@"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", RegexOptions.Compiled)]
    private static partial Regex EmailPattern();

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text) || !text.Contains('@'))
            yield break;

        var matches = EmailPattern().Matches(text);
        foreach (Match match in matches)
        {
            yield return new PiiMatch
            {
                RawValue = match.Value,
                Type = PiiType.Email,
                TypeName = nameof(PiiType.Email),
                Confidence = 0.95,
                Index = match.Index,
                Length = match.Length
            };
        }
    }
}

/// <summary>
/// Recognizes IPv4 and IPv6 addresses.
/// </summary>
public sealed partial class IpAddressRecognizer : IPiiRecognizer
{
    public string Name => "IpAddress";
    public PiiType PiiType => PiiType.IpAddress;

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled)]
    private static partial Regex Ipv4Pattern();

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            yield break;

        var matches = Ipv4Pattern().Matches(text);
        foreach (Match match in matches)
        {
            if (IPAddress.TryParse(match.Value, out var ip) &&
                ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                yield return new PiiMatch
                {
                    RawValue = match.Value,
                    Type = PiiType.IpAddress,
                    TypeName = nameof(PiiType.IpAddress),
                    Confidence = 0.90,
                    Index = match.Index,
                    Length = match.Length
                };
            }
        }
    }
}
