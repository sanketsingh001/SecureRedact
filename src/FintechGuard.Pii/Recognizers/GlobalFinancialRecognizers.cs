using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using FintechGuard.Pii.Algorithms;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Recognizers;

/// <summary>
/// Recognizes International Bank Account Numbers (IBAN) — both compact and 4-char space/dash grouped —
/// using ISO 13616 length rules and ISO 7064 Mod-97 verification.
/// </summary>
public sealed partial class IbanRecognizer : IFastPiiRecognizer
{
    public string Name => "Global_IBAN";
    public PiiType PiiType => PiiType.Iban;

    [GeneratedRegex(@"\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,4})?\b", RegexOptions.NonBacktracking, matchTimeoutMilliseconds: 1000)]
    private static partial Regex IbanPattern();

    public bool MightMatch(in TextFeatures features) =>
        features.Length >= 14 && features.DigitCount >= 2 && features.HasAsciiUpper;

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

        foreach (ValueMatch vm in IbanPattern().EnumerateMatches(text.AsSpan()))
        {
            if (IbanValidator.Validate(text.AsSpan(vm.Index, vm.Length)))
            {
                destination.Add(new PiiMatch
                {
                    RawValue = text.Substring(vm.Index, vm.Length),
                    Type = PiiType.Iban,
                    TypeName = nameof(PiiType.Iban),
                    Confidence = 0.99,
                    Index = vm.Index,
                    Length = vm.Length
                });
            }
        }
    }
}

/// <summary>
/// Recognizes US Social Security Numbers (SSN) with area/group/serial range checks.
/// </summary>
public sealed partial class SsnRecognizer : IFastPiiRecognizer
{
    public string Name => "US_SSN";
    public PiiType PiiType => PiiType.UsSsn;

    [GeneratedRegex(@"\b\d{3}-\d{2}-\d{4}\b", RegexOptions.NonBacktracking, matchTimeoutMilliseconds: 1000)]
    private static partial Regex SsnPattern();

    public bool MightMatch(in TextFeatures features) =>
        features.Length >= 11 && features.DigitCount >= 9 && features.HasDash;

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

        foreach (ValueMatch vm in SsnPattern().EnumerateMatches(text.AsSpan()))
        {
            if (SsnValidator.Validate(text.AsSpan(vm.Index, vm.Length)))
            {
                destination.Add(new PiiMatch
                {
                    RawValue = text.Substring(vm.Index, vm.Length),
                    Type = PiiType.UsSsn,
                    TypeName = nameof(PiiType.UsSsn),
                    Confidence = 0.98,
                    Index = vm.Index,
                    Length = vm.Length
                });
            }
        }
    }
}

/// <summary>
/// Recognizes Email addresses using RFC-compliant pattern.
/// </summary>
public sealed partial class EmailRecognizer : IFastPiiRecognizer
{
    public string Name => "Email";
    public PiiType PiiType => PiiType.Email;

    [GeneratedRegex(@"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", RegexOptions.NonBacktracking, matchTimeoutMilliseconds: 1000)]
    private static partial Regex EmailPattern();

    public bool MightMatch(in TextFeatures features) =>
        features.HasAt && features.HasDot && features.Length >= 5;

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

        foreach (ValueMatch vm in EmailPattern().EnumerateMatches(text.AsSpan()))
        {
            destination.Add(new PiiMatch
            {
                RawValue = text.Substring(vm.Index, vm.Length),
                Type = PiiType.Email,
                TypeName = nameof(PiiType.Email),
                Confidence = 0.95,
                Index = vm.Index,
                Length = vm.Length
            });
        }
    }
}

/// <summary>
/// Recognizes both IPv4 (excluding version numbers like v1.2.3.4) and IPv6 addresses (excluding HH:MM:SS timestamps).
/// </summary>
public sealed partial class IpAddressRecognizer : IFastPiiRecognizer
{
    public string Name => "IpAddress";
    public PiiType PiiType => PiiType.IpAddress;

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.NonBacktracking, matchTimeoutMilliseconds: 1000)]
    private static partial Regex Ipv4Pattern();

    public bool MightMatch(in TextFeatures features) =>
        (features.HasDot && features.DigitCount >= 4) || (features.HasColon && features.Length >= 3);

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

        if (features.HasDot && features.DigitCount >= 4)
        {
            foreach (ValueMatch vm in Ipv4Pattern().EnumerateMatches(span))
            {
                if (vm.Index > 0)
                {
                    char prev = span[vm.Index - 1];
                    if (prev == 'v' || prev == 'V' || prev == '.')
                        continue;
                }
                if (vm.Index + vm.Length < span.Length && span[vm.Index + vm.Length] == '.')
                    continue;

                if (IPAddress.TryParse(span.Slice(vm.Index, vm.Length), out var ip) &&
                    ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    destination.Add(new PiiMatch
                    {
                        RawValue = text.Substring(vm.Index, vm.Length),
                        Type = PiiType.IpAddress,
                        TypeName = nameof(PiiType.IpAddress),
                        Confidence = 0.90,
                        Index = vm.Index,
                        Length = vm.Length
                    });
                }
            }
        }

        if (features.HasColon && features.Length >= 3)
        {
            ScanIpv6Into(text, span, destination);
        }
    }

    private static void ScanIpv6Into(string text, ReadOnlySpan<char> span, List<PiiMatch> destination)
    {
        int len = span.Length;
        int i = 0;

        while (i < len)
        {
            char c = span[i];
            if (!IsHexOrColon(c))
            {
                i++;
                continue;
            }

            if (i > 0 && (char.IsLetterOrDigit(span[i - 1]) || span[i - 1] == '_'))
            {
                while (i < len && (IsHexOrColon(span[i]) || char.IsLetterOrDigit(span[i]))) i++;
                continue;
            }

            int start = i;
            int colons = 0;
            bool hasDoubleColon = false;
            bool hasDot = false;

            while (i < len)
            {
                char ch = span[i];
                if (ch == ':')
                {
                    colons++;
                    if (i > start && span[i - 1] == ':')
                        hasDoubleColon = true;
                    i++;
                }
                else if (IsAsciiHex(ch))
                {
                    i++;
                }
                else if (ch == '.' && colons >= 2)
                {
                    hasDot = true;
                    i++;
                }
                else
                {
                    break;
                }
            }

            int end = i;
            if (end < len && (char.IsLetterOrDigit(span[end]) || span[end] == '_'))
            {
                while (i < len && char.IsLetterOrDigit(span[i])) i++;
                continue;
            }

            // Require at least 2 colons and either :: compression or full 7-colon (or IPv4-mapped) form
            if (colons >= 2 && (hasDoubleColon || colons == 7 || (hasDot && colons >= 6)) && end - start >= 3)
            {
                ReadOnlySpan<char> candidate = span.Slice(start, end - start);
                if (IPAddress.TryParse(candidate, out var ip) &&
                    ip.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    destination.Add(new PiiMatch
                    {
                        RawValue = text.Substring(start, end - start),
                        Type = PiiType.IpAddress,
                        TypeName = nameof(PiiType.IpAddress),
                        Confidence = 0.92,
                        Index = start,
                        Length = end - start
                    });
                }
            }
        }
    }

    private static bool IsAsciiHex(char c) =>
        (uint)(c - '0') <= 9 || (uint)(c - 'a') <= 5 || (uint)(c - 'A') <= 5;

    private static bool IsHexOrColon(char c) => c == ':' || IsAsciiHex(c);
}

/// <summary>
/// Recognizes international E.164 formatted phone numbers (excluding +91 which is handled by <see cref="IndianMobileRecognizer"/>).
/// </summary>
public sealed partial class GenericPhoneRecognizer : IFastPiiRecognizer
{
    public string Name => "Generic_Phone";
    public PiiType PiiType => PiiType.GenericPhone;

    [GeneratedRegex(@"\+[1-9]\d{0,2}(?:[- .]?\(?\d{1,4}\)?){2,5}", RegexOptions.NonBacktracking, matchTimeoutMilliseconds: 1000)]
    private static partial Regex InternationalPhonePattern();

    public bool MightMatch(in TextFeatures features) =>
        features.HasPlus && features.DigitCount >= 10;

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
        foreach (ValueMatch vm in InternationalPhonePattern().EnumerateMatches(span))
        {
            if (vm.Index > 0 && char.IsLetterOrDigit(span[vm.Index - 1]))
                continue;
            if (vm.Index + vm.Length < span.Length && char.IsLetterOrDigit(span[vm.Index + vm.Length]))
                continue;

            ReadOnlySpan<char> cand = span.Slice(vm.Index, vm.Length);
            // Exclude +91 Indian numbers so IndianMobileRecognizer owns them cleanly
            if (cand.Length >= 3 && cand[1] == '9' && cand[2] == '1')
                continue;

            int digits = 0;
            for (int k = 0; k < cand.Length; k++)
            {
                if (char.IsDigit(cand[k])) digits++;
            }

            if (digits >= 10 && digits <= 15)
            {
                destination.Add(new PiiMatch
                {
                    RawValue = text.Substring(vm.Index, vm.Length),
                    Type = PiiType.GenericPhone,
                    TypeName = nameof(PiiType.GenericPhone),
                    Confidence = 0.88,
                    Index = vm.Index,
                    Length = vm.Length
                });
            }
        }
    }
}

/// <summary>
/// Recognizes calendar dates as Date of Birth when gated by DOB/birth inline context or JSON key hints.
/// Generic timestamps and created_at fields stay below MinConfidence and are never falsely masked.
/// </summary>
public sealed partial class DateOfBirthRecognizer : IFastPiiRecognizer
{
    public string Name => "DateOfBirth";
    public PiiType PiiType => PiiType.DateOfBirth;

    [GeneratedRegex(@"\b(?:(?:19|20)\d{2}[-/](?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12]\d|3[01])|(?:0?[1-9]|[12]\d|3[01])[-/](?:0?[1-9]|1[0-2])[-/](?:19|20)\d{2}|(?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12]\d|3[01])[-/](?:19|20)\d{2})\b", RegexOptions.NonBacktracking, matchTimeoutMilliseconds: 1000)]
    private static partial Regex DatePattern();

    private static readonly string[] InlineContextWords = ["dob", "birth", "born", "d.o.b"];

    public bool MightMatch(in TextFeatures features) =>
        features.DigitCount >= 6 && (features.HasDash || features.HasSlash);

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
        foreach (ValueMatch vm in DatePattern().EnumerateMatches(span))
        {
            // Ignore ISO-8601 datetime timestamps like 2026-09-06T15:30:00Z
            int after = vm.Index + vm.Length;
            if (after < span.Length && (span[after] == 'T' || span[after] == 't'))
                continue;

            double conf = IndianMobileRecognizer.HasInlineContext(span, vm.Index, vm.Length, InlineContextWords)
                ? 0.90
                : 0.55;

            destination.Add(new PiiMatch
            {
                RawValue = text.Substring(vm.Index, vm.Length),
                Type = PiiType.DateOfBirth,
                TypeName = nameof(PiiType.DateOfBirth),
                Confidence = conf,
                Index = vm.Index,
                Length = vm.Length
            });
        }
    }
}
