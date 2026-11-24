using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Masking;

/// <summary>
/// Utility for generating natural, human-readable masked representations of PII.
/// </summary>
public static class FormatHelper
{
    public const string FormatPreservingPrefix = "#fp[";
    public const char FormatPreservingSuffix = ']';

    /// <summary>
    /// Creates a natural, format-preserving mask (e.g. 4532-****-****-9010 or j*****n@domain.com).
    /// </summary>
    public static string CreateMask(PiiType type, string rawValue, char maskChar = '*')
    {
        if (string.IsNullOrEmpty(rawValue))
            return rawValue;

        return type switch
        {
            PiiType.CreditCard => MaskCreditCard(rawValue, maskChar),
            PiiType.Aadhaar => MaskAadhaar(rawValue),
            PiiType.Pan => MaskPan(rawValue, maskChar),
            PiiType.Gstin => MaskGstin(rawValue, maskChar),
            PiiType.Email => MaskEmail(rawValue, maskChar),
            PiiType.UsSsn => MaskSsn(rawValue, maskChar),
            PiiType.Iban => MaskIban(rawValue, maskChar),
            PiiType.IndianMobile or PiiType.GenericPhone => MaskPhone(rawValue, maskChar),
            PiiType.UpiId => MaskUpi(rawValue, maskChar),
            PiiType.IpAddress => MaskIpAddress(rawValue, maskChar),
            PiiType.DateOfBirth => MaskDateOfBirth(rawValue, maskChar),
            PiiType.PersonName or PiiType.Address or PiiType.Organization => MaskWhitespaceFreeEntity(rawValue, maskChar),
            _ => MaskGeneric(rawValue, maskChar)
        };
    }

    private static string MaskCreditCard(string raw, char maskChar)
    {
        Span<char> digits = stackalloc char[19];
        int count = 0;
        foreach (char c in raw)
        {
            if (char.IsDigit(c))
            {
                if (count >= 19)
                    return MaskGeneric(raw, maskChar);
                digits[count++] = c;
            }
        }

        if (count < 12)
            return MaskGeneric(raw, maskChar);

        ReadOnlySpan<char> d = digits[..count];
        char sep = raw.Contains('-') ? '-' : raw.Contains(' ') ? ' ' : '\0';

        if (sep != '\0')
        {
            return string.Create(19, (d[0], d[1], d[2], d[3], d[count - 4], d[count - 3], d[count - 2], d[count - 1], sep, maskChar), static (span, s) =>
            {
                span[0] = s.Item1; span[1] = s.Item2; span[2] = s.Item3; span[3] = s.Item4;
                span[4] = s.sep;
                span[5] = s.maskChar; span[6] = s.maskChar; span[7] = s.maskChar; span[8] = s.maskChar;
                span[9] = s.sep;
                span[10] = s.maskChar; span[11] = s.maskChar; span[12] = s.maskChar; span[13] = s.maskChar;
                span[14] = s.sep;
                span[15] = s.Item5; span[16] = s.Item6; span[17] = s.Item7; span[18] = s.Item8;
            });
        }

        return string.Create(count, (raw, maskChar), static (span, state) =>
        {
            int idx = 0;
            Span<char> buf = stackalloc char[19];
            foreach (char c in state.raw)
            {
                if (char.IsDigit(c)) buf[idx++] = c;
            }
            buf[..4].CopyTo(span);
            span.Slice(4, span.Length - 8).Fill(state.maskChar);
            buf.Slice(idx - 4, 4).CopyTo(span.Slice(span.Length - 4, 4));
        });
    }

    private static string MaskAadhaar(string raw)
    {
        Span<char> digits = stackalloc char[12];
        int count = 0;
        foreach (char c in raw)
        {
            if (char.IsDigit(c))
            {
                if (count >= 12)
                    return MaskGeneric(raw, 'X');
                digits[count++] = c;
            }
        }

        if (count != 12)
            return MaskGeneric(raw, 'X');

        char sep = raw.Contains('-') ? '-' : ' ';
        return string.Create(14, (digits[8], digits[9], digits[10], digits[11], sep), static (span, s) =>
        {
            span[0] = 'X'; span[1] = 'X'; span[2] = 'X'; span[3] = 'X';
            span[4] = s.sep;
            span[5] = 'X'; span[6] = 'X'; span[7] = 'X'; span[8] = 'X';
            span[9] = s.sep;
            span[10] = s.Item1; span[11] = s.Item2; span[12] = s.Item3; span[13] = s.Item4;
        });
    }

    private static string MaskPan(string raw, char maskChar)
    {
        ReadOnlySpan<char> clean = raw.AsSpan().Trim();
        if (clean.Length == 10)
        {
            return string.Create(10, (raw, maskChar), static (span, s) =>
            {
                ReadOnlySpan<char> t = s.raw.AsSpan().Trim();
                span[0] = char.ToUpperInvariant(t[0]);
                span[1] = char.ToUpperInvariant(t[1]);
                span.Slice(2, 4).Fill(s.maskChar);
                for (int i = 6; i < 10; i++)
                    span[i] = char.ToUpperInvariant(t[i]);
            });
        }
        return MaskGeneric(raw, maskChar);
    }

    private static string MaskGstin(string raw, char maskChar)
    {
        ReadOnlySpan<char> clean = raw.AsSpan().Trim();
        if (clean.Length == 15)
        {
            return string.Create(15, (raw, maskChar), static (span, s) =>
            {
                ReadOnlySpan<char> t = s.raw.AsSpan().Trim();
                span[0] = char.ToUpperInvariant(t[0]);
                span[1] = char.ToUpperInvariant(t[1]);
                span.Slice(2, 5).Fill(s.maskChar);
                for (int i = 7; i < 11; i++)
                    span[i] = char.ToUpperInvariant(t[i]);
                span[11] = s.maskChar;
                span[12] = s.maskChar;
                span[13] = s.maskChar;
                span[14] = char.ToUpperInvariant(t[14]);
            });
        }
        return MaskGeneric(raw, maskChar);
    }

    private static string MaskEmail(string raw, char maskChar)
    {
        int atIndex = raw.IndexOf('@');
        if (atIndex <= 1)
            return MaskGeneric(raw, maskChar);

        string local = raw[..atIndex];
        string domain = raw[atIndex..];

        if (local.Length <= 2)
            return $"{local[0]}{maskChar}{domain}";

        return $"{local[0]}{new string(maskChar, Math.Min(5, local.Length - 2))}{local[^1]}{domain}";
    }

    private static string MaskSsn(string raw, char maskChar)
    {
        Span<char> digits = stackalloc char[9];
        int count = 0;
        foreach (char c in raw)
        {
            if (char.IsDigit(c))
            {
                if (count >= 9)
                    return MaskGeneric(raw, maskChar);
                digits[count++] = c;
            }
        }

        if (count == 9)
        {
            return $"***-**-{digits[5]}{digits[6]}{digits[7]}{digits[8]}";
        }
        return MaskGeneric(raw, maskChar);
    }

    private static string MaskIban(string raw, char maskChar)
    {
        Span<char> clean = stackalloc char[34];
        int count = 0;
        foreach (char c in raw)
        {
            if (c == ' ' || c == '-')
                continue;
            if (count >= 34)
                return MaskGeneric(raw, maskChar);
            clean[count++] = char.ToUpperInvariant(c);
        }

        if (count > 8)
        {
            return $"{clean[..4]}{new string(maskChar, count - 8)}{clean.Slice(count - 4, 4)}";
        }
        return MaskGeneric(raw, maskChar);
    }

    private static string MaskPhone(string raw, char maskChar)
    {
        Span<char> digits = stackalloc char[20];
        int count = 0;
        foreach (char c in raw)
        {
            if (char.IsDigit(c))
            {
                if (count >= 20)
                    return MaskGeneric(raw, maskChar);
                digits[count++] = c;
            }
        }

        if (count >= 10)
        {
            return $"{digits[..2]}{new string(maskChar, count - 4)}{digits.Slice(count - 2, 2)}";
        }
        return MaskGeneric(raw, maskChar);
    }

    private static string MaskUpi(string raw, char maskChar)
    {
        int atIndex = raw.IndexOf('@');
        if (atIndex > 2)
        {
            string handle = raw[..atIndex];
            string psp = raw[atIndex..];
            return $"{handle[..2]}{new string(maskChar, 3)}{handle[^1]}{psp}";
        }
        return MaskGeneric(raw, maskChar);
    }

    private static string MaskIpAddress(string raw, char maskChar)
    {
        int firstDot = raw.IndexOf('.');
        int lastDot = raw.LastIndexOf('.');
        if (firstDot > 0 && lastDot > firstDot)
        {
            return $"{raw[..firstDot]}.{new string(maskChar, 3)}.{new string(maskChar, 3)}.{raw[(lastDot + 1)..]}";
        }

        int firstColon = raw.IndexOf(':');
        int lastColon = raw.LastIndexOf(':');
        if (firstColon > 0 && lastColon > firstColon)
        {
            return $"{raw[..firstColon]}:{new string(maskChar, 3)}:{new string(maskChar, 3)}:{raw[(lastColon + 1)..]}";
        }

        return MaskWhitespaceFreeEntity(raw, maskChar);
    }

    private static string MaskDateOfBirth(string raw, char maskChar)
    {
        // Preserve only non-digit separators and final 2 or 4 characters? Actually mask digits except last 2 of year or keep separators:
        // e.g. 1990-05-12 -> ****-**-12 or 12/05/1990 -> **/**/1990 (no spaces!)
        if (raw.Length >= 8)
        {
            return string.Create(raw.Length, (raw, maskChar), static (span, state) =>
            {
                int keepTail = Math.Min(2, state.raw.Length);
                int maskEnd = state.raw.Length - keepTail;
                for (int i = 0; i < state.raw.Length; i++)
                {
                    char c = state.raw[i];
                    if (c == '-' || c == '/' || c == '.')
                        span[i] = c;
                    else if (i >= maskEnd)
                        span[i] = c;
                    else
                        span[i] = state.maskChar;
                }
            });
        }

        return MaskWhitespaceFreeEntity(raw, maskChar);
    }

    private static string MaskWhitespaceFreeEntity(string raw, char maskChar)
    {
        if (raw.Length <= 4)
            return new string(maskChar, raw.Length);

        int keep = Math.Clamp(raw.Length / 4, 1, 2);
        return string.Create(raw.Length, (raw, maskChar, keep), static (span, state) =>
        {
            for (int i = 0; i < span.Length; i++)
            {
                char c = state.raw[i];
                bool inKeepZone = i < state.keep || i >= span.Length - state.keep;
                if (inKeepZone && !char.IsWhiteSpace(c) && c != ',' && c != ';' && c != ':')
                    span[i] = c;
                else
                    span[i] = state.maskChar;
            }
        });
    }

    private static string MaskGeneric(string raw, char maskChar)
    {
        return MaskWhitespaceFreeEntity(raw, maskChar);
    }
}
