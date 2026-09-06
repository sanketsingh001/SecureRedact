using System.Text;
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
    /// Creates a natural, format-preserving mask (e.g. 4532-****-****-9010 or jo***n@domain.com).
    /// </summary>
    public static string CreateMask(PiiType type, string rawValue, char maskChar = '*')
    {
        if (string.IsNullOrEmpty(rawValue))
            return rawValue;

        switch (type)
        {
            case PiiType.CreditCard:
                return MaskCreditCard(rawValue, maskChar);

            case PiiType.Aadhaar:
                return MaskAadhaar(rawValue);

            case PiiType.Pan:
                return MaskPan(rawValue, maskChar);

            case PiiType.Gstin:
                return MaskGstin(rawValue, maskChar);

            case PiiType.Email:
                return MaskEmail(rawValue, maskChar);

            case PiiType.UsSsn:
                return MaskSsn(rawValue, maskChar);

            case PiiType.Iban:
                return MaskIban(rawValue, maskChar);

            case PiiType.IndianMobile:
            case PiiType.GenericPhone:
                return MaskPhone(rawValue, maskChar);

            case PiiType.UpiId:
                return MaskUpi(rawValue, maskChar);

            default:
                return MaskGeneric(rawValue, maskChar);
        }
    }

    private static string MaskCreditCard(string raw, char maskChar)
    {
        // 4532-1234-5678-9010 -> 4532-****-****-9010
        var digitsOnly = new StringBuilder();
        foreach (char c in raw)
        {
            if (char.IsDigit(c)) digitsOnly.Append(c);
        }

        if (digitsOnly.Length < 12)
            return MaskGeneric(raw, maskChar);

        string d = digitsOnly.ToString();
        string first4 = d[..4];
        string last4 = d[^4..];

        if (raw.Contains('-'))
            return $"{first4}-{new string(maskChar, 4)}-{new string(maskChar, 4)}-{last4}";
        if (raw.Contains(' '))
            return $"{first4} {new string(maskChar, 4)} {new string(maskChar, 4)} {last4}";

        return $"{first4}{new string(maskChar, d.Length - 8)}{last4}";
    }

    private static string MaskAadhaar(string raw)
    {
        // UIDAI standard format: XXXX XXXX 1234
        var digitsOnly = new StringBuilder();
        foreach (char c in raw)
        {
            if (char.IsDigit(c)) digitsOnly.Append(c);
        }

        if (digitsOnly.Length != 12)
            return MaskGeneric(raw, 'X');

        string last4 = digitsOnly.ToString()[^4..];
        return raw.Contains('-') ? $"XXXX-XXXX-{last4}" : $"XXXX XXXX {last4}";
    }

    private static string MaskPan(string raw, char maskChar)
    {
        // ABCDE1234F -> AB***12*4F or AB*****34F
        string clean = raw.Trim().ToUpperInvariant();
        if (clean.Length == 10)
        {
            return $"{clean[..2]}{new string(maskChar, 4)}{clean[^4..]}";
        }
        return MaskGeneric(raw, maskChar);
    }

    private static string MaskGstin(string raw, char maskChar)
    {
        // 27ABCDE1234F1Z5 -> 27******1234*Z*
        string clean = raw.Trim().ToUpperInvariant();
        if (clean.Length == 15)
        {
            return $"{clean[..2]}{new string(maskChar, 5)}{clean[7..11]}{new string(maskChar, 2)}{clean[^1]}";
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
        var digits = new StringBuilder();
        foreach (char c in raw)
        {
            if (char.IsDigit(c)) digits.Append(c);
        }

        if (digits.Length == 9)
        {
            string last4 = digits.ToString()[^4..];
            return $"***-**-{last4}";
        }
        return MaskGeneric(raw, maskChar);
    }

    private static string MaskIban(string raw, char maskChar)
    {
        string clean = raw.Replace(" ", "").Trim();
        if (clean.Length > 8)
        {
            return $"{clean[..4]}{new string(maskChar, clean.Length - 8)}{clean[^4..]}";
        }
        return MaskGeneric(raw, maskChar);
    }

    private static string MaskPhone(string raw, char maskChar)
    {
        var digits = new StringBuilder();
        foreach (char c in raw)
        {
            if (char.IsDigit(c)) digits.Append(c);
        }

        if (digits.Length >= 10)
        {
            string d = digits.ToString();
            return $"{d[..2]}{new string(maskChar, d.Length - 4)}{d[^2..]}";
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

    private static string MaskGeneric(string raw, char maskChar)
    {
        if (raw.Length <= 4)
            return new string(maskChar, raw.Length);

        int keep = Math.Max(1, raw.Length / 4);
        return $"{raw[..keep]}{new string(maskChar, raw.Length - (keep * 2))}{raw[^keep..]}";
    }
}
