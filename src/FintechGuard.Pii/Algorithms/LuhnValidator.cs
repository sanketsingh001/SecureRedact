namespace FintechGuard.Pii.Algorithms;

/// <summary>
/// Implements the Luhn Modulo 10 algorithm and IIN/BIN prefix verification used for Credit/Debit Cards (ISO/IEC 7812).
/// </summary>
public static class LuhnValidator
{
    /// <summary>
    /// Validates whether a digit sequence passes the Luhn Mod 10 checksum.
    /// </summary>
    public static bool Validate(ReadOnlySpan<char> input)
    {
        if (input.Length < 13 || input.Length > 19)
            return false;

        int sum = 0;
        bool alternate = false;

        for (int i = input.Length - 1; i >= 0; i--)
        {
            char c = input[i];
            if (c < '0' || c > '9')
                return false;

            int n = c - '0';
            if (alternate)
            {
                n *= 2;
                if (n > 9)
                    n -= 9;
            }

            sum += n;
            alternate = !alternate;
        }

        return (sum % 10) == 0;
    }

    /// <summary>
    /// Strips spaces and dashes into a bounded stack-allocated buffer and validates Luhn.
    /// </summary>
    public static bool ValidateWithSeparators(ReadOnlySpan<char> input)
    {
        if (input.Length < 13 || input.Length > 40)
            return false;

        Span<char> digits = stackalloc char[19];
        int count = 0;

        foreach (char c in input)
        {
            if (c >= '0' && c <= '9')
            {
                if (count >= 19)
                    return false;
                digits[count++] = c;
            }
            else if (c != ' ' && c != '-')
            {
                return false;
            }
        }

        return Validate(digits[..count]);
    }

    /// <summary>
    /// Validates whether the digit sequence matches a known global or Indian payment card IIN/BIN prefix and length.
    /// Significantly reduces false positives on arbitrary Luhn-valid numeric IDs.
    /// </summary>
    public static bool IsValidCardIin(ReadOnlySpan<char> digits)
    {
        int len = digits.Length;
        if (len < 12 || len > 19)
            return false;

        for (int i = 0; i < len; i++)
        {
            if (digits[i] < '0' || digits[i] > '9')
                return false;
        }

        int d1 = digits[0] - '0';
        int d2 = d1 * 10 + (digits[1] - '0');
        int d3 = d2 * 10 + (digits[2] - '0');
        int d4 = d3 * 10 + (digits[3] - '0');
        int d6 = (d4 * 10 + (digits[4] - '0')) * 10 + (digits[5] - '0');

        // Visa: 4..., length 13, 16, or 19
        if (d1 == 4 && (len == 13 || len == 16 || len == 19))
            return true;

        // Mastercard: 51..55 or 2221..2720, length 16
        if (len == 16 && ((d2 >= 51 && d2 <= 55) || (d4 >= 2221 && d4 <= 2720)))
            return true;

        // Amex: 34 or 37, length 15
        if (len == 15 && (d2 == 34 || d2 == 37))
            return true;

        // RuPay (India): 60, 6521..6522, 81, 82, 508, 353, 356, length 16
        if (len == 16 && (d2 == 60 || d2 == 81 || d2 == 82 || d3 == 508 || d3 == 353 || d3 == 356 || d4 == 6521 || d4 == 6522))
            return true;

        // Discover: 6011, 644..649, 65, 622126..622925, length 16..19
        if (len >= 16 && len <= 19 && (d4 == 6011 || (d3 >= 644 && d3 <= 649) || d2 == 65 || (d6 >= 622126 && d6 <= 622925)))
            return true;

        // Diners Club: 300..305, 36, 38..39, length 14..19
        if (len >= 14 && len <= 19 && ((d3 >= 300 && d3 <= 305) || d2 == 36 || d2 == 38 || d2 == 39))
            return true;

        // JCB: 3528..3589, length 16..19
        if (len >= 16 && len <= 19 && d4 >= 3528 && d4 <= 3589)
            return true;

        // UnionPay: 62, length 16..19
        if (len >= 16 && len <= 19 && d2 == 62)
            return true;

        // Maestro: 50, 56..58, 6, length 12..19
        if (len >= 12 && len <= 19 && (d2 == 50 || (d2 >= 56 && d2 <= 58) || d1 == 6))
            return true;

        return false;
    }
}
