namespace FintechGuard.Pii.Algorithms;

/// <summary>
/// Implements the Luhn Modulo 10 algorithm used for Credit/Debit Cards (ISO/IEC 7812).
/// Eliminates ~90% of random digit false positives when keys are completely arbitrary.
/// </summary>
public static class LuhnValidator
{
    /// <summary>
    /// Validates whether a digit sequence passes the Luhn Mod 10 checksum.
    /// Non-digit characters (spaces, dashes) should be skipped or stripped.
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
                    n = (n % 10) + 1;
            }

            sum += n;
            alternate = !alternate;
        }

        return (sum % 10) == 0;
    }

    /// <summary>
    /// Strips spaces and dashes into a stack-allocated buffer and validates Luhn.
    /// </summary>
    public static bool ValidateWithSeparators(ReadOnlySpan<char> input)
    {
        Span<char> digits = stackalloc char[input.Length];
        int count = 0;

        foreach (char c in input)
        {
            if (char.IsDigit(c))
            {
                digits[count++] = c;
            }
            else if (c != ' ' && c != '-')
            {
                return false; // Invalid character for card format
            }
        }

        return Validate(digits[..count]);
    }
}
