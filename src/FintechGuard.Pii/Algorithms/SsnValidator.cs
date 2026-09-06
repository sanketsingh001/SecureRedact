namespace FintechGuard.Pii.Algorithms;

/// <summary>
/// Validates US Social Security Numbers (SSN).
/// Rules:
/// - Area number (first 3 digits): cannot be 000, 666, or 900-999.
/// - Group number (middle 2 digits): cannot be 00.
/// - Serial number (last 4 digits): cannot be 0000.
/// </summary>
public static class SsnValidator
{
    public static bool Validate(ReadOnlySpan<char> input)
    {
        Span<char> digits = stackalloc char[input.Length];
        int count = 0;

        foreach (char c in input)
        {
            if (char.IsDigit(c))
            {
                digits[count++] = c;
            }
            else if (c != '-' && c != ' ')
            {
                return false;
            }
        }

        if (count != 9)
            return false;

        int area = (digits[0] - '0') * 100 + (digits[1] - '0') * 10 + (digits[2] - '0');
        if (area == 0 || area == 666 || area >= 900)
            return false;

        int group = (digits[3] - '0') * 10 + (digits[4] - '0');
        if (group == 0)
            return false;

        int serial = (digits[5] - '0') * 1000 + (digits[6] - '0') * 100 + (digits[7] - '0') * 10 + (digits[8] - '0');
        if (serial == 0)
            return false;

        return true;
    }
}
