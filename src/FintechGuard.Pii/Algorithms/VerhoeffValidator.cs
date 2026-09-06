namespace FintechGuard.Pii.Algorithms;

/// <summary>
/// Implements the Verhoeff algorithm (Dihedral group D8) used by UIDAI for Indian Aadhaar number validation.
/// Catches 100% of single-digit errors and over 95% of adjacent transposition errors.
/// </summary>
public static class VerhoeffValidator
{
    // The multiplication table (d)
    private static readonly int[,] MultiplicationTable = new int[10, 10]
    {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 },
        { 1, 2, 3, 4, 0, 6, 7, 8, 9, 5 },
        { 2, 3, 4, 0, 1, 7, 8, 9, 5, 6 },
        { 3, 4, 0, 1, 2, 8, 9, 5, 6, 7 },
        { 4, 0, 1, 2, 3, 9, 5, 6, 7, 8 },
        { 5, 9, 8, 7, 6, 0, 4, 3, 2, 1 },
        { 6, 5, 9, 8, 7, 1, 0, 4, 3, 2 },
        { 7, 6, 5, 9, 8, 2, 1, 0, 4, 3 },
        { 8, 7, 6, 5, 9, 3, 2, 1, 0, 4 },
        { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
    };

    // The permutation table (p)
    private static readonly int[,] PermutationTable = new int[8, 10]
    {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 },
        { 1, 5, 7, 6, 2, 8, 3, 0, 9, 4 },
        { 5, 8, 0, 3, 7, 9, 6, 1, 4, 2 },
        { 8, 9, 1, 6, 0, 4, 3, 5, 2, 7 },
        { 9, 4, 5, 3, 1, 2, 6, 8, 7, 0 },
        { 4, 2, 8, 6, 5, 7, 3, 9, 0, 1 },
        { 2, 7, 9, 3, 8, 0, 6, 4, 1, 5 },
        { 7, 0, 4, 6, 9, 1, 3, 2, 5, 8 }
    };

    // The inverse table (inv)
    private static readonly int[] InverseTable = { 0, 4, 3, 2, 1, 5, 6, 7, 8, 9 };

    /// <summary>
    /// Computes the Verhoeff check digit for a given sequence of digits.
    /// </summary>
    public static int CalculateCheckDigit(ReadOnlySpan<char> digits)
    {
        int c = 0;
        int len = digits.Length;

        for (int i = 0; i < len; i++)
        {
            char ch = digits[len - 1 - i];
            if (ch < '0' || ch > '9')
                return -1;

            int digit = ch - '0';
            c = MultiplicationTable[c, PermutationTable[(i + 1) % 8, digit]];
        }

        return InverseTable[c];
    }

    /// <summary>
    /// Validates whether the given digit string passes the Verhoeff checksum.
    /// </summary>
    public static bool Validate(ReadOnlySpan<char> digits)
    {
        if (digits.IsEmpty)
            return false;

        int c = 0;
        int len = digits.Length;

        for (int i = 0; i < len; i++)
        {
            char ch = digits[len - 1 - i];
            if (ch < '0' || ch > '9')
                return false;

            int digit = ch - '0';
            c = MultiplicationTable[c, PermutationTable[i % 8, digit]];
        }

        return c == 0;
    }
}
