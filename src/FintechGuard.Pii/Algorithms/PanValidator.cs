namespace FintechGuard.Pii.Algorithms;

/// <summary>
/// Validates Indian Income Tax PAN (Permanent Account Number).
/// Structure: 10 characters: 5 letters, 4 digits, 1 letter.
/// 4th character must be one of statutory entity types: P, C, H, F, A, T, B, L, J, G.
/// </summary>
public static class PanValidator
{
    private const string AllowedEntityChars = "PCHFATBLJG";

    public static bool Validate(ReadOnlySpan<char> pan)
    {
        if (pan.Length != 10)
            return false;

        // First 3: Series letters
        if (!char.IsAsciiLetterUpper(pan[0]) || !char.IsAsciiLetterUpper(pan[1]) || !char.IsAsciiLetterUpper(pan[2]))
            return false;

        // 4th char: Entity status
        if (AllowedEntityChars.IndexOf(pan[3]) < 0)
            return false;

        // 5th char: Surname initial letter
        if (!char.IsAsciiLetterUpper(pan[4]))
            return false;

        // 6th to 9th chars: 4 digits
        for (int i = 5; i < 9; i++)
        {
            if (!char.IsAsciiDigit(pan[i]))
                return false;
        }

        // 10th char: Last letter
        return char.IsAsciiLetterUpper(pan[9]);
    }
}
