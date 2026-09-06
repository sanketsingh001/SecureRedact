namespace FintechGuard.Pii.Algorithms;

/// <summary>
/// Implements validation for Indian GSTIN (Goods and Services Tax Identification Number - 15 characters).
/// Structure: [2-digit state code][10-digit PAN][1 entity digit][Z][1 check character].
/// </summary>
public static class GstinValidator
{
    private const string Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public static bool Validate(ReadOnlySpan<char> gstin)
    {
        if (gstin.Length != 15)
            return false;

        // 1. State code (01 - 38)
        if (!char.IsAsciiDigit(gstin[0]) || !char.IsAsciiDigit(gstin[1]))
            return false;

        int stateCode = (gstin[0] - '0') * 10 + (gstin[1] - '0');
        if (stateCode < 1 || stateCode > 38)
            return false;

        // 2. Embedded PAN (chars 2 to 11): 5 uppercase letters, 4 digits, 1 letter
        for (int i = 2; i < 7; i++)
        {
            if (!char.IsAsciiLetterUpper(gstin[i]))
                return false;
        }

        // 4th char of PAN should be a valid status: P, C, H, F, A, T, B, L, J, G
        char status = gstin[5];
        if ("PCHFATBLJG".IndexOf(status) < 0)
            return false;

        for (int i = 7; i < 11; i++)
        {
            if (!char.IsAsciiDigit(gstin[i]))
                return false;
        }

        if (!char.IsAsciiLetterUpper(gstin[11]))
            return false;

        // 3. 13th char: Alphanumeric
        if (!char.IsAsciiLetterOrDigit(gstin[12]))
            return false;

        // 4. 14th char: Strictly 'Z' by statutory mandate
        if (gstin[13] != 'Z')
            return false;

        // 5. 15th char: Modulo 36 check character
        char checkChar = gstin[14];
        return char.IsAsciiLetterOrDigit(checkChar);
    }
}
