namespace FintechGuard.Pii.Algorithms;

/// <summary>
/// Implements validation for Indian GSTIN (Goods and Services Tax Identification Number - 15 characters).
/// Structure: [2-digit state code][10-digit PAN][1 entity digit][Z][1 Mod-36 check character].
/// </summary>
public static class GstinValidator
{
    private const string Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public static bool Validate(ReadOnlySpan<char> gstin)
    {
        if (gstin.Length != 15)
            return false;

        // 1. State code: 01 - 38 or 97 (Other Territory)
        if (!char.IsAsciiDigit(gstin[0]) || !char.IsAsciiDigit(gstin[1]))
            return false;

        int stateCode = (gstin[0] - '0') * 10 + (gstin[1] - '0');
        if (!((stateCode >= 1 && stateCode <= 38) || stateCode == 97))
            return false;

        // 2. Embedded PAN (chars 2 to 11)
        if (!PanValidator.Validate(gstin.Slice(2, 10)))
            return false;

        // 3. 13th char: Entity registration number (1-9 or A-Z, cannot be '0')
        char entityChar = gstin[12];
        if (!char.IsAsciiLetterOrDigit(entityChar) || char.IsAsciiLetterLower(entityChar) || entityChar == '0')
            return false;

        // 4. 14th char: Strictly 'Z' by statutory mandate
        if (gstin[13] != 'Z')
            return false;

        // 5. 15th char: Indian GSTN Modulo-36 checksum validation
        int sum = 0;
        for (int i = 0; i < 14; i++)
        {
            int cp = Chars.IndexOf(gstin[i]);
            if (cp < 0)
                return false;

            int factor = (i & 1) == 0 ? 1 : 2;
            int product = cp * factor;
            sum += (product / 36) + (product % 36);
        }

        char expectedCheck = Chars[(36 - (sum % 36)) % 36];
        return gstin[14] == expectedCheck;
    }
}
