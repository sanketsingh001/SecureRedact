namespace FintechGuard.Pii.Recognizers;

[Flags]
public enum TextFeatureFlags : ushort
{
    None = 0,
    HasDigit = 1 << 0,
    HasAsciiUpper = 1 << 1,
    HasAsciiLower = 1 << 2,
    HasAt = 1 << 3,
    HasDot = 1 << 4,
    HasDash = 1 << 5,
    HasColon = 1 << 6,
    HasPlus = 1 << 7,
    HasSlash = 1 << 8,
    HasSpace = 1 << 9,
    HasNonAscii = 1 << 10
}

/// <summary>
/// Single-pass character-class summary computed over a string to skip irrelevant recognizers
/// in nanoseconds without invoking regexes.
/// </summary>
public readonly struct TextFeatures
{
    public int Length { get; init; }
    public int DigitCount { get; init; }
    public int UpperCount { get; init; }
    public int SpaceCount { get; init; }
    public int WordCount { get; init; }
    public TextFeatureFlags Flags { get; init; }

    public bool HasDigit => (Flags & TextFeatureFlags.HasDigit) != 0;
    public bool HasAsciiUpper => (Flags & TextFeatureFlags.HasAsciiUpper) != 0;
    public bool HasAsciiLower => (Flags & TextFeatureFlags.HasAsciiLower) != 0;
    public bool HasAt => (Flags & TextFeatureFlags.HasAt) != 0;
    public bool HasDot => (Flags & TextFeatureFlags.HasDot) != 0;
    public bool HasDash => (Flags & TextFeatureFlags.HasDash) != 0;
    public bool HasColon => (Flags & TextFeatureFlags.HasColon) != 0;
    public bool HasPlus => (Flags & TextFeatureFlags.HasPlus) != 0;
    public bool HasSlash => (Flags & TextFeatureFlags.HasSlash) != 0;
    public bool HasSpace => (Flags & TextFeatureFlags.HasSpace) != 0;
    public bool HasNonAscii => (Flags & TextFeatureFlags.HasNonAscii) != 0;

    public static TextFeatures Analyze(ReadOnlySpan<char> text)
    {
        int len = text.Length;
        int digits = 0;
        int uppers = 0;
        int spaces = 0;
        int words = 0;
        bool inWord = false;
        TextFeatureFlags flags = TextFeatureFlags.None;

        for (int i = 0; i < len; i++)
        {
            char c = text[i];

            if ((uint)(c - '0') <= 9)
            {
                digits++;
                flags |= TextFeatureFlags.HasDigit;
                if (!inWord) { words++; inWord = true; }
            }
            else if ((uint)(c - 'A') <= ('Z' - 'A'))
            {
                uppers++;
                flags |= TextFeatureFlags.HasAsciiUpper;
                if (!inWord) { words++; inWord = true; }
            }
            else if ((uint)(c - 'a') <= ('z' - 'a'))
            {
                flags |= TextFeatureFlags.HasAsciiLower;
                if (!inWord) { words++; inWord = true; }
            }
            else if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            {
                spaces++;
                flags |= TextFeatureFlags.HasSpace;
                inWord = false;
            }
            else
            {
                switch (c)
                {
                    case '@': flags |= TextFeatureFlags.HasAt; break;
                    case '.': flags |= TextFeatureFlags.HasDot; break;
                    case '-': flags |= TextFeatureFlags.HasDash; break;
                    case ':': flags |= TextFeatureFlags.HasColon; break;
                    case '+': flags |= TextFeatureFlags.HasPlus; break;
                    case '/': flags |= TextFeatureFlags.HasSlash; break;
                    default:
                        if (c > 127)
                        {
                            flags |= TextFeatureFlags.HasNonAscii;
                            if (char.IsWhiteSpace(c))
                            {
                                spaces++;
                                flags |= TextFeatureFlags.HasSpace;
                                inWord = false;
                                continue;
                            }
                        }
                        break;
                }

                if (!inWord && (c > 127 || char.IsLetterOrDigit(c)))
                {
                    words++;
                    inWord = true;
                }
                else if (c <= 127 && !char.IsLetterOrDigit(c))
                {
                    inWord = false;
                }
            }
        }

        return new TextFeatures
        {
            Length = len,
            DigitCount = digits,
            UpperCount = uppers,
            SpaceCount = spaces,
            WordCount = words,
            Flags = flags
        };
    }
}
