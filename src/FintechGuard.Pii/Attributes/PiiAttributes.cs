using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Attributes;

/// <summary>
/// Marks a property or field for automatic PII masking and tokenization during serialization.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field, AllowMultiple = false, Inherited = true)]
public class PiiMaskAttribute : Attribute
{
    private MaskingStrategy _strategy = MaskingStrategy.FormatPreservingReversible;
    private char _maskChar = '*';

    public PiiType PiiType { get; set; }

    public MaskingStrategy Strategy
    {
        get => _strategy;
        set
        {
            _strategy = value;
            HasExplicitStrategy = true;
        }
    }

    public char MaskChar
    {
        get => _maskChar;
        set
        {
            _maskChar = value;
            HasExplicitMaskChar = true;
        }
    }

    internal bool HasExplicitStrategy { get; private set; }
    internal bool HasExplicitMaskChar { get; private set; }

    public PiiMaskAttribute(PiiType piiType)
    {
        PiiType = piiType;
    }

    public PiiMaskAttribute(PiiType piiType, MaskingStrategy strategy)
    {
        PiiType = piiType;
        _strategy = strategy;
        HasExplicitStrategy = true;
    }
}

/// <summary>
/// Defines a custom regex masking rule directly on a C# model property.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field, AllowMultiple = false, Inherited = true)]
public class CustomPiiRuleAttribute : Attribute
{
    private MaskingStrategy _strategy = MaskingStrategy.FormatPreservingReversible;

    public string Pattern { get; set; }

    public MaskingStrategy Strategy
    {
        get => _strategy;
        set
        {
            _strategy = value;
            HasExplicitStrategy = true;
        }
    }

    public char MaskChar { get; set; } = '*';
    public int KeepPrefix { get; set; } = 2;
    public int KeepSuffix { get; set; } = 2;

    internal bool HasExplicitStrategy { get; private set; }

    public CustomPiiRuleAttribute(string pattern)
    {
        Pattern = pattern;
    }
}

/// <summary>
/// Explicitly excludes a property from being scanned or masked, even if its value resembles PII.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field, AllowMultiple = false, Inherited = true)]
public class PiiIgnoreAttribute : Attribute
{
}
