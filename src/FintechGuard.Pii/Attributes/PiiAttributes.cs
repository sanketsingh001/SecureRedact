using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Attributes;

/// <summary>
/// Marks a property or field for automatic PII masking and tokenization during serialization.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field, AllowMultiple = false, Inherited = true)]
public class PiiMaskAttribute : Attribute
{
    public PiiType PiiType { get; set; }
    public MaskingStrategy Strategy { get; set; } = MaskingStrategy.FormatPreservingReversible;
    public char MaskChar { get; set; } = '*';

    public PiiMaskAttribute(PiiType piiType)
    {
        PiiType = piiType;
    }

    public PiiMaskAttribute(PiiType piiType, MaskingStrategy strategy)
    {
        PiiType = piiType;
        Strategy = strategy;
    }
}

/// <summary>
/// Defines a custom regex masking rule directly on a C# model property.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field, AllowMultiple = false, Inherited = true)]
public class CustomPiiRuleAttribute : Attribute
{
    public string Pattern { get; set; }
    public MaskingStrategy Strategy { get; set; } = MaskingStrategy.FormatPreservingReversible;
    public char MaskChar { get; set; } = '*';
    public int KeepPrefix { get; set; } = 2;
    public int KeepSuffix { get; set; } = 2;

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
