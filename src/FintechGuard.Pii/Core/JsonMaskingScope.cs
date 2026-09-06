namespace FintechGuard.Pii.Core;

/// <summary>
/// Fine-grained control over how an individual JSON payload is masked before sending to a Database, API, or Queue.
/// Allows developers to selectively include/exclude specific PII types, property keys, or override strategies.
/// </summary>
public class JsonMaskingScope
{
    /// <summary>
    /// If specified, ONLY these PII types will be scanned and masked. All other PII will remain untouched.
    /// Example: IncludeTypes = [PiiType.CreditCard, PiiType.Aadhaar] (ignore emails and IPs).
    /// </summary>
    public HashSet<PiiType>? IncludeTypes { get; set; }

    /// <summary>
    /// If specified, these PII types will be skipped from masking.
    /// Example: ExcludeTypes = [PiiType.Email] (mask cards and PAN, but keep email plaintext).
    /// </summary>
    public HashSet<PiiType>? ExcludeTypes { get; set; }

    /// <summary>
    /// JSON property keys that should NEVER be masked, even if their value resembles PII.
    /// Example: ExcludeKeys = ["reference_id", "public_account_alias"].
    /// </summary>
    public HashSet<string>? ExcludeKeys { get; set; }

    /// <summary>
    /// If specified, ONLY properties with these key names will be scanned for PII.
    /// Example: IncludeKeys = ["payment_data", "customer_kyc"].
    /// </summary>
    public HashSet<string>? IncludeKeys { get; set; }

    /// <summary>
    /// Overrides the masking strategy for this specific payload.
    /// Example: Use MaskingStrategy.OneWayRedaction when writing to an Audit Log DB,
    /// but use MaskingStrategy.FormatPreservingReversible when writing to a Transactions DB.
    /// </summary>
    public MaskingStrategy? StrategyOverride { get; set; }
}
