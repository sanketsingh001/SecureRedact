namespace FintechGuard.Pii.Core;

/// <summary>
/// Supported PII classifications for Fintech and Regulatory compliance.
/// </summary>
public enum PiiType
{
    // Global Financial
    CreditCard = 1,
    Iban = 2,
    UsSsn = 3,
    Email = 4,
    IpAddress = 5,
    GenericPhone = 6,
    DateOfBirth = 7,

    // Indian Financial & Statutory
    Aadhaar = 101,
    Pan = 102,
    Gstin = 103,
    Ifsc = 104,
    UpiId = 105,
    IndianMobile = 106,
    DrivingLicense = 107,
    VoterId = 108,
    IndianPassport = 109,

    // Extensibility
    Custom = 999
}

/// <summary>
/// Masking and tokenization behavior.
/// </summary>
public enum MaskingStrategy
{
    /// <summary>
    /// Permanent one-way redaction with standard mask visual cues (e.g. 4532-****-****-9010). Cannot be unmasked.
    /// </summary>
    OneWayRedaction = 1,

    /// <summary>
    /// Reversible format-preserving mask. Looks visually like a mask, but embeds a compact authenticated cryptographic token.
    /// Downstream authorized services can call Unmask() to restore original data identically.
    /// </summary>
    FormatPreservingReversible = 2,

    /// <summary>
    /// Reversible explicit cryptographic token (e.g. ENC{PAN:base64...}).
    /// </summary>
    ReversibleCryptoToken = 3,

    /// <summary>
    /// Cryptographic one-way HMAC or SHA256 hash.
    /// </summary>
    Hash = 4
}
