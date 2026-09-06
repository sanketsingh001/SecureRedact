using FintechGuard.Pii.Crypto;
using FintechGuard.Pii.Recognizers;

namespace FintechGuard.Pii.Core;

/// <summary>
/// Fluent builder for constructing and configuring a high-performance PiiEngine.
/// </summary>
public sealed class PiiEngineBuilder
{
    private readonly PiiEngineOptions _options = new();

    public static PiiEngineBuilder Create() => new();

    /// <summary>
    /// Configures 256-bit AES-GCM authenticated encryption using a passphrase.
    /// </summary>
    public PiiEngineBuilder WithMasterKey(string passphrase)
    {
        _options.CryptoProvider = AesGcmReversibleCrypto.FromPassphrase(passphrase);
        return this;
    }

    /// <summary>
    /// Configures AES-GCM authenticated encryption using raw 16, 24, or 32-byte key.
    /// </summary>
    public PiiEngineBuilder WithMasterKey(byte[] keyBytes)
    {
        _options.CryptoProvider = new AesGcmReversibleCrypto(keyBytes);
        return this;
    }

    /// <summary>
    /// Sets a custom cryptographic tokenization provider.
    /// </summary>
    public PiiEngineBuilder WithCryptoProvider(IReversibleCrypto crypto)
    {
        _options.CryptoProvider = crypto;
        return this;
    }

    /// <summary>
    /// Adds all standard Indian fintech and statutory identifiers (Aadhaar, PAN, GSTIN, IFSC, UPI, Mobile, DL, VoterID, Passport).
    /// </summary>
    public PiiEngineBuilder AddIndianFintechRecognizers()
    {
        _options.Recognizers.Add(new AadhaarRecognizer());
        _options.Recognizers.Add(new PanRecognizer());
        _options.Recognizers.Add(new GstinRecognizer());
        _options.Recognizers.Add(new IfscRecognizer());
        _options.Recognizers.Add(new UpiRecognizer());
        _options.Recognizers.Add(new IndianMobileRecognizer());
        _options.Recognizers.Add(new DrivingLicenseRecognizer());
        _options.Recognizers.Add(new VoterIdRecognizer());
        _options.Recognizers.Add(new PassportRecognizer());
        return this;
    }

    /// <summary>
    /// Adds global financial and contact identifiers (Credit/Debit Card via Luhn, IBAN via Mod-97, US SSN, Email, IP Address).
    /// </summary>
    public PiiEngineBuilder AddGlobalFintechRecognizers()
    {
        _options.Recognizers.Add(new LuhnCreditCardRecognizer());
        _options.Recognizers.Add(new IbanRecognizer());
        _options.Recognizers.Add(new SsnRecognizer());
        _options.Recognizers.Add(new EmailRecognizer());
        _options.Recognizers.Add(new IpAddressRecognizer());
        return this;
    }

    /// <summary>
    /// Adds both Indian and Global standard financial recognizers.
    /// </summary>
    public PiiEngineBuilder AddDefaultRecognizers()
    {
        return AddIndianFintechRecognizers().AddGlobalFintechRecognizers();
    }

    /// <summary>
    /// Registers a custom user-defined regex recognizer and optional validator.
    /// </summary>
    public PiiEngineBuilder AddCustomRecognizer(
        string name,
        string pattern,
        PiiType piiType = PiiType.Custom,
        string? customTypeName = null,
        Func<string, bool>? validator = null)
    {
        _options.Recognizers.Add(new CustomPatternRecognizer(name, pattern, piiType, customTypeName, validator));
        return this;
    }

    /// <summary>
    /// Registers an arbitrary IPiiRecognizer instance.
    /// </summary>
    public PiiEngineBuilder AddRecognizer(IPiiRecognizer recognizer)
    {
        ArgumentNullException.ThrowIfNull(recognizer);
        _options.Recognizers.Add(recognizer);
        return this;
    }

    /// <summary>
    /// Sets the default masking strategy across all PII types.
    /// </summary>
    public PiiEngineBuilder SetDefaultStrategy(MaskingStrategy strategy)
    {
        _options.DefaultStrategy = strategy;
        return this;
    }

    /// <summary>
    /// Configures a specific masking strategy for a given PII type.
    /// </summary>
    public PiiEngineBuilder SetStrategy(PiiType type, MaskingStrategy strategy)
    {
        _options.StrategyOverrides[type] = strategy;
        return this;
    }

    /// <summary>
    /// Sets the mask character (default is '*').
    /// </summary>
    public PiiEngineBuilder SetMaskCharacter(char maskChar)
    {
        _options.MaskCharacter = maskChar;
        return this;
    }

    /// <summary>
    /// Builds and returns the configured IPiiEngine.
    /// </summary>
    public IPiiEngine Build()
    {
        return new PiiEngine(_options);
    }
}
