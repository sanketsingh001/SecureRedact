using System.Security.Cryptography;
using System.Text;
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
    /// Configures 256-bit AES-GCM authenticated encryption using a passphrase (derived with PBKDF2-HMAC-SHA256).
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
    /// Configures zero-downtime key rotation with an active key ID and historical decryption keys.
    /// </summary>
    public PiiEngineBuilder WithKeyRing(string activeKeyId, IReadOnlyDictionary<string, byte[]> keyRing)
    {
        _options.CryptoProvider = new AesGcmReversibleCrypto(activeKeyId, keyRing);
        return this;
    }

    /// <summary>
    /// Configures a dedicated secret key for deterministic HMAC-SHA256 one-way hashing (<see cref="MaskingStrategy.Hash"/>).
    /// </summary>
    public PiiEngineBuilder WithHashKey(string secret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);
        _options.HashKey = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        return this;
    }

    /// <summary>
    /// Configures a raw byte secret key for deterministic HMAC-SHA256 one-way hashing (<see cref="MaskingStrategy.Hash"/>).
    /// </summary>
    public PiiEngineBuilder WithHashKey(byte[] keyBytes)
    {
        ArgumentNullException.ThrowIfNull(keyBytes);
        if (keyBytes.Length == 0)
            throw new ArgumentException("Hash key cannot be empty.", nameof(keyBytes));
        _options.HashKey = (byte[])keyBytes.Clone();
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
    /// Adds global financial and contact identifiers (Credit/Debit Card via Luhn+IIN, IBAN via Mod-97, US SSN, Email, IPv4/IPv6, International Phone, Context-gated DOB).
    /// </summary>
    public PiiEngineBuilder AddGlobalFintechRecognizers()
    {
        _options.Recognizers.Add(new LuhnCreditCardRecognizer());
        _options.Recognizers.Add(new IbanRecognizer());
        _options.Recognizers.Add(new SsnRecognizer());
        _options.Recognizers.Add(new EmailRecognizer());
        _options.Recognizers.Add(new IpAddressRecognizer());
        _options.Recognizers.Add(new GenericPhoneRecognizer());
        _options.Recognizers.Add(new DateOfBirthRecognizer());
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
    /// Registers a custom user-defined regex recognizer and optional validator (with ReDoS match timeout).
    /// </summary>
    public PiiEngineBuilder AddCustomRecognizer(
        string name,
        string pattern,
        PiiType piiType = PiiType.Custom,
        string? customTypeName = null,
        Func<string, bool>? validator = null,
        double confidence = 0.95)
    {
        _options.Recognizers.Add(new CustomPatternRecognizer(
            name,
            pattern,
            piiType,
            customTypeName,
            validator,
            System.Text.RegularExpressions.RegexOptions.Compiled,
            confidence));
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
    /// Configures how the engine behaves when an unrecoverable error occurs (default is Throw).
    /// </summary>
    public PiiEngineBuilder WithErrorBehavior(PiiErrorBehavior behavior)
    {
        _options.ErrorBehavior = behavior;
        return this;
    }

    /// <summary>
    /// Sets the minimum confidence score required to apply a mask.
    /// </summary>
    public PiiEngineBuilder SetMinConfidence(double minConfidence)
    {
        _options.MinConfidence = Math.Clamp(minConfidence, 0.0, 1.0);
        return this;
    }

    /// <summary>
    /// Configures custom key hints to boost or demote confidence scores based on JSON property names.
    /// </summary>
    public PiiEngineBuilder WithKeyHints(Action<FintechGuard.Pii.Context.KeyHintRegistry> configure)
    {
        configure?.Invoke(_options.KeyHints);
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
    /// Caps concurrent engine operations to target at most approximately <paramref name="maxCpuPercent"/>% of server CPU cores.
    /// </summary>
    public PiiEngineBuilder WithMaxCpuUsage(int maxCpuPercent, TimeSpan? acquireTimeout = null)
    {
        _options.MaxConcurrentOperations = PiiEngineOptions.CalculateConcurrencyForCpuPercent(maxCpuPercent);
        if (acquireTimeout.HasValue)
            _options.ConcurrencyAcquireTimeout = acquireTimeout.Value;
        return this;
    }

    /// <summary>
    /// Sets an explicit cap on concurrent operations executing inside the engine (0 = unlimited).
    /// </summary>
    public PiiEngineBuilder WithMaxConcurrency(int maxConcurrentOperations, TimeSpan? acquireTimeout = null)
    {
        if (maxConcurrentOperations < 0)
            throw new ArgumentOutOfRangeException(nameof(maxConcurrentOperations), "Max concurrency cannot be negative.");
        _options.MaxConcurrentOperations = maxConcurrentOperations;
        if (acquireTimeout.HasValue)
            _options.ConcurrencyAcquireTimeout = acquireTimeout.Value;
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
