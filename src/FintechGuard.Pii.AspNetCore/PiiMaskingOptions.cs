using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.AspNetCore;

/// <summary>
/// Configuration options for the PII masking middleware.
/// </summary>
public class PiiMaskingOptions
{
    /// <summary>
    /// AES-256 master key passphrase for reversible format-preserving masking.
    /// If null, one-way redaction will be used.
    /// </summary>
    public string? MasterKey { get; set; }

    /// <summary>
    /// Raw 16/24/32-byte AES key. Takes precedence over MasterKey passphrase.
    /// </summary>
    public byte[]? MasterKeyBytes { get; set; }

    /// <summary>
    /// Whether to mask PII in incoming request bodies. Default: true.
    /// </summary>
    public bool MaskRequests { get; set; } = true;

    /// <summary>
    /// Whether to mask PII in outgoing response bodies. Default: true.
    /// </summary>
    public bool MaskResponses { get; set; } = true;

    /// <summary>
    /// Whether to unmask reversible tokens in incoming request bodies (for authorized upstream services). Default: false.
    /// </summary>
    public bool UnmaskRequests { get; set; } = false;

    /// <summary>
    /// Default masking strategy. Default: FormatPreservingReversible.
    /// </summary>
    public MaskingStrategy DefaultStrategy { get; set; } = MaskingStrategy.FormatPreservingReversible;

    /// <summary>
    /// Request paths to exclude from PII processing (e.g. "/health", "/metrics", "/swagger").
    /// Matched using StartsWith (case-insensitive).
    /// </summary>
    public List<string> ExcludePaths { get; set; } = new();

    /// <summary>
    /// HTTP methods to exclude from PII processing (e.g. "OPTIONS", "HEAD"). Default: OPTIONS, HEAD.
    /// </summary>
    public HashSet<string> ExcludeMethods { get; set; } = new(StringComparer.OrdinalIgnoreCase) { "OPTIONS", "HEAD" };

    /// <summary>
    /// Content types to process. Default: "application/json".
    /// </summary>
    public HashSet<string> ProcessContentTypes { get; set; } = new(StringComparer.OrdinalIgnoreCase) { "application/json" };

    /// <summary>
    /// Whether to include Indian fintech recognizers (Aadhaar, PAN, GSTIN, IFSC, UPI, etc.). Default: true.
    /// </summary>
    public bool UseIndianFintechRecognizers { get; set; } = true;

    /// <summary>
    /// Whether to include global financial recognizers (Credit Card, IBAN, SSN, Email, IP). Default: true.
    /// </summary>
    public bool UseGlobalFintechRecognizers { get; set; } = true;

    /// <summary>
    /// Optional callback to configure the PiiEngineBuilder with additional custom recognizers or strategies.
    /// </summary>
    public Action<PiiEngineBuilder>? ConfigureEngine { get; set; }

    /// <summary>
    /// Maximum request/response body size to process (in bytes). Bodies larger than this are passed through without scanning.
    /// Default: 10 MB.
    /// </summary>
    public long MaxBodySizeBytes { get; set; } = 10 * 1024 * 1024;
}
