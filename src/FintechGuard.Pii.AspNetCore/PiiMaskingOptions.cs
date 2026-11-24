using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.AspNetCore;

/// <summary>
/// Controls middleware behavior when a request or response payload exceeds <see cref="PiiMaskingOptions.MaxBodySizeBytes"/>.
/// </summary>
public enum OversizedPayloadBehavior
{
    /// <summary>
    /// Fail-closed default: reject oversized payloads with HTTP 413 Payload Too Large so uninspected PII never leaks.
    /// </summary>
    RejectWith413 = 0,

    /// <summary>
    /// Opt-in passthrough: skip masking for oversized payloads.
    /// </summary>
    PassThrough = 1
}

/// <summary>
/// Controls middleware behavior when all server CPU PII inspection slots are occupied.
/// </summary>
public enum ConcurrencyLimitBehavior
{
    /// <summary>
    /// Fail-closed default: reject excess requests with HTTP 503 Service Unavailable and Retry-After header once timeout expires.
    /// </summary>
    RejectWith503 = 0,

    /// <summary>
    /// Wait asynchronously until a CPU inspection slot becomes available (respecting request cancellation).
    /// </summary>
    Wait = 1
}

/// <summary>
/// Configuration options for the PII masking middleware.
/// </summary>
public class PiiMaskingOptions
{
    /// <summary>
    /// AES-256 master key passphrase for reversible format-preserving masking.
    /// If null (and MasterKeyBytes is null), reversible strategies fall back to OneWayRedaction.
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
    /// Behavior when request or response bodies exceed <see cref="MaxBodySizeBytes"/>.
    /// Default is <see cref="OversizedPayloadBehavior.RejectWith413"/> (fail-closed).
    /// </summary>
    public OversizedPayloadBehavior OversizedBehavior { get; set; } = OversizedPayloadBehavior.RejectWith413;

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
    /// Maximum request/response body size to inspect (in bytes). Default: 10 MB.
    /// </summary>
    public long MaxBodySizeBytes { get; set; } = 10 * 1024 * 1024;

    /// <summary>
    /// Target maximum server CPU percentage (1-100) for concurrent PII inspection (0 = unlimited). Ignored if <see cref="MaxConcurrentRequests"/> &gt; 0.
    /// </summary>
    public int MaxCpuPercent { get; set; } = 0;

    /// <summary>
    /// Explicit cap on concurrent CPU-bound request/response PII masking operations (0 = derive from <see cref="MaxCpuPercent"/> or unlimited).
    /// </summary>
    public int MaxConcurrentRequests { get; set; } = 0;

    /// <summary>
    /// Wait timeout in milliseconds for a CPU inspection slot when <see cref="ConcurrencyExceededBehavior"/> is <see cref="ConcurrencyLimitBehavior.RejectWith503"/>. Default: 2000 ms.
    /// </summary>
    public int ConcurrencyAcquireTimeoutMs { get; set; } = 2000;

    /// <summary>
    /// Behavior when the server CPU inspection bulkhead is saturated. Default: <see cref="ConcurrencyLimitBehavior.RejectWith503"/>.
    /// </summary>
    public ConcurrencyLimitBehavior ConcurrencyExceededBehavior { get; set; } = ConcurrencyLimitBehavior.RejectWith503;
}
