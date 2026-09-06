using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.LlmProxy;

/// <summary>
/// Configuration options for the LLM Privacy Proxy.
/// </summary>
public class LlmPrivacyOptions
{
    /// <summary>
    /// AES-256 master key passphrase for reversible masking of PII in LLM prompts.
    /// Required for reversible unmasking in responses.
    /// </summary>
    public string? MasterKey { get; set; }

    /// <summary>
    /// Whether to mask PII in outbound prompts/requests. Default: true.
    /// </summary>
    public bool MaskPrompts { get; set; } = true;

    /// <summary>
    /// Whether to unmask reversible tokens found in LLM responses. Default: true.
    /// </summary>
    public bool UnmaskResponses { get; set; } = true;

    /// <summary>
    /// Default masking strategy. Default: FormatPreservingReversible (allows unmasking in responses).
    /// </summary>
    public MaskingStrategy DefaultStrategy { get; set; } = MaskingStrategy.FormatPreservingReversible;

    /// <summary>
    /// Whether to include Indian fintech recognizers. Default: true.
    /// </summary>
    public bool UseIndianFintechRecognizers { get; set; } = true;

    /// <summary>
    /// Whether to include global financial recognizers. Default: true.
    /// </summary>
    public bool UseGlobalFintechRecognizers { get; set; } = true;

    /// <summary>
    /// Optional callback to configure the PiiEngineBuilder.
    /// </summary>
    public Action<PiiEngineBuilder>? ConfigureEngine { get; set; }
}
