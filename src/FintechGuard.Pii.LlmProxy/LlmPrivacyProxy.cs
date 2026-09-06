using System.Text;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.LlmProxy;

/// <summary>
/// High-level wrapper for sending PII-safe prompts to any LLM API.
/// Transparently masks PII in prompts before sending, and unmasks tokens in responses.
///
/// This is the simplest entry point for developers who want to protect customer data
/// when using LLM APIs without modifying their existing code.
///
/// Usage:
///   var proxy = new LlmPrivacyProxy(engine);
///   string safePrompt = proxy.MaskPrompt("Analyze transaction for card 4532-0151-1283-0366");
///   // Send safePrompt to your LLM API...
///   // When you get a response:
///   string restoredResponse = proxy.UnmaskResponse(llmResponse);
/// </summary>
public sealed class LlmPrivacyProxy
{
    private readonly IPiiEngine _engine;

    public LlmPrivacyProxy(IPiiEngine engine)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
    }

    /// <summary>
    /// Creates a new LlmPrivacyProxy from options.
    /// </summary>
    public static LlmPrivacyProxy Create(Action<LlmPrivacyOptions> configure)
    {
        var options = new LlmPrivacyOptions();
        configure(options);

        var builder = PiiEngineBuilder.Create();

        if (!string.IsNullOrEmpty(options.MasterKey))
            builder.WithMasterKey(options.MasterKey);

        if (options.UseIndianFintechRecognizers)
            builder.AddIndianFintechRecognizers();

        if (options.UseGlobalFintechRecognizers)
            builder.AddGlobalFintechRecognizers();

        builder.SetDefaultStrategy(options.DefaultStrategy);
        options.ConfigureEngine?.Invoke(builder);

        return new LlmPrivacyProxy(builder.Build());
    }

    /// <summary>
    /// Masks PII in a plain text prompt before sending to an LLM.
    /// </summary>
    public string MaskPrompt(string prompt)
    {
        if (string.IsNullOrWhiteSpace(prompt))
            return prompt;

        return _engine.MaskValue(prompt);
    }

    /// <summary>
    /// Masks PII in a JSON request body (e.g. OpenAI chat completion request with messages array).
    /// </summary>
    public string MaskJsonPrompt(string jsonBody)
    {
        if (string.IsNullOrWhiteSpace(jsonBody))
            return jsonBody;

        return _engine.MaskJson(jsonBody);
    }

    /// <summary>
    /// Unmasks reversible PII tokens in an LLM response string.
    /// If the LLM echoed back any format-preserving tokens, they are restored to original values.
    /// </summary>
    public string UnmaskResponse(string response)
    {
        if (string.IsNullOrWhiteSpace(response))
            return response;

        return _engine.UnmaskValue(response);
    }

    /// <summary>
    /// Unmasks reversible PII tokens in an LLM JSON response body.
    /// </summary>
    public string UnmaskJsonResponse(string jsonResponse)
    {
        if (string.IsNullOrWhiteSpace(jsonResponse))
            return jsonResponse;

        return _engine.UnmaskJson(jsonResponse);
    }

    /// <summary>
    /// Scans a prompt and returns all detected PII (without masking).
    /// Useful for auditing what PII would have been sent to the LLM.
    /// </summary>
    public IReadOnlyList<PiiMatch> AuditPrompt(string prompt)
    {
        return _engine.Scan(prompt);
    }

    /// <summary>
    /// Returns a PII-safe HttpClient that transparently masks/unmasks for the given LLM provider.
    /// </summary>
    public HttpClient CreateSafeHttpClient(string baseUrl)
    {
        return PiiSafeClientFactory.Create(_engine, baseUrl);
    }
}
