using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.LlmProxy;

/// <summary>
/// Factory and convenience methods for creating PII-safe HttpClient instances
/// that transparently mask PII before sending to LLM APIs (OpenAI, Gemini, Claude, etc.).
/// </summary>
public static class PiiSafeClientFactory
{
    /// <summary>
    /// Creates a PII-safe HttpClient that masks prompts and unmasks responses.
    ///
    /// Usage:
    ///   var client = PiiSafeClientFactory.CreateForOpenAI(engine, "sk-your-api-key");
    ///   var response = await client.PostAsync("/v1/chat/completions", content);
    /// </summary>
    public static HttpClient CreateForOpenAI(IPiiEngine engine, string apiKey)
    {
        var handler = new PiiSafeHttpHandler(engine)
        {
            InnerHandler = new HttpClientHandler()
        };

        var client = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://api.openai.com/")
        };

        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {apiKey}");
        return client;
    }

    /// <summary>
    /// Creates a PII-safe HttpClient for Google Gemini API.
    /// </summary>
    public static HttpClient CreateForGemini(IPiiEngine engine, string apiKey)
    {
        var handler = new PiiSafeHttpHandler(engine)
        {
            InnerHandler = new HttpClientHandler()
        };

        var client = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://generativelanguage.googleapis.com/")
        };

        // Gemini uses query param for API key, added per-request
        return client;
    }

    /// <summary>
    /// Creates a PII-safe HttpClient for Anthropic Claude API.
    /// </summary>
    public static HttpClient CreateForClaude(IPiiEngine engine, string apiKey)
    {
        var handler = new PiiSafeHttpHandler(engine)
        {
            InnerHandler = new HttpClientHandler()
        };

        var client = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://api.anthropic.com/")
        };

        client.DefaultRequestHeaders.Add("x-api-key", apiKey);
        client.DefaultRequestHeaders.Add("anthropic-version", "2024-10-22");
        return client;
    }

    /// <summary>
    /// Creates a PII-safe HttpClient for any arbitrary LLM endpoint.
    /// </summary>
    public static HttpClient Create(IPiiEngine engine, string baseUrl, bool maskRequests = true, bool unmaskResponses = true)
    {
        var handler = new PiiSafeHttpHandler(engine, maskRequests, unmaskResponses)
        {
            InnerHandler = new HttpClientHandler()
        };

        var client = new HttpClient(handler)
        {
            BaseAddress = new Uri(baseUrl)
        };

        return client;
    }

    /// <summary>
    /// Wraps an existing HttpClient pipeline with PII masking/unmasking via a DelegatingHandler.
    /// Useful for integrating into IHttpClientFactory patterns.
    /// </summary>
    public static PiiSafeHttpHandler CreateHandler(IPiiEngine engine, bool maskRequests = true, bool unmaskResponses = true)
    {
        return new PiiSafeHttpHandler(engine, maskRequests, unmaskResponses);
    }
}
