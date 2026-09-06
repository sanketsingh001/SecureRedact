using System.Text;
using System.Text.Json;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.LlmProxy;

/// <summary>
/// A DelegatingHandler that transparently masks PII in outbound HTTP request bodies (LLM prompts)
/// and unmasks reversible PII tokens in inbound HTTP response bodies (LLM completions).
///
/// Sits in the HttpClient pipeline so any LLM SDK (OpenAI, Gemini, Claude, Anthropic, Azure OpenAI)
/// that uses HttpClient gets automatic PII protection with zero code changes.
///
/// Usage:
///   var handler = new PiiSafeHttpHandler(engine) { InnerHandler = new HttpClientHandler() };
///   var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.openai.com") };
/// </summary>
public class PiiSafeHttpHandler : DelegatingHandler
{
    private readonly IPiiEngine _engine;
    private readonly bool _maskRequests;
    private readonly bool _unmaskResponses;

    public PiiSafeHttpHandler(IPiiEngine engine, bool maskRequests = true, bool unmaskResponses = true)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _maskRequests = maskRequests;
        _unmaskResponses = unmaskResponses;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // 1. Mask PII in outbound request body (LLM prompt)
        if (_maskRequests && request.Content != null)
        {
            string? contentType = request.Content.Headers.ContentType?.MediaType;
            if (IsJsonContent(contentType))
            {
                string requestBody = await request.Content.ReadAsStringAsync(cancellationToken);
                if (!string.IsNullOrWhiteSpace(requestBody))
                {
                    string maskedBody = MaskJsonStrings(requestBody);
                    request.Content = new StringContent(maskedBody, Encoding.UTF8, contentType ?? "application/json");
                }
            }
        }

        // 2. Send to LLM API
        var response = await base.SendAsync(request, cancellationToken);

        // 3. Unmask reversible tokens in inbound response body (LLM completion)
        if (_unmaskResponses && response.Content != null)
        {
            string? responseContentType = response.Content.Headers.ContentType?.MediaType;
            if (IsJsonContent(responseContentType))
            {
                string responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
                if (!string.IsNullOrWhiteSpace(responseBody))
                {
                    string unmaskedBody = UnmaskJsonStrings(responseBody);
                    response.Content = new StringContent(unmaskedBody, Encoding.UTF8, responseContentType ?? "application/json");
                }
            }
        }

        return response;
    }

    /// <summary>
    /// Masks PII inside JSON string values. Handles LLM API request formats where
    /// user content may be in nested "messages[].content" or "prompt" fields.
    /// </summary>
    private string MaskJsonStrings(string json)
    {
        try
        {
            return _engine.MaskJson(json);
        }
        catch
        {
            // If it's not valid JSON (e.g. plain text prompt), mask as a scalar value
            return _engine.MaskValue(json);
        }
    }

    /// <summary>
    /// Unmasks reversible PII tokens inside JSON string values.
    /// </summary>
    private string UnmaskJsonStrings(string json)
    {
        try
        {
            return _engine.UnmaskJson(json);
        }
        catch
        {
            return _engine.UnmaskValue(json);
        }
    }

    private static bool IsJsonContent(string? contentType)
    {
        if (string.IsNullOrEmpty(contentType))
            return false;

        return contentType.Contains("json", StringComparison.OrdinalIgnoreCase);
    }
}
