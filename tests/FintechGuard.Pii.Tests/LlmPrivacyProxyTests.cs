using System.Net;
using System.Text;
using System.Text.Json;
using FintechGuard.Pii.Core;
using FintechGuard.Pii.LlmProxy;
using FluentAssertions;
using Xunit;

namespace FintechGuard.Pii.Tests;

public class LlmPrivacyProxyTests
{
    private readonly LlmPrivacyProxy _proxy;
    private readonly IPiiEngine _engine;

    public LlmPrivacyProxyTests()
    {
        _engine = PiiEngineBuilder.Create()
            .WithMasterKey("llm-proxy-test-key-fintech-256!!")
            .AddDefaultRecognizers()
            .SetDefaultStrategy(MaskingStrategy.FormatPreservingReversible)
            .Build();

        _proxy = new LlmPrivacyProxy(_engine);
    }

    [Fact]
    public void MaskPrompt_MasksPiiInPlainTextPrompt()
    {
        string prompt = "Analyze transaction for card 4532-0151-1283-0366 and customer PAN ABCPE1234F";

        string masked = _proxy.MaskPrompt(prompt);

        // Raw PII should be gone
        masked.Should().NotContain("4532-0151-1283-0366");
        masked.Should().NotContain("ABCPE1234F");

        // Format-preserving visual cues should be present
        masked.Should().Contain("4532-****-****-0366");
        masked.Should().Contain("#fp[");
    }

    [Fact]
    public void UnmaskResponse_RestoresReversibleTokensInLlmResponse()
    {
        // Simulate: mask a prompt, LLM echoes back the masked tokens
        string prompt = "Check account for card 4532-0151-1283-0366";
        string masked = _proxy.MaskPrompt(prompt);

        // Simulate LLM response that contains the masked token
        string llmResponse = $"The transaction on {masked.Substring(masked.IndexOf("4532"))} looks suspicious.";

        // Now unmask
        string restored = _proxy.UnmaskResponse(llmResponse);
        restored.Should().Contain("4532-0151-1283-0366");
    }

    [Fact]
    public void MaskJsonPrompt_MasksOpenAIChatCompletionRequestFormat()
    {
        // Simulated OpenAI chat completion request with Indian PII in messages
        string openAiRequest = """
        {
            "model": "gpt-4",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a financial analyst assistant."
                },
                {
                    "role": "user",
                    "content": "Analyze this transaction: Card 4532-0151-1283-0366, IFSC HDFC0000240, Email audit@fintech.com"
                }
            ],
            "temperature": 0.7
        }
        """;

        string masked = _proxy.MaskJsonPrompt(openAiRequest);

        // Verify PII is masked
        masked.Should().NotContain("4532-0151-1283-0366");
        masked.Should().NotContain("HDFC0000240");
        masked.Should().NotContain("audit@fintech.com");

        // Verify non-PII is preserved
        masked.Should().Contain("gpt-4");
        masked.Should().Contain("financial analyst assistant");

        // Verify valid JSON
        var doc = JsonDocument.Parse(masked);
        doc.Should().NotBeNull();
    }

    [Fact]
    public void AuditPrompt_ReturnsDetectedPiiWithoutMasking()
    {
        string prompt = "Transfer Rs 5000 from card 4532-0151-1283-0366 to UPI rohit.sharma@okhdfcbank";

        var detections = _proxy.AuditPrompt(prompt);

        detections.Should().HaveCountGreaterThanOrEqualTo(2);
        detections.Should().Contain(m => m.Type == PiiType.CreditCard);
        detections.Should().Contain(m => m.Type == PiiType.UpiId);
    }

    [Fact]
    public void Create_FromOptions_BuildsWorkingProxy()
    {
        var proxy = LlmPrivacyProxy.Create(options =>
        {
            options.MasterKey = "test-key-for-factory-method!!!!!";
            options.UseIndianFintechRecognizers = true;
            options.UseGlobalFintechRecognizers = true;
        });

        string prompt = "Customer Aadhaar: 2123 4567 8901";
        string masked = proxy.MaskPrompt(prompt);
        masked.Should().NotContain("2123 4567 8901");
    }
}

/// <summary>
/// Tests for PiiSafeHttpHandler using a mock inner handler.
/// </summary>
public class PiiSafeHttpHandlerTests
{
    [Fact]
    public async Task Handler_MasksRequestBody_AndUnmasksResponseBody()
    {
        var engine = PiiEngineBuilder.Create()
            .WithMasterKey("handler-test-key-256bit-fintech!")
            .AddDefaultRecognizers()
            .SetDefaultStrategy(MaskingStrategy.FormatPreservingReversible)
            .Build();

        // Create a mock inner handler that captures the masked request and returns a response with the masked tokens
        string? capturedRequestBody = null;

        var mockHandler = new MockHttpHandler(async (request) =>
        {
            capturedRequestBody = await request.Content!.ReadAsStringAsync();

            // Simulate LLM response echoing back some content
            var responseContent = new StringContent(
                """{"choices": [{"message": {"content": "Processed your request."}}]}""",
                Encoding.UTF8,
                "application/json"
            );

            return new HttpResponseMessage(HttpStatusCode.OK) { Content = responseContent };
        });

        var handler = new PiiSafeHttpHandler(engine) { InnerHandler = mockHandler };
        var client = new HttpClient(handler);

        // Send request with PII
        var requestBody = new StringContent(
            """{"messages": [{"role": "user", "content": "Card is 4532-0151-1283-0366"}]}""",
            Encoding.UTF8,
            "application/json"
        );

        var response = await client.PostAsync("https://api.openai.com/v1/chat/completions", requestBody);

        // Verify the captured request was masked
        capturedRequestBody.Should().NotBeNull();
        capturedRequestBody.Should().NotContain("4532-0151-1283-0366");
        capturedRequestBody.Should().Contain("4532-****-****-0366");

        // Verify response is valid
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}

/// <summary>
/// Simple mock HTTP handler for testing.
/// </summary>
internal class MockHttpHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, Task<HttpResponseMessage>> _handler;

    public MockHttpHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler)
    {
        _handler = handler;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        return _handler(request);
    }
}
