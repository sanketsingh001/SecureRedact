using System.Text.Json;
using FintechGuard.Pii.Core;
using FluentAssertions;
using Xunit;

namespace FintechGuard.Pii.Tests;

public class ArbitraryKeyNestedJsonTests
{
    private readonly IPiiEngine _engine;

    public ArbitraryKeyNestedJsonTests()
    {
        _engine = PiiEngineBuilder.Create()
            .WithMasterKey("fintech-super-secret-master-key-32b!")
            .AddDefaultRecognizers()
            .SetDefaultStrategy(MaskingStrategy.FormatPreservingReversible)
            .Build();
    }

    [Fact]
    public void MaskJson_WithCompletelyArbitraryKeys_MasksNestedValues()
    {
        // Notice key names have ZERO semantic meaning: "x0", "a_99", "k_field", "arr", "item_val"
        string inputJson = """
        {
          "x0": "4532-0151-1283-0366",
          "a_99": "ABCPE1234F",
          "nested_level_1": {
            "k_field": "vikram.sharma@okhdfcbank",
            "arr": [
              { "item_val": "27ABCPE1234F1Z5" },
              { "safe_val": "EUR_CURRENCY_CODE" }
            ]
          }
        }
        """;

        string maskedJson = _engine.MaskJson(inputJson);

        // 1. Raw sensitive values should NO LONGER be present in plaintext
        maskedJson.Should().NotContain("4532-0151-1283-0366");
        maskedJson.Should().NotContain("ABCPE1234F");
        maskedJson.Should().NotContain("vikram.sharma@okhdfcbank");
        maskedJson.Should().NotContain("27ABCPE1234F1Z5");

        // 2. Safe non-PII values should remain completely untouched
        maskedJson.Should().Contain("EUR_CURRENCY_CODE");

        // 3. Format-preserving visual cues should be present
        maskedJson.Should().Contain("4532-****-****-0366");
        maskedJson.Should().Contain("#fp[");

        // 4. JSON must be syntactically valid JSON
        var parsed = JsonDocument.Parse(maskedJson);
        parsed.Should().NotBeNull();
    }

    [Fact]
    public void UnmaskJson_RestoresAllArbitraryNestedValuesIdentically()
    {
        string inputJson = """
        {
          "f_random_1": "4532-0151-1283-0366",
          "f_random_2": "DE89370400440532013000",
          "deep": {
            "level2": {
              "level3": [
                { "k": "customer.finance@secure-fintech.com" },
                { "k2": "HDFC0000240" }
              ]
            }
          }
        }
        """;

        string maskedJson = _engine.MaskJson(inputJson);
        string unmaskedJson = _engine.UnmaskJson(maskedJson);

        // Normalize JSON whitespace for strict structural equality comparison
        using var docOriginal = JsonDocument.Parse(inputJson);
        using var docRestored = JsonDocument.Parse(unmaskedJson);

        string originalNormalized = JsonSerializer.Serialize(docOriginal.RootElement);
        string restoredNormalized = JsonSerializer.Serialize(docRestored.RootElement);

        restoredNormalized.Should().Be(originalNormalized);
    }

    [Fact]
    public void OneWayRedaction_DoesNotIncludeCryptoToken()
    {
        var oneWayEngine = PiiEngineBuilder.Create()
            .AddDefaultRecognizers()
            .SetDefaultStrategy(MaskingStrategy.OneWayRedaction)
            .Build();

        string json = """{ "card": "4532-0151-1283-0366" }""";
        string masked = oneWayEngine.MaskJson(json);

        masked.Should().Contain("4532-****-****-0366");
        masked.Should().NotContain("#fp[");
        masked.Should().NotContain("ENC{");

        // Unmasking should leave one-way redacted value as-is
        string unmasked = oneWayEngine.UnmaskJson(masked);
        unmasked.Should().Be(masked);
    }
}
