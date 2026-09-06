using System.Security.Cryptography;
using FintechGuard.Pii.Core;
using FluentAssertions;
using Xunit;

namespace FintechGuard.Pii.Tests;

public class SecurityAndDeepNestingTests
{
    private readonly IPiiEngine _engine;
    private const string MasterKey = "fintech-bank-grade-aes-key-256!!";

    public SecurityAndDeepNestingTests()
    {
        _engine = PiiEngineBuilder.Create()
            .WithMasterKey(MasterKey)
            .AddDefaultRecognizers()
            .SetDefaultStrategy(MaskingStrategy.FormatPreservingReversible)
            .Build();
    }

    [Fact]
    public void DeeplyNestedJson_10Levels_MasksAndUnmasksWith100PercentFidelity()
    {
        string inputJson = """
        {
          "k0": "safe_top",
          "l1": {
            "l2": {
              "l3": {
                "l4": {
                  "l5": {
                    "l6": {
                      "l7": {
                        "l8": {
                          "l9": {
                            "l10_card": "4532-0151-1283-0366",
                            "l10_aadhaar": "2123 4567 8901",
                            "l10_upi": "customer.care@okhdfcbank"
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """;

        string maskedJson = _engine.MaskJson(inputJson);

        // Verify all 10-level deep PII are masked
        maskedJson.Should().NotContain("4532-0151-1283-0366");
        maskedJson.Should().NotContain("2123 4567 8901");
        maskedJson.Should().NotContain("customer.care@okhdfcbank");
        maskedJson.Should().Contain("4532-****-****-0366#fp[");

        // Verify perfect round-trip unmasking
        string unmaskedJson = _engine.UnmaskJson(maskedJson);
        unmaskedJson.Should().Contain("4532-0151-1283-0366");
        unmaskedJson.Should().Contain("2123 4567 8901");
        unmaskedJson.Should().Contain("customer.care@okhdfcbank");
    }

    [Fact]
    public void TamperedCipherToken_ThrowsCryptographicExceptionOnUnmask()
    {
        string raw = "4532-0151-1283-0366";
        string masked = _engine.MaskValue(raw, PiiType.CreditCard);

        // Tamper with the ciphertext by flipping a guaranteed character inside the token
        int fpIdx = masked.IndexOf("#fp[", StringComparison.Ordinal);
        int charToFlip = fpIdx + 6;
        char originalChar = masked[charToFlip];
        char corruptedChar = originalChar == 'X' ? 'Y' : 'X';
        string tampered = masked[..charToFlip] + corruptedChar + masked[(charToFlip + 1)..];

        // UnmaskValue returns the tampered string without crash, or TryUnmaskValue returns false
        _engine.TryUnmaskValue(tampered, out string? unmasked).Should().BeFalse();
        unmasked.Should().BeNull();
    }

    [Fact]
    public void WrongMasterKey_FailsDecryptionGracefully()
    {
        string raw = "4532-0151-1283-0366";
        string masked = _engine.MaskValue(raw, PiiType.CreditCard);

        // Create engine with a different unauthorized key
        var unauthorizedEngine = PiiEngineBuilder.Create()
            .WithMasterKey("wrong-unauthorized-key-different!!")
            .AddDefaultRecognizers()
            .Build();

        unauthorizedEngine.TryUnmaskValue(masked, out string? unmasked).Should().BeFalse();
        unmasked.Should().BeNull();
    }
}
