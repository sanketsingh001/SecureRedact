using System.Text.Json;
using FintechGuard.Pii.Core;
using FluentAssertions;
using Xunit;

namespace FintechGuard.Pii.Tests;

public class EdgeCaseTestSuite
{
    private readonly IPiiEngine _engine;

    public EdgeCaseTestSuite()
    {
        _engine = PiiEngineBuilder.Create()
            .WithMasterKey("fintech-super-secret-master-key-32b!")
            .AddDefaultRecognizers()
            .SetDefaultStrategy(MaskingStrategy.FormatPreservingReversible)
            .Build();
    }

    [Fact]
    public void MaskJson_WithComprehensiveEdgeCases_MasksPiiAndPreservesTraps()
    {
        string edgeCasesJson = """
        {
          "deeply_nested_arbitrary_keys": {
            "level_1_key_x0": {
              "level_2_key_a99": {
                "level_3_key_obj": {
                  "level_4_array": [
                    {
                      "level_5_subitem": {
                        "level_6_deep_target": {
                          "valid_credit_card_luhn": "4532-0151-1283-0366",
                          "valid_indian_pan": "ABCPE1234F",
                          "valid_upi_handle": "vikram.sharma@okhdfcbank"
                        }
                      }
                    }
                  ]
                }
              }
            }
          },
          "statutory_and_global_pii_valid": {
            "credit_card_visa": "4532-0151-1283-0366",
            "aadhaar_number": "2123 4567 8901",
            "pan_card_individual": "ABCPE1234F",
            "gstin_maharashtra": "27ABCPE1234F1Z5",
            "ifsc_bank_code": "HDFC0000240",
            "upi_vpa": "vikram.sharma@okhdfcbank",
            "global_iban_germany": "DE89370400440532013000",
            "us_ssn": "123-45-6789",
            "email_address": "customer.finance@secure-fintech.com",
            "ipv4_address": "192.168.1.100",
            "indian_mobile": "+91 9876543210"
          },
          "false_positive_traps_must_NOT_be_masked": {
            "card_candidate_failing_luhn_mod10": "4532-0151-1283-0367",
            "aadhaar_candidate_failing_verhoeff": "2123 4567 8902",
            "pan_candidate_invalid_4th_char_entity": "ABCXE1234F",
            "gstin_candidate_invalid_state_code_99": "99XYZPE1234F1Z5",
            "ifsc_candidate_invalid_5th_char_not_zero": "HDFC1000240",
            "upi_candidate_unrecognized_psp_domain": "vikram.sharma@notabank",
            "ssn_candidate_illegal_area_000": "000-45-6789",
            "ssn_candidate_illegal_area_666": "666-45-6789",
            "ipv4_candidate_out_of_range_octets": "999.888.777.666",
            "mobile_candidate_invalid_starting_digit_1": "+91 1234567890",
            "safe_business_token_order": "ORDER_REF_TXN_987654321",
            "safe_currency_code": "EUR_CURRENCY_CODE",
            "safe_transaction_status": "TXN_APPROVED_BY_GATEWAY"
          },
          "mixed_datatypes_and_edge_values": {
            "safe_numeric_id_not_a_card": 9876543210123456,
            "transaction_amount_float": 14999.75,
            "negative_integer": -42,
            "zero_integer": 0,
            "boolean_true": true,
            "boolean_false": false,
            "explicit_null_field": null,
            "empty_nested_object": {},
            "empty_array": [],
            "array_of_primitives": [
              "EUR",
              100,
              true,
              null,
              "4532-0151-1283-0366"
            ]
          }
        }
        """;

        string masked = _engine.MaskJson(edgeCasesJson);

        using var doc = JsonDocument.Parse(masked);

        // 1. Valid PII targets are properly masked with format-preserving reversible tokens
        var statutory = doc.RootElement.GetProperty("statutory_and_global_pii_valid");
        statutory.GetProperty("credit_card_visa").GetString().Should().StartWith("4532-****-****-0366#fp[");
        statutory.GetProperty("aadhaar_number").GetString().Should().StartWith("XXXX XXXX 8901#fp[");
        statutory.GetProperty("pan_card_individual").GetString().Should().StartWith("AB****234F#fp[");
        statutory.GetProperty("gstin_maharashtra").GetString().Should().StartWith("27*****1234**5#fp[");
        statutory.GetProperty("ifsc_bank_code").GetString().Should().StartWith("HD*******40#fp[");
        statutory.GetProperty("upi_vpa").GetString().Should().Contain("@okhdfcbank#fp[");
        statutory.GetProperty("global_iban_germany").GetString().Should().StartWith("DE89**************3000#fp[");
        statutory.GetProperty("us_ssn").GetString().Should().StartWith("***-**-6789#fp[");
        statutory.GetProperty("email_address").GetString().Should().Contain("@secure-fintech.com#fp[");
        statutory.GetProperty("ipv4_address").GetString().Should().Contain("#fp[");
        statutory.GetProperty("indian_mobile").GetString().Should().Contain("#fp[");

        // 2. Traps must NOT be masked (algorithm check-digit eliminates them)
        var traps = doc.RootElement.GetProperty("false_positive_traps_must_NOT_be_masked");
        traps.GetProperty("card_candidate_failing_luhn_mod10").GetString().Should().Be("4532-0151-1283-0367");
        traps.GetProperty("aadhaar_candidate_failing_verhoeff").GetString().Should().Be("2123 4567 8902");
        traps.GetProperty("pan_candidate_invalid_4th_char_entity").GetString().Should().Be("ABCXE1234F");
        traps.GetProperty("gstin_candidate_invalid_state_code_99").GetString().Should().Be("99XYZPE1234F1Z5");
        traps.GetProperty("ifsc_candidate_invalid_5th_char_not_zero").GetString().Should().Be("HDFC1000240");
        traps.GetProperty("upi_candidate_unrecognized_psp_domain").GetString().Should().Be("vikram.sharma@notabank");
        traps.GetProperty("ssn_candidate_illegal_area_000").GetString().Should().Be("000-45-6789");
        traps.GetProperty("ssn_candidate_illegal_area_666").GetString().Should().Be("666-45-6789");
        traps.GetProperty("ipv4_candidate_out_of_range_octets").GetString().Should().Be("999.888.777.666");
        traps.GetProperty("mobile_candidate_invalid_starting_digit_1").GetString().Should().Be("+91 1234567890");
        traps.GetProperty("safe_business_token_order").GetString().Should().Be("ORDER_REF_TXN_987654321");
        traps.GetProperty("safe_currency_code").GetString().Should().Be("EUR_CURRENCY_CODE");
        traps.GetProperty("safe_transaction_status").GetString().Should().Be("TXN_APPROVED_BY_GATEWAY");

        // 3. Primitives, nulls, booleans, and numbers must remain intact
        var mixed = doc.RootElement.GetProperty("mixed_datatypes_and_edge_values");
        mixed.GetProperty("safe_numeric_id_not_a_card").GetInt64().Should().Be(9876543210123456);
        mixed.GetProperty("transaction_amount_float").GetDecimal().Should().Be(14999.75m);
        mixed.GetProperty("negative_integer").GetInt32().Should().Be(-42);
        mixed.GetProperty("zero_integer").GetInt32().Should().Be(0);
        mixed.GetProperty("boolean_true").GetBoolean().Should().BeTrue();
        mixed.GetProperty("boolean_false").GetBoolean().Should().BeFalse();
        mixed.GetProperty("explicit_null_field").ValueKind.Should().Be(JsonValueKind.Null);

        // 4. Deeply nested value masked correctly
        var deep = doc.RootElement
            .GetProperty("deeply_nested_arbitrary_keys")
            .GetProperty("level_1_key_x0")
            .GetProperty("level_2_key_a99")
            .GetProperty("level_3_key_obj")
            .GetProperty("level_4_array")[0]
            .GetProperty("level_5_subitem")
            .GetProperty("level_6_deep_target");

        deep.GetProperty("valid_credit_card_luhn").GetString().Should().StartWith("4532-****-****-0366#fp[");
        deep.GetProperty("valid_indian_pan").GetString().Should().StartWith("AB****234F#fp[");
        deep.GetProperty("valid_upi_handle").GetString().Should().Contain("@okhdfcbank#fp[");

        // 5. Unmasking must restore the exact original JSON identically
        string unmasked = _engine.UnmaskJson(masked);
        using var originalDoc = JsonDocument.Parse(edgeCasesJson);
        using var restoredDoc = JsonDocument.Parse(unmasked);

        string normOrig = JsonSerializer.Serialize(originalDoc.RootElement);
        string normRest = JsonSerializer.Serialize(restoredDoc.RootElement);
        normRest.Should().Be(normOrig);
    }
}
