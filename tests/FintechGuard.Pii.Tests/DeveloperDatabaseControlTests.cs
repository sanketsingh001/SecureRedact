using System.Text.Json;
using FintechGuard.Pii.Core;
using Xunit;

namespace FintechGuard.Pii.Tests;

public class DeveloperDatabaseControlTests
{
    private readonly IPiiEngine _engine;

    public DeveloperDatabaseControlTests()
    {
        _engine = PiiEngineBuilder.Create()
            .WithMasterKey("fintech-db-control-key-256bit!!")
            .AddDefaultRecognizers()
            .SetDefaultStrategy(MaskingStrategy.FormatPreservingReversible)
            .Build();
    }

    [Fact]
    public void DeveloperControls_OnlyMaskCardsAndAadhaar_LeavesEmailAndPanPlaintext()
    {
        // Scenario: Developer is sending user registration data to DB.
        // Compliance requires Card and Aadhaar masked, but marketing needs Email in plaintext in DB.
        string incomingJson = """
        {
          "card_num": "4532-0151-1283-0366",
          "national_uid": "2123 4567 8901",
          "tax_id": "ABCPE1234F",
          "contact_email": "customer@fintech.com"
        }
        """;

        // Developer explicitly controls the masking scope before sending to DB:
        string dbJson = _engine.MaskJson(incomingJson, scope =>
        {
            scope.IncludeTypes = [PiiType.CreditCard, PiiType.Aadhaar];
        });

        // 1. Card and Aadhaar MUST be masked
        Assert.DoesNotContain("4532-0151-1283-0366", dbJson);
        Assert.DoesNotContain("2123 4567 8901", dbJson);
        Assert.Contains("4532-****-****-0366#fp[", dbJson);

        // 2. Email and PAN MUST stay in plaintext because developer chose not to mask them
        Assert.Contains("\"tax_id\":\"ABCPE1234F\"", dbJson);
        Assert.Contains("\"contact_email\":\"customer@fintech.com\"", dbJson);
    }

    [Fact]
    public void DeveloperControls_ExcludeSpecificKeys_FromEverBeingMasked()
    {
        // Scenario: A field named "public_display_card" holds card digits intended for display,
        // while "real_card" is the one to protect.
        string incomingJson = """
        {
          "real_card": "4532-0151-1283-0366",
          "public_display_card": "4532-0151-1283-0366"
        }
        """;

        string dbJson = _engine.MaskJson(incomingJson, scope =>
        {
            scope.ExcludeKeys = ["public_display_card"];
        });

        // "real_card" is masked
        Assert.Contains("\"real_card\":\"4532-****-****-0366#fp[", dbJson);

        // "public_display_card" is preserved intact
        Assert.Contains("\"public_display_card\":\"4532-0151-1283-0366\"", dbJson);
    }

    [Fact]
    public void DeveloperControls_StrategyOverride_ForAuditLogDbVsPrimaryDb()
    {
        string incomingJson = """{ "card": "4532-0151-1283-0366" }""";

        // 1. Sending to Primary DB: developer uses Reversible (needs to charge card later)
        string primaryDbJson = _engine.MaskJson(incomingJson, scope =>
        {
            scope.StrategyOverride = MaskingStrategy.FormatPreservingReversible;
        });
        Assert.Contains("#fp[", primaryDbJson);

        // 2. Sending to Audit Log DB: developer uses One-Way (permanent redaction, never unmasked)
        string auditDbJson = _engine.MaskJson(incomingJson, scope =>
        {
            scope.StrategyOverride = MaskingStrategy.OneWayRedaction;
        });
        Assert.DoesNotContain("#fp[", auditDbJson);
        Assert.Equal("""{"card":"4532-****-****-0366"}""", auditDbJson);
    }

    [Fact]
    public void DeveloperControls_FullDatabaseSaveAndReadLifecycle()
    {
        // STEP 1: Developer receives raw webhook from payment gateway
        string rawWebhookJson = """
        {
          "order_id": "ORD-2026-9021",
          "customer": {
            "card": "4532-0151-1283-0366",
            "pan": "ABCPE1234F",
            "upi": "merchant@okhdfcbank"
          },
          "status": "CAPTURED"
        }
        """;

        // STEP 2: Developer explicitly sanitizes before inserting into DB
        string jsonToPersistInDb = _engine.MaskJson(rawWebhookJson);

        // Verify: database string contains NO raw plaintext card or PAN
        Assert.DoesNotContain("4532-0151-1283-0366", jsonToPersistInDb);
        Assert.DoesNotContain("ABCPE1234F", jsonToPersistInDb);

        // STEP 3: Later, an authorized settlement worker reads from DB and explicitly unmasks:
        string unmaskedForSettlement = _engine.UnmaskJson(jsonToPersistInDb);

        // Verify: exact original payload is restored
        Assert.Contains("4532-0151-1283-0366", unmaskedForSettlement);
        Assert.Contains("ABCPE1234F", unmaskedForSettlement);
        Assert.Contains("merchant@okhdfcbank", unmaskedForSettlement);
    }
}
