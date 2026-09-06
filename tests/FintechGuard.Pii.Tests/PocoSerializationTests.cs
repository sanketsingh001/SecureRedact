using FintechGuard.Pii.Attributes;
using FintechGuard.Pii.Core;
using FintechGuard.Pii.Serialization;
using FluentAssertions;
using Xunit;

namespace FintechGuard.Pii.Tests;

public class TransactionDto
{
    public string TransactionId { get; set; } = string.Empty;

    [PiiMask(PiiType.CreditCard)]
    public string CardNumber { get; set; } = string.Empty;

    [PiiMask(PiiType.Pan)]
    public string CustomerPan { get; set; } = string.Empty;

    [PiiIgnore]
    public string PublicIdentifier { get; set; } = string.Empty;

    public decimal Amount { get; set; }
}

public class PocoSerializationTests
{
    [Fact]
    public void Poco_SerializesWithMasking_AndDeserializesWithUnmasking()
    {
        var engine = PiiEngineBuilder.Create()
            .WithMasterKey("top-secret-fintech-key-256bit!")
            .AddDefaultRecognizers()
            .SetDefaultStrategy(MaskingStrategy.FormatPreservingReversible)
            .Build();

        var originalDto = new TransactionDto
        {
            TransactionId = "TXN-2026-998811",
            CardNumber = "4532-0151-1283-0366",
            CustomerPan = "ABCPE1234F",
            PublicIdentifier = "ABCPE1234F", // Decorated with [PiiIgnore], should NOT be masked
            Amount = 15450.50m
        };

        // 1. Serialize with masking
        string json = engine.SerializeWithMasking(originalDto);

        // Verification: Card and PAN are masked in JSON
        json.Should().NotContain("4532-0151-1283-0366");
        json.Should().Contain("4532-****-****-0366");
        json.Should().Contain("#fp[");

        // PublicIdentifier was ignored, so it stays plaintext
        json.Should().Contain("\"PublicIdentifier\":\"ABCPE1234F\"");

        // 2. Deserialize & unmask in authorized consumer
        var restoredDto = engine.DeserializeAndUnmask<TransactionDto>(json);

        restoredDto.Should().NotBeNull();
        restoredDto!.TransactionId.Should().Be("TXN-2026-998811");
        restoredDto.CardNumber.Should().Be("4532-0151-1283-0366");
        restoredDto.CustomerPan.Should().Be("ABCPE1234F");
        restoredDto.Amount.Should().Be(15450.50m);
    }
}
