using FintechGuard.Pii.Core;
using FintechGuard.Pii.Recognizers;
using Xunit;

namespace FintechGuard.Pii.Tests;

public class RecognizerTests
{
    [Fact]
    public void AadhaarRecognizer_DetectsValidAadhaar()
    {
        var recognizer = new AadhaarRecognizer();
        // 2123 4567 8901 is a valid Verhoeff number
        string text = "Customer uid is 2123 4567 8901 for KYC verification";

        var matches = recognizer.Recognize(text).ToList();

        var match = Assert.Single(matches);
        Assert.Equal(PiiType.Aadhaar, match.Type);
        Assert.Equal("2123 4567 8901", match.RawValue);
    }

    [Fact]
    public void AadhaarRecognizer_IgnoresInvalidAadhaar()
    {
        var recognizer = new AadhaarRecognizer();
        // Altered check digit fails Verhoeff
        string text = "Customer uid is 2123 4567 8900 for KYC";

        var matches = recognizer.Recognize(text).ToList();

        Assert.Empty(matches);
    }

    [Fact]
    public void PanRecognizer_DetectsValidPan()
    {
        var recognizer = new PanRecognizer();
        string text = "Tax assessment for ABCPE1234F completed";

        var matches = recognizer.Recognize(text).ToList();

        var match = Assert.Single(matches);
        Assert.Equal(PiiType.Pan, match.Type);
        Assert.Equal("ABCPE1234F", match.RawValue);
    }

    [Fact]
    public void GstinRecognizer_DetectsValidGstin()
    {
        var recognizer = new GstinRecognizer();
        string text = "Invoice B2B GSTIN: 27ABCPE1234F1ZB confirmed";

        var matches = recognizer.Recognize(text).ToList();

        var match = Assert.Single(matches);
        Assert.Equal(PiiType.Gstin, match.Type);
        Assert.Equal("27ABCPE1234F1ZB", match.RawValue);
    }

    [Fact]
    public void IfscRecognizer_DetectsValidIfsc()
    {
        var recognizer = new IfscRecognizer();
        string text = "Payout via NEFT to HDFC0000240 successfully";

        var matches = recognizer.Recognize(text).ToList();

        var match = Assert.Single(matches);
        Assert.Equal(PiiType.Ifsc, match.Type);
        Assert.Equal("HDFC0000240", match.RawValue);
    }

    [Fact]
    public void UpiRecognizer_DetectsValidUpiHandle()
    {
        var recognizer = new UpiRecognizer();
        string text = "Transfer Rs 500 to rohit.sharma@okhdfcbank instantly";

        var matches = recognizer.Recognize(text).ToList();

        var match = Assert.Single(matches);
        Assert.Equal(PiiType.UpiId, match.Type);
        Assert.Equal("rohit.sharma@okhdfcbank", match.RawValue);
    }

    [Fact]
    public void LuhnCreditCardRecognizer_DetectsValidCard()
    {
        var recognizer = new LuhnCreditCardRecognizer();
        string text = "Billed to card 4532-0151-1283-0366 at POS";

        var matches = recognizer.Recognize(text).ToList();

        var match = Assert.Single(matches);
        Assert.Equal(PiiType.CreditCard, match.Type);
        Assert.Equal("4532-0151-1283-0366", match.RawValue);
    }

    [Fact]
    public void CustomPatternRecognizer_AppliesCustomRuleAndValidator()
    {
        var recognizer = new CustomPatternRecognizer(
            name: "FintechLoanId",
            pattern: @"LOAN-\d{8}",
            piiType: PiiType.Custom,
            customTypeName: "LoanId",
            validator: val => val.EndsWith("99") // Custom rule: only loans ending in 99 are special
        );

        string text = "Found LOAN-12345699 and LOAN-12345600";
        var matches = recognizer.Recognize(text).ToList();

        var match = Assert.Single(matches);
        Assert.Equal("LOAN-12345699", match.RawValue);
        Assert.Equal("LoanId", match.TypeName);
    }
}
