using FintechGuard.Pii.Core;
using Xunit;

namespace FintechGuard.Pii.Tests;

public class Phase2ContextAwareTests
{
    [Fact]
    public void KeyHint_BoostsConfidence_WhenKeyMatches()
    {
        // 1. We create a custom recognizer that has low base confidence (0.60)
        // 2. We set global min confidence to 0.80
        // 3. It should ONLY mask when the JSON key gives it a +0.30 boost (total 0.90)

        var engine = PiiEngineBuilder.Create()
            .WithMasterKey("12345678901234567890123456789012")
            .SetMinConfidence(0.80)
            .AddCustomRecognizer("LowConf_Num", @"\b\d{10}\b", PiiType.Pan, null, null, 0.60)
            .WithKeyHints(hints => 
            {
                hints.AddHint("secret_pan", PiiType.Pan, 0.30);
            })
            .Build();

        string json = """
        {
            "some_number": "1234567890",
            "secret_pan": "0987654321"
        }
        """;

        var result = engine.MaskJsonWithAudit(json);

        // some_number is ignored (0.60 < 0.80)
        // secret_pan is masked (0.60 + 0.30 = 0.90 >= 0.80)
        
        Assert.True(result.HasPii);
        Assert.Equal(1, result.PiiFieldCount);
        Assert.Equal("secret_pan", result.Detections[0].JsonPath);

        Assert.Contains("1234567890", result.Output);
        Assert.DoesNotContain("0987654321", result.Output);
    }
}
