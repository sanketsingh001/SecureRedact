using FintechGuard.Pii.Core;
using FintechGuard.Pii.Ner;
using Xunit;

namespace FintechGuard.Pii.Tests;

public class Phase3NerIntegrationTests
{
    [Fact]
    public void OnnxNerRecognizer_DetectsHindiAndEnglishNames()
    {
        var engine = PiiEngineBuilder.Create()
            .WithMasterKey("12345678901234567890123456789012")
            .AddOnnxNerRecognizer(
                modelPath: "", // Empty for stub testing
                targetKeys: new[] { "notes", "chat_transcript" }
            )
            .Build();

        string json = """
        {
            "user_id": "U-1923",
            "chat_transcript": "कस्टमर का नाम रवि है, कार्ड नंबर 4532... है",
            "notes": "Spoke to Sanjay Kumar about his account",
            "ignored_field": "Ravi is not caught here because key is not targeted"
        }
        """;

        var result = engine.MaskJsonWithAudit(json);

        Assert.True(result.HasPii);
        
        // Should detect 2 names because of the targetKeys filter
        Assert.Equal(2, result.PiiFieldCount);
        
        // Assert Hindi detection
        Assert.Contains(result.Detections, d => d.JsonPath == "chat_transcript" && d.RecognizerName == "ONNX_NER_Model");
        Assert.DoesNotContain("रवि", result.Output);
        
        // Assert English detection
        Assert.Contains(result.Detections, d => d.JsonPath == "notes" && d.RecognizerName == "ONNX_NER_Model");
        Assert.DoesNotContain("Sanjay Kumar", result.Output);
        
        // Ensure "Ravi" is still present in the ignored field
        Assert.Contains("Ravi is not caught here", result.Output);
    }
}
