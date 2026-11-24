using FintechGuard.Pii.Core;
using FintechGuard.Pii.Ner;
using Xunit;

namespace FintechGuard.Pii.Tests;

public class Phase3NerIntegrationTests
{
    [Fact]
    public void ContextualNerRecognizer_DetectsHindiAndEnglishNames_OnTargetedKeys()
    {
        var engine = PiiEngineBuilder.Create()
            .WithMasterKey("12345678901234567890123456789012")
            .AddContextualNerRecognizer(opts =>
            {
                opts.TargetKeys = new[] { "notes", "chat_transcript" };
            })
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
        Assert.Equal(2, result.PiiFieldCount);

        Assert.Contains(result.Detections, d => d.JsonPath == "chat_transcript" && d.Type == PiiType.PersonName);
        Assert.DoesNotContain("रवि", result.Output);

        Assert.Contains(result.Detections, d => d.JsonPath == "notes" && d.Type == PiiType.PersonName);
        Assert.DoesNotContain("Sanjay Kumar", result.Output);

        Assert.Contains("Ravi is not caught here", result.Output);
    }

    [Fact]
    public void OnnxNerRecognizer_DetectsEntities_UsingRealTokenizedOnnxModel()
    {
        string modelPath = Path.Combine(AppContext.BaseDirectory, "TestData", "test_ner.onnx");
        string vocabPath = Path.Combine(AppContext.BaseDirectory, "TestData", "test_vocab.txt");

        using var engine = (PiiEngine)PiiEngineBuilder.Create()
            .WithMasterKey("12345678901234567890123456789012")
            .AddOnnxNerRecognizer(new OnnxNerOptions
            {
                ModelPath = modelPath,
                VocabPath = vocabPath,
                TargetKeys = new[] { "notes", "chat_transcript" },
                MinConfidence = 0.75
            })
            .Build();

        string json = """
        {
            "chat_transcript": "कस्टमर का नाम रवि है",
            "notes": "Spoke to Sanjay Kumar about his account",
            "ignored_field": "Sanjay Kumar should stay unmasked"
        }
        """;

        var result = engine.MaskJsonWithAudit(json);

        Assert.True(result.HasPii);
        Assert.DoesNotContain("Sanjay Kumar about", result.Output);
        Assert.DoesNotContain("रवि", result.Output);
        Assert.Contains("Sanjay Kumar should stay unmasked", result.Output);

        // Reversible round-trip restores entities identically
        string restored = engine.UnmaskJson(result.Output);
        Assert.Contains("Sanjay Kumar", restored);
        Assert.Contains("रवि", restored);
    }
}
