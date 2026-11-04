using FintechGuard.Pii.Core;
using Xunit;
using Xunit.Abstractions;
using System.Diagnostics;
using System.Text.Json;

namespace FintechGuard.Pii.Tests;

public class Phase1SafetyNetTests
{
    private readonly ITestOutputHelper _output;

    public Phase1SafetyNetTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void MaskJsonWithAudit_ReturnsDetailedTelemetry()
    {
        var engine = PiiEngineBuilder.Create()
            .WithMasterKey("12345678901234567890123456789012") // 32 bytes
            .AddDefaultRecognizers()
            .SetMinConfidence(0.80)
            .Build();

        string json = """
        {
            "user_id": 12345,
            "pan_number": "ABCPE1234F",
            "metadata": {
                "email": "audit.test@example.com",
                "notes": "User provided fake PAN and 4532-0151-1283-0366"
            }
        }
        """;

        var result = engine.MaskJsonWithAudit(json);

        Assert.True(result.HasPii);
        Assert.Equal(3, result.PiiFieldCount);
        
        Assert.Contains(result.Detections, d => d.Type == PiiType.Pan && d.JsonPath == "pan_number");
        Assert.Contains(result.Detections, d => d.Type == PiiType.Email && d.JsonPath == "email");
        Assert.Contains(result.Detections, d => d.Type == PiiType.CreditCard && d.JsonPath == "notes");

        _output.WriteLine("Output JSON:");
        _output.WriteLine(result.Output);
    }

    [Fact]
    public void ProcessJsonStream_ErrorBehaviorPassThrough_OnMalformedJson()
    {
        var engine = PiiEngineBuilder.Create()
            .WithMasterKey("12345678901234567890123456789012")
            .WithErrorBehavior(PiiErrorBehavior.PassThrough)
            .Build();

        string malformedJson = """{ "user": "test", "pan": "ABCPE1234F", malformed... """;

        var result = engine.MaskJsonWithAudit(malformedJson);

        // It should catch the JsonException, log it, and return the exact original string
        Assert.Equal(malformedJson, result.Output);
        Assert.False(result.HasPii);
    }

    [Fact]
    public void ReDoS_TimeoutGuard_PreventsCatastrophicBacktracking()
    {
        var engine = PiiEngineBuilder.Create()
            .WithMasterKey("12345678901234567890123456789012")
            .AddDefaultRecognizers()
            .Build();

        // This string causes standard unoptimized regex to hang due to backtracking
        // `(?:\d[ -]*?){13,19}` trying every combination
        string poisonPayload = """{ "card": "1111111111111111111111111111111111111x" }""";

        var sw = Stopwatch.StartNew();
        var result = engine.MaskJsonWithAudit(poisonPayload);
        sw.Stop();

        // Ensure it doesn't hang forever. With 100ms timeout per regex, it should finish quickly.
        Assert.True(sw.ElapsedMilliseconds < 5000, $"Engine took too long: {sw.ElapsedMilliseconds}ms");
        Assert.False(result.HasPii);
    }
}
