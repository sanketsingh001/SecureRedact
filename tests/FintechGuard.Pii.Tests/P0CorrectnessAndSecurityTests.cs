using System.Diagnostics.Metrics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using FintechGuard.Pii.Algorithms;
using FintechGuard.Pii.Attributes;
using FintechGuard.Pii.Context;
using FintechGuard.Pii.Core;
using FintechGuard.Pii.Crypto;
using FintechGuard.Pii.Diagnostics;
using FintechGuard.Pii.Recognizers;
using FintechGuard.Pii.Serialization;
using Xunit;

namespace FintechGuard.Pii.Tests;

public class CustomRulePoco
{
    [CustomPiiRule(@"LOAN-\d{6}", Strategy = MaskingStrategy.OneWayRedaction, MaskChar = '#', KeepPrefix = 5, KeepSuffix = 2)]
    public string LoanReference { get; set; } = string.Empty;

    [PiiMask(PiiType.CreditCard, MaskingStrategy.OneWayRedaction, MaskChar = '#')]
    public string Card { get; set; } = string.Empty;

    [JsonIgnore]
    public string InternalSecret { get; set; } = "should_not_appear";
}

public record ImmutableOrderRecord(string OrderId, string CardNumber);

public class P0CorrectnessAndSecurityTests
{
    [Fact]
    public void IbanRecognizer_MatchesSpaceFormattedIbans_AndRejectsInvalidCountryLengths()
    {
        var recognizer = new IbanRecognizer();

        var deMatches = recognizer.Recognize("Wire to DE89 3704 0044 0532 0130 00 today").ToList();
        var deMatch = Assert.Single(deMatches);
        Assert.Equal("DE89 3704 0044 0532 0130 00", deMatch.RawValue);

        var gbMatches = recognizer.Recognize("Account: GB82 WEST 1234 5698 7654 32").ToList();
        Assert.Single(gbMatches);

        // Too short for DE (20 chars instead of 22) even if checksum could match
        Assert.False(IbanValidator.Validate("DE893704004405320130".AsSpan()));
    }

    [Fact]
    public void IpAddressRecognizer_DetectsIpv6_AndIgnoresVersionsAndTimestamps()
    {
        var recognizer = new IpAddressRecognizer();

        var v6Full = recognizer.Recognize("Client connected from 2001:0db8:85a3:0000:0000:8a2e:0370:7334").ToList();
        var v6Single = Assert.Single(v6Full);
        Assert.Equal(PiiType.IpAddress, v6Single.Type);

        var v6Loopback = recognizer.Recognize("Origin ::1 logged").ToList();
        Assert.Single(v6Loopback);

        // Negative traps: version numbers & HH:MM:SS timestamps must NOT match
        Assert.Empty(recognizer.Recognize("Version v1.2.3.4 released at 12:30:00"));
        Assert.Empty(recognizer.Recognize("2026-09-06T15:30:00Z"));
    }

    [Fact]
    public void GenericPhoneAndDobRecognizers_DetectAccuratelyWithoutFalsePositives()
    {
        var engine = PiiEngineBuilder.Create()
            .WithMasterKey("test-key-for-phone-and-dob-256!!")
            .AddDefaultRecognizers()
            .Build();

        string json = """
        {
            "us_phone": "+1-415-555-2671",
            "date_of_birth": "1992-07-14",
            "created_at": "2026-09-06",
            "event_timestamp": "2026-09-06T15:30:00Z",
            "notes": "DOB is 14/08/1988"
        }
        """;

        var result = engine.MaskJsonWithAudit(json);
        Assert.DoesNotContain("+1-415-555-2671", result.Output);
        Assert.DoesNotContain("1992-07-14", result.Output);
        Assert.DoesNotContain("14/08/1988", result.Output);

        // Regular dates / timestamps MUST remain untouched
        Assert.Contains("\"created_at\":\"2026-09-06\"", result.Output);
        Assert.Contains("\"event_timestamp\":\"2026-09-06T15:30:00Z\"", result.Output);
    }

    [Fact]
    public void MaskingStrategyHash_ProducesDeterministicKeyedHmacTokens()
    {
        var engine1 = PiiEngineBuilder.Create()
            .WithHashKey("secret-hmac-salt-1")
            .AddDefaultRecognizers()
            .SetDefaultStrategy(MaskingStrategy.Hash)
            .Build();

        var engine2 = PiiEngineBuilder.Create()
            .WithHashKey("secret-hmac-salt-2")
            .AddDefaultRecognizers()
            .SetDefaultStrategy(MaskingStrategy.Hash)
            .Build();

        string h1a = engine1.MaskValue("ABCPE1234F", PiiType.Pan);
        string h1b = engine1.MaskValue("ABCPE1234F", PiiType.Pan);
        string h2 = engine2.MaskValue("ABCPE1234F", PiiType.Pan);

        Assert.StartsWith("HASH{Pan:", h1a);
        Assert.EndsWith("}", h1a);
        Assert.Equal(h1b, h1a);
        Assert.NotEqual(h2, h1a);
    }

    [Fact]
    public void KeyHintRegistry_MatchesIdentifierBoundaries_NotSubstrings()
    {
        var hints = new KeyHintRegistry();

        // Substring traps must NOT match
        Assert.Equal(0.0, hints.GetBoost("company_name", PiiType.Pan));
        Assert.Equal(0.0, hints.GetBoost("shipping_address", PiiType.IpAddress));
        Assert.Equal(0.0, hints.GetBoost("account_number", PiiType.CreditCard));

        // True boundary matches MUST boost/penalize
        Assert.True(hints.GetBoost("customer_pan", PiiType.Pan) > 0.0);
        Assert.True(hints.GetBoost("clientIp", PiiType.IpAddress) > 0.0);
        Assert.True(hints.GetBoost("mobileNumber", PiiType.IndianMobile) > 0.0);
        Assert.True(hints.GetBoost("order_id", PiiType.CreditCard) < 0.0);
    }

    [Fact]
    public void FalsePositiveTraps_AreRejectedByIinAndContextGating()
    {
        var engine = PiiEngineBuilder.Create()
            .WithMasterKey("test-key-fp-traps-256-bit-safe!")
            .AddDefaultRecognizers()
            .Build();

        string json = """
        {
            "tx_code": "TXN1234567",
            "user_tag": "u1234567",
            "non_iin_luhn": "9123456789012343",
            "order_id": "6789012345"
        }
        """;

        string masked = engine.MaskJson(json);
        Assert.Contains("TXN1234567", masked);
        Assert.Contains("u1234567", masked);
        Assert.Contains("9123456789012343", masked);
        Assert.Contains("6789012345", masked);
    }

    [Fact]
    public void CustomPatternRecognizer_EnforcesReDoSTimeout()
    {
        var recognizer = new CustomPatternRecognizer(
            "EvilBacktrack",
            @"^(a+)+$",
            matchTimeout: TimeSpan.FromMilliseconds(25));

        Assert.Throws<RegexMatchTimeoutException>(() => recognizer.Recognize(new string('a', 40) + "!").ToList());
    }

    [Fact]
    public void Validators_RejectHugeInputsWithoutStackOverflow()
    {
        string huge = new string('4', 150_000);
        Assert.False(IbanValidator.Validate(huge.AsSpan()));
        Assert.False(LuhnValidator.ValidateWithSeparators(huge.AsSpan()));
        Assert.False(SsnValidator.Validate(huge.AsSpan()));
    }

    [Fact]
    public void AesGcmCrypto_SupportsKeyRotation_AndConcurrentThroughput()
    {
        byte[] keyV1 = new byte[32];
        byte[] keyV2 = new byte[32];
        Array.Fill(keyV1, (byte)0x11);
        Array.Fill(keyV2, (byte)0x22);

        using var v1Crypto = new AesGcmReversibleCrypto("v1", new Dictionary<string, byte[]> { ["v1"] = keyV1 });
        string tokenFromV1 = v1Crypto.Encrypt("4532-0151-1283-0366");

        using var rotatedCrypto = new AesGcmReversibleCrypto("v2", new Dictionary<string, byte[]>
        {
            ["v1"] = keyV1,
            ["v2"] = keyV2
        });

        string tokenFromV2 = rotatedCrypto.Encrypt("ABCPE1234F");

        Assert.True(rotatedCrypto.TryDecrypt(tokenFromV1, out string? plain1));
        Assert.Equal("4532-0151-1283-0366", plain1);

        Assert.True(rotatedCrypto.TryDecrypt(tokenFromV2, out string? plain2));
        Assert.Equal("ABCPE1234F", plain2);

        // Concurrent thread safety check
        Parallel.For(0, 500, i =>
        {
            string input = $"PAN_{i}_ABCPE1234F";
            string enc = rotatedCrypto.Encrypt(input);
            Assert.True(rotatedCrypto.TryDecrypt(enc, out string? dec));
            Assert.Equal(input, dec);
        });
    }

    [Fact]
    public void PocoSerialization_HonorsCustomPiiRule_ExplicitMaskStrategy_AndSkipsRecordsCleanly()
    {
        var engine = PiiEngineBuilder.Create()
            .WithMasterKey("poco-test-key-256-bit-secret!!")
            .AddDefaultRecognizers()
            .Build();

        var dto = new CustomRulePoco
        {
            LoanReference = "LOAN-987654",
            Card = "4532-0151-1283-0366"
        };

        string json = engine.SerializeWithMasking(dto);
        Assert.Contains("\"LoanReference\":\"LOAN-####54\"", json);
        Assert.Contains("\"Card\":\"4532-####-####-0366\"", json);
        Assert.DoesNotContain("#fp[", json);
        Assert.DoesNotContain("InternalSecret", json);

        // C# record without parameterless ctor must NOT crash PiiJsonConverterFactory
        var recordObj = new ImmutableOrderRecord("ORD-1", "4532-0151-1283-0366");
        var options = engine.CreateJsonSerializerOptions();
        string recJson = JsonSerializer.Serialize(recordObj, options);
        Assert.Contains("ORD-1", recJson);
    }

    [Fact]
    public void JsonScope_IncludeKeysOnParentAndNumbers_AndFullJsonPath_WorkAccurately()
    {
        var engine = PiiEngineBuilder.Create()
            .WithMasterKey("scope-test-key-256-bit-secret!")
            .AddDefaultRecognizers()
            .Build();

        string json = """
        {
            "payment": {
                "card_num": 4532015112830366,
                "pan": "ABCPE1234F"
            },
            "public_card": "4532-0151-1283-0366"
        }
        """;

        var result = engine.MaskJsonWithAudit(json, new JsonMaskingScope
        {
            IncludeKeys = ["payment"]
        });

        Assert.DoesNotContain("4532015112830366", result.Output);
        Assert.DoesNotContain("ABCPE1234F", result.Output);
        Assert.Contains("\"public_card\":\"4532-0151-1283-0366\"", result.Output);
        Assert.Contains(result.Detections, d => d.FullJsonPath == "$.payment.pan" && d.JsonPath == "pan");
        Assert.Contains(result.Detections, d => d.FullJsonPath == "$.payment.card_num" && d.Type == PiiType.CreditCard);
    }

    [Fact]
    public void PiiMetrics_RecordsElementsMaskedAndDuration_DuringMaskJson()
    {
        long elementsObserved = 0;
        long durationSamples = 0;

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == PiiMetrics.MeterName)
                meterListener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((inst, val, _, _) =>
        {
            if (inst.Name == "pii.elements.masked")
                Interlocked.Add(ref elementsObserved, val);
        });
        listener.SetMeasurementEventCallback<double>((inst, _, _, _) =>
        {
            if (inst.Name == "pii.processing.duration")
                Interlocked.Increment(ref durationSamples);
        });
        listener.Start();

        var engine = PiiEngineBuilder.Create()
            .WithMasterKey("metrics-test-key-256-bit-safe!")
            .AddDefaultRecognizers()
            .Build();

        engine.MaskJson("""{"pan":"ABCPE1234F","card":"4532-0151-1283-0366"}""");

        Assert.True(elementsObserved >= 2);
        Assert.True(durationSamples >= 1);
    }

    [Fact]
    public async Task MaskNdjsonStreamAsync_MasksMultiLineNdjson_AndEmbeddedMixedTokensUnmask()
    {
        var engine = PiiEngineBuilder.Create()
            .WithMasterKey("ndjson-test-key-256-bit-safe!!")
            .AddDefaultRecognizers()
            .Build();

        string ndjson =
            "{\"pan\":\"ABCPE1234F\"}\n" +
            "{\"card\":\"4532-0151-1283-0366\"}\n" +
            "{\"email\":\"audit@bank.com\"}\n";

        using var input = new MemoryStream(Encoding.UTF8.GetBytes(ndjson));
        using var output = new MemoryStream();

        await engine.MaskNdjsonStreamAsync(input, output);
        string maskedNdjson = Encoding.UTF8.GetString(output.ToArray());

        Assert.DoesNotContain("ABCPE1234F", maskedNdjson);
        Assert.DoesNotContain("4532-0151-1283-0366", maskedNdjson);
        Assert.DoesNotContain("audit@bank.com", maskedNdjson);

        string[] lines = maskedNdjson.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(3, lines.Length);
        foreach (var line in lines)
        {
            string restored = engine.UnmaskJson(line);
            using var doc = JsonDocument.Parse(restored);
            Assert.NotNull(doc);
        }

        // Mixed #fp[...] and ENC{...} in a single string
        string fpToken = engine.MaskValue("4532-0151-1283-0366", PiiType.CreditCard);
        string encToken = engine.MaskValue("ABCPE1234F", PiiType.Pan, MaskingStrategy.ReversibleCryptoToken);
        string combined = $"Card={fpToken}; PAN={encToken}";
        string unmaskedCombined = engine.UnmaskValue(combined);
        Assert.Equal("Card=4532-0151-1283-0366; PAN=ABCPE1234F", unmaskedCombined);
    }

    [Fact]
    public async Task PiiEngine_WithMaxCpuUsageAndConcurrency_BoundsParallelExecutionAndEnforcesTimeouts()
    {
        int calc25 = PiiEngineOptions.CalculateConcurrencyForCpuPercent(25);
        Assert.InRange(calc25, 1, Environment.ProcessorCount);
        Assert.Throws<ArgumentOutOfRangeException>(() => PiiEngineOptions.CalculateConcurrencyForCpuPercent(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => PiiEngineOptions.CalculateConcurrencyForCpuPercent(101));

        // 1. Verify active concurrency never exceeds WithMaxConcurrency(2)
        int active = 0;
        int peakActive = 0;
        using var cappedEngine = (PiiEngine)PiiEngineBuilder.Create()
            .WithMasterKey("cpu-cap-test-key-256-bit-safe!!")
            .WithMaxCpuUsage(25)
            .WithMaxConcurrency(2)
            .AddDefaultRecognizers()
            .AddRecognizer(new ConcurrencyTrackingRecognizer(
                () =>
                {
                    int cur = Interlocked.Increment(ref active);
                    int prev;
                    while (cur > (prev = Volatile.Read(ref peakActive)))
                        Interlocked.CompareExchange(ref peakActive, cur, prev);
                    Thread.Sleep(20);
                    Interlocked.Decrement(ref active);
                }))
            .Build();

        Parallel.For(0, 12, new ParallelOptions { MaxDegreeOfParallelism = 8 }, _ =>
        {
            string masked = cappedEngine.MaskJson("""{"pan":"ABCPE1234F"}""");
            Assert.DoesNotContain("ABCPE1234F", masked);
        });
        Assert.True(peakActive <= 2, $"Expected peak concurrency <= 2, observed {peakActive}");

        // 2. Verify deterministic timeout handling under Throw vs Redact
        using var entered = new ManualResetEventSlim(false);
        using var release = new ManualResetEventSlim(false);

        using var throwEngine = (PiiEngine)PiiEngineBuilder.Create()
            .WithMasterKey("cpu-cap-throw-key-256-bit-safe!")
            .WithMaxConcurrency(1, TimeSpan.FromMilliseconds(30))
            .WithErrorBehavior(PiiErrorBehavior.Throw)
            .AddRecognizer(new GateRecognizer(entered, release))
            .Build();

        var holderTask = Task.Run(() => throwEngine.MaskJson("""{"k":"v"}"""));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));

        Assert.Throws<PiiProcessingException>(() => throwEngine.MaskJson("""{"k":"v2"}"""));
        release.Set();
        await holderTask;

        entered.Reset();
        release.Reset();

        using var redactEngine = (PiiEngine)PiiEngineBuilder.Create()
            .WithMasterKey("cpu-cap-redact-key-256-bit-safe")
            .WithMaxConcurrency(1, TimeSpan.FromMilliseconds(30))
            .WithErrorBehavior(PiiErrorBehavior.Redact)
            .AddRecognizer(new GateRecognizer(entered, release))
            .Build();

        var holder2 = Task.Run(() => redactEngine.MaskJson("""{"k":"v"}"""));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));

        string fallback = redactEngine.MaskJson("""{"k":"v2"}""");
        Assert.Contains("REDACTED_DUE_TO_PROCESSING_ERROR", fallback);

        release.Set();
        await holder2;
    }

    [Fact]
    public void PiiEngine_OneLineFactories_WorkAndDisposeCleanly()
    {
        using var revEngine = PiiEngine.CreateDefault("my-secret-key-32-bytes-long!!!!!", maxCpuPercent: 25);
        string maskedRev = revEngine.MaskJson("""{"pan":"ABCPE1234F"}""");
        Assert.Contains("AB****234F#fp[", maskedRev);
        Assert.Equal("""{"pan":"ABCPE1234F"}""", revEngine.UnmaskJson(maskedRev));

        using var oneWayEngine = PiiEngine.CreateOneWay(maxCpuPercent: 25);
        string maskedOneWay = oneWayEngine.MaskJson("""{"pan":"ABCPE1234F"}""");
        Assert.Equal("""{"pan":"AB****234F"}""", maskedOneWay);

        byte[] key32 = new byte[32];
        Array.Fill(key32, (byte)0x42);
        using var ringEngine = PiiEngine.CreateWithKeyRing(
            "k1",
            new Dictionary<string, byte[]> { ["k1"] = key32 },
            maxCpuPercent: 25);
        string maskedRing = ringEngine.MaskJson("""{"card":"4532-0151-1283-0366"}""");
        Assert.Contains("#fp[", maskedRing);
        Assert.Contains("4532-0151-1283-0366", ringEngine.UnmaskJson(maskedRing));
    }

    private sealed class ConcurrencyTrackingRecognizer : IPiiRecognizer
    {
        private readonly Action _onWork;
        public ConcurrencyTrackingRecognizer(Action onWork) => _onWork = onWork;
        public string Name => "ConcurrencyTracker";
        public PiiType PiiType => PiiType.Custom;
        public IEnumerable<PiiMatch> Recognize(string text)
        {
            _onWork();
            return Array.Empty<PiiMatch>();
        }
        public IEnumerable<PiiMatch> Recognize(string text, RecognitionContext context) => Recognize(text);
    }

    private sealed class GateRecognizer : IPiiRecognizer
    {
        private readonly ManualResetEventSlim _entered;
        private readonly ManualResetEventSlim _release;
        public GateRecognizer(ManualResetEventSlim entered, ManualResetEventSlim release)
        {
            _entered = entered;
            _release = release;
        }
        public string Name => "GateRecognizer";
        public PiiType PiiType => PiiType.Custom;
        public IEnumerable<PiiMatch> Recognize(string text)
        {
            _entered.Set();
            _release.Wait(TimeSpan.FromSeconds(5));
            return Array.Empty<PiiMatch>();
        }
        public IEnumerable<PiiMatch> Recognize(string text, RecognitionContext context) => Recognize(text);
    }
}
