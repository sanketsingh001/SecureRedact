using System.Net;
using System.Net.Http;
using System.Text;
using FintechGuard.Pii.Core;
using FintechGuard.Pii.Ner;
using Microsoft.ML.OnnxRuntime.Tensors;
using Xunit;

namespace FintechGuard.Pii.Tests;

public class CpuNerPipelineTests
{
    private static string TestModelPath => Path.Combine(AppContext.BaseDirectory, "TestData", "test_ner.onnx");
    private static string TestVocabPath => Path.Combine(AppContext.BaseDirectory, "TestData", "test_vocab.txt");

    [Fact]
    public void Tier1ContextualNer_DetectsNamesAndAddresses_AndAvoidsBankingFalsePositives()
    {
        var engine = PiiEngineBuilder.Create()
            .WithMasterKey("tier1-cpu-ner-test-key-256-bit!")
            .AddDefaultRecognizers()
            .AddContextualNerRecognizer()
            .Build();

        string json = """
        {
            "greeting": "Mr. Rajesh Verma confirmed the KYC document.",
            "chat_english": "My name is Vikram Patel and I need help.",
            "chat_hindi": "कस्टमर का नाम रवि है",
            "address_note": "Customer lives at Flat 402, 14 MG Road, Indiranagar, Bengaluru 560038.",
            "safe_bank_msg": "HDFC Bank Limited payment approved for order."
        }
        """;

        var result = engine.MaskJsonWithAudit(json);

        Assert.DoesNotContain("Rajesh Verma", result.Output);
        Assert.DoesNotContain("Vikram Patel", result.Output);
        Assert.DoesNotContain("रवि", result.Output);
        Assert.DoesNotContain("14 MG Road", result.Output);
        Assert.Contains("HDFC Bank Limited payment approved for order.", result.Output);

        Assert.Contains(result.Detections, d => d.Type == PiiType.PersonName && d.JsonPath == "greeting");
        Assert.Contains(result.Detections, d => d.Type == PiiType.PersonName && d.JsonPath == "chat_english");
        Assert.Contains(result.Detections, d => d.Type == PiiType.PersonName && d.JsonPath == "chat_hindi");
        Assert.Contains(result.Detections, d => d.Type == PiiType.Address && d.JsonPath == "address_note");

        // Reversible round-trip restores all masked NER entities identically
        string restored = engine.UnmaskJson(result.Output);
        Assert.Contains("Rajesh Verma", restored);
        Assert.Contains("Vikram Patel", restored);
        Assert.Contains("रवि", restored);
        Assert.Contains("Flat 402, 14 MG Road, Indiranagar, Bengaluru 560038", restored);
    }

    [Fact]
    public void Tier2OnnxNer_DecodesSubwordTokens_Locations_AndFiltersByMinConfidence()
    {
        using var recognizer = new OnnxNerRecognizer(new OnnxNerOptions
        {
            ModelPath = TestModelPath,
            VocabPath = TestVocabPath,
            MinConfidence = 0.75
        });

        // WordPiece subwords: "Vik" + "##ram" and "Pa" + "##tel", plus B-LOC/I-LOC, plus low-confidence "Ambiguous"
        string text = "Vikram Patel lives in Indiranagar Bengaluru and Ambiguous stays";
        var matches = recognizer.Recognize(text).ToList();

        Assert.Contains(matches, m => m.Type == PiiType.PersonName && m.RawValue == "Vikram Patel");
        Assert.Contains(matches, m => m.Type == PiiType.Address && m.RawValue == "Indiranagar Bengaluru");
        Assert.DoesNotContain(matches, m => m.RawValue == "Ambiguous");
    }

    [Fact]
    public async Task Tier2OnnxNer_MicroBatching_Handles64ConcurrentRequestsSafely()
    {
        using var recognizer = new OnnxNerRecognizer(new OnnxNerOptions
        {
            ModelPath = TestModelPath,
            VocabPath = TestVocabPath,
            EnableMicroBatching = true,
            MaxBatchSize = 16,
            MaxBatchWaitMs = 3,
            IntraOpNumThreads = 1,
            InterOpNumThreads = 1
        });

        var tasks = Enumerable.Range(0, 64).Select(async i =>
        {
            string input = i % 2 == 0
                ? "Spoke to Sanjay Kumar about his account"
                : "User John Doe connected to agent Priya Sharma in Mumbai";

            var matches = await recognizer.RecognizeAsync(input);
            if (i % 2 == 0)
            {
                Assert.Single(matches, m => m.Type == PiiType.PersonName && m.RawValue == "Sanjay Kumar");
            }
            else
            {
                Assert.Contains(matches, m => m.Type == PiiType.PersonName && m.RawValue == "John Doe");
                Assert.Contains(matches, m => m.Type == PiiType.PersonName && m.RawValue == "Priya Sharma");
                Assert.Contains(matches, m => m.Type == PiiType.Address && m.RawValue == "Mumbai");
            }
        });

        await Task.WhenAll(tasks);
    }

    [Fact]
    public void BioEntityDecoder_MergesRepeatedBTag_OnWordPieceSubwords()
    {
        string text = "Vikram Patel";
        var windowTokens = new OnnxTokenWindowItem[]
        {
            new(0, 0, IsSpecial: true, IsSubword: false),
            new(0, 3, IsSpecial: false, IsSubword: false),  // "Vik" -> B-PER
            new(3, 6, IsSpecial: false, IsSubword: true),   // "##ram" -> B-PER (must merge!)
            new(7, 9, IsSpecial: false, IsSubword: false),  // "Pa" -> I-PER
            new(9, 12, IsSpecial: false, IsSubword: true),  // "##tel" -> B-PER (must merge!)
            new(0, 0, IsSpecial: true, IsSubword: false),
        };

        // 6 tokens x 9 labels: 0=O, 1=B-PER, 2=I-PER
        var logits = new DenseTensor<float>(new[] { 1, 6, 9 });
        for (int t = 0; t < 6; t++)
            for (int c = 0; c < 9; c++)
                logits[0, t, c] = -3.0f;

        logits[0, 0, 0] = 6.0f; // [CLS]
        logits[0, 1, 1] = 6.0f; // Vik -> B-PER
        logits[0, 2, 1] = 6.0f; // ##ram -> B-PER (subword)
        logits[0, 3, 2] = 6.0f; // Pa -> I-PER
        logits[0, 4, 1] = 6.0f; // ##tel -> B-PER (subword)
        logits[0, 5, 0] = 6.0f; // [SEP]

        var options = new OnnxNerOptions { ModelPath = "unused.onnx", MinConfidence = 0.75 };
        var matches = BioEntityDecoder.DecodeWindow(text, logits, batchRowIndex: 0, windowTokens, options);

        var single = Assert.Single(matches);
        Assert.Equal(PiiType.PersonName, single.Type);
        Assert.Equal("Vikram Patel", single.RawValue);
    }

    [Fact]
    public void BioEntityDecoder_SnapsBackwardToWordStart_WhenContinuationSubwordStartsEntity()
    {
        var options = new OnnxNerOptions
        {
            ModelPath = "unused.onnx",
            MinConfidence = 0.70,
            ExcludedTerms = OnnxNerOptions.DefaultFintechExcludedTerms
        };

        // Case 1: "San" tagged O, "##jay" tagged I-PER, "Kumar" tagged I-PER -> snaps back to "Sanjay Kumar"
        string text1 = "Sanjay Kumar via NEFT";
        var tokens1 = new OnnxTokenWindowItem[]
        {
            new(0, 0, IsSpecial: true, IsSubword: false),
            new(0, 3, IsSpecial: false, IsSubword: false),   // "San" -> O
            new(3, 6, IsSpecial: false, IsSubword: true),    // "##jay" -> I-PER
            new(7, 12, IsSpecial: false, IsSubword: false),  // "Kumar" -> I-PER
            new(13, 16, IsSpecial: false, IsSubword: false), // "via" -> O
            new(17, 19, IsSpecial: false, IsSubword: false), // "NE" -> B-ORG
            new(19, 21, IsSpecial: false, IsSubword: true),  // "##FT" -> I-ORG (excluded by DefaultFintechExcludedTerms)
            new(0, 0, IsSpecial: true, IsSubword: false),
        };
        var logits1 = new DenseTensor<float>(new[] { 1, 8, 9 });
        for (int t = 0; t < 8; t++)
            for (int c = 0; c < 9; c++)
                logits1[0, t, c] = -3.0f;

        logits1[0, 0, 0] = 6.0f; // [CLS]
        logits1[0, 1, 0] = 6.0f; // San -> O
        logits1[0, 2, 2] = 6.0f; // ##jay -> I-PER
        logits1[0, 3, 2] = 6.0f; // Kumar -> I-PER
        logits1[0, 4, 0] = 6.0f; // via -> O
        logits1[0, 5, 3] = 6.0f; // NE -> B-ORG
        logits1[0, 6, 4] = 6.0f; // ##FT -> I-ORG
        logits1[0, 7, 0] = 6.0f; // [SEP]

        var matches1 = BioEntityDecoder.DecodeWindow(text1, logits1, 0, tokens1, options);
        var single1 = Assert.Single(matches1);
        Assert.Equal(PiiType.PersonName, single1.Type);
        Assert.Equal("Sanjay Kumar", single1.RawValue);

        // Case 2: Devanagari "प" (O) + "##्रिया" (B-PER) -> snaps backward to full word "प्रिया"
        string text2 = "प्रिया";
        var tokens2 = new OnnxTokenWindowItem[]
        {
            new(0, 0, IsSpecial: true, IsSubword: false),
            new(0, 1, IsSpecial: false, IsSubword: false), // "प" -> O
            new(1, 6, IsSpecial: false, IsSubword: true),  // "##्रिया" -> B-PER
            new(0, 0, IsSpecial: true, IsSubword: false),
        };
        var logits2 = new DenseTensor<float>(new[] { 1, 4, 9 });
        for (int t = 0; t < 4; t++)
            for (int c = 0; c < 9; c++)
                logits2[0, t, c] = -3.0f;

        logits2[0, 0, 0] = 6.0f;
        logits2[0, 1, 0] = 6.0f;
        logits2[0, 2, 1] = 6.0f;
        logits2[0, 3, 0] = 6.0f;

        var matches2 = BioEntityDecoder.DecodeWindow(text2, logits2, 0, tokens2, options);
        var single2 = Assert.Single(matches2);
        Assert.Equal(PiiType.PersonName, single2.Type);
        Assert.Equal("प्रिया", single2.RawValue);
    }

    [Fact]
    public void OnnxNerOptions_FromHuggingFaceDirectory_ParsesConfigAndQuantizedModel()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "sr_hf_dir_" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(Path.Combine(tempDir, "onnx"));
            File.WriteAllBytes(Path.Combine(tempDir, "onnx", "model_int8.onnx"), Array.Empty<byte>());
            File.WriteAllBytes(Path.Combine(tempDir, "onnx", "model.onnx"), Array.Empty<byte>());
            File.WriteAllText(Path.Combine(tempDir, "vocab.txt"), "[PAD]\n[UNK]\n[CLS]\n[SEP]\n");
            File.WriteAllText(Path.Combine(tempDir, "config.json"), """
                {
                  "id2label": { "0": "O", "3": "B-PER", "4": "I-PER", "7": "B-LOC", "8": "I-LOC" }
                }
                """);
            File.WriteAllText(Path.Combine(tempDir, "tokenizer_config.json"), """
                {
                  "do_lower_case": true
                }
                """);

            var fallbackOpts = OnnxNerOptions.FromHuggingFaceDirectory(
                tempDir,
                targetKeys: new[] { "notes" },
                minConfidence: 0.70,
                enableMicroBatching: true,
                batchWorkerCount: 4,
                excludedTerms: OnnxNerOptions.DefaultFintechExcludedTerms);

            Assert.EndsWith("model_int8.onnx", fallbackOpts.ModelPath);
            Assert.EndsWith("vocab.txt", fallbackOpts.VocabPath!);
            Assert.Equal("B-PER", fallbackOpts.IdToLabel[3]);
            Assert.Equal("B-LOC", fallbackOpts.IdToLabel[7]);
            Assert.True(fallbackOpts.LowerCaseBeforeTokenization);
            Assert.Equal("notes", Assert.Single(fallbackOpts.TargetKeys));
            Assert.True(fallbackOpts.EnableMicroBatching);
            Assert.Equal(4, fallbackOpts.BatchWorkerCount);
            Assert.NotNull(fallbackOpts.ExcludedTerms);
            Assert.True(fallbackOpts.ExcludedTerms!.Contains("NEFT"));

            // When dynamic quantized model_quantized.onnx exists alongside model_int8.onnx, prefer model_quantized.onnx
            File.WriteAllBytes(Path.Combine(tempDir, "onnx", "model_quantized.onnx"), Array.Empty<byte>());
            var preferredOpts = OnnxNerOptions.FromHuggingFaceDirectory(tempDir);
            Assert.EndsWith("model_quantized.onnx", preferredOpts.ModelPath);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public async Task OnnxNerOptions_WithMaxCpuUsage_MaxWindowsPerField_AndConcurrencyCap_ProtectServerCpu()
    {
        var opts = new OnnxNerOptions
        {
            ModelPath = TestModelPath,
            VocabPath = TestVocabPath,
            BatchWorkerCount = 8,
            MaxWindowsPerField = 2,
            MaxSequenceLength = 16,
            SlidingWindowStride = 2
        }.WithMaxCpuUsage(25);

        Assert.Equal(1, opts.IntraOpNumThreads);
        Assert.Equal(1, opts.InterOpNumThreads);
        Assert.True(opts.DisableThreadSpinning);
        Assert.Equal(PiiEngineOptions.CalculateConcurrencyForCpuPercent(25), opts.MaxConcurrentInferences);
        Assert.True(opts.BatchWorkerCount <= opts.MaxConcurrentInferences);
        Assert.Throws<ArgumentOutOfRangeException>(() => opts.WithMaxCpuUsage(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => opts.WithMaxCpuUsage(101));

        // MaxWindowsPerField=2 with MaxSequenceLength=16 allows at most ~26 content tokens
        using var recognizer = new OnnxNerRecognizer(opts);
        string padding = string.Join(" ", Enumerable.Repeat("account", 60));
        string longText = $"Vikram Patel {padding} Sanjay Kumar";
        var matches = recognizer.Recognize(longText).ToList();

        Assert.Contains(matches, m => m.RawValue == "Vikram Patel");
        Assert.DoesNotContain(matches, m => m.RawValue == "Sanjay Kumar");

        // Parallel calls execute cleanly through MaxConcurrentInferences gate without deadlock
        var tasks = Enumerable.Range(0, 8).Select(_ =>
            recognizer.RecognizeAsync("Spoke to Sanjay Kumar in Mumbai"));
        var results = await Task.WhenAll(tasks);
        foreach (var r in results)
        {
            Assert.Contains(r, m => m.RawValue == "Sanjay Kumar");
        }
    }

    [Fact]
    public void RealMultilingualDistilBertInt8_DetectsIndianEnglishAndHindiEntities()
    {
        string? modelDir = FindRealModelDirectory();
        if (modelDir == null)
            return; // Cleanly skip in environments without downloaded 129 MB ONNX weights

        using var engine = (PiiEngine)PiiEngineBuilder.Create()
            .WithMasterKey("real-int8-distilbert-ner-key-32b")
            .AddDefaultRecognizers()
            .AddOnnxNerRecognizer(OnnxNerOptions.FromHuggingFaceDirectory(
                modelDir,
                targetKeys: new[] { "chat_transcript", "notes" },
                minConfidence: 0.70,
                excludedTerms: OnnxNerOptions.DefaultFintechExcludedTerms))
            .Build();

        string json = """
        {
            "notes": "Customer Sanjay Kumar transferred Rs 25,000 from Bengaluru to Priya Sharma in Mumbai.",
            "chat_transcript": "ग्राहक संजय कुमार मुंबई से कॉल कर रहे हैं",
            "safe_status": "TXN_APPROVED_BY_GATEWAY"
        }
        """;

        var result = engine.MaskJsonWithAudit(json);

        Assert.True(result.HasPii);
        Assert.DoesNotContain("Sanjay Kumar", result.Output);
        Assert.DoesNotContain("Bengaluru", result.Output);
        Assert.DoesNotContain("Priya Sharma", result.Output);
        Assert.DoesNotContain("Mumbai", result.Output);
        Assert.DoesNotContain("संजय कुमार", result.Output);
        Assert.DoesNotContain("मुंबई", result.Output);
        Assert.Contains("TXN_APPROVED_BY_GATEWAY", result.Output);
        Assert.Contains("ग्राहक", result.Output);

        Assert.Contains(result.Detections, d => d.Type == PiiType.PersonName && d.JsonPath == "notes");
        Assert.Contains(result.Detections, d => d.Type == PiiType.Address && d.JsonPath == "notes");
        Assert.Contains(result.Detections, d => d.Type == PiiType.PersonName && d.JsonPath == "chat_transcript");
        Assert.Contains(result.Detections, d => d.Type == PiiType.Address && d.JsonPath == "chat_transcript");

        string restored = engine.UnmaskJson(result.Output);
        Assert.Contains("Sanjay Kumar", restored);
        Assert.Contains("Bengaluru", restored);
        Assert.Contains("Priya Sharma", restored);
        Assert.Contains("Mumbai", restored);
        Assert.Contains("संजय कुमार", restored);
        Assert.Contains("मुंबई", restored);
    }

    [Fact]
    public async Task OnnxNerModelDownloader_EnsureModelAsync_DownloadsAtomicallyAndSkipsCachedFiles()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "sr_dl_test_" + Guid.NewGuid().ToString("N"));
        try
        {
            int httpCalls = 0;
            byte[] modelBytes = File.ReadAllBytes(TestModelPath);
            byte[] vocabBytes = File.ReadAllBytes(TestVocabPath);
            byte[] configBytes = Encoding.UTF8.GetBytes("""{"id2label":{"0":"O","1":"B-PER","2":"I-PER","3":"B-ORG","4":"I-ORG","5":"B-LOC","6":"I-LOC"}}""");
            byte[] tokConfigBytes = Encoding.UTF8.GetBytes("""{"do_lower_case":false}""");

            using var handler = new FakeHfHandler(uri =>
            {
                Interlocked.Increment(ref httpCalls);
                if (uri.EndsWith("model_quantized.onnx", StringComparison.Ordinal)) return modelBytes;
                if (uri.EndsWith("vocab.txt", StringComparison.Ordinal)) return vocabBytes;
                if (uri.EndsWith("config.json", StringComparison.Ordinal)) return configBytes;
                if (uri.EndsWith("tokenizer_config.json", StringComparison.Ordinal)) return tokConfigBytes;
                return null;
            });
            using var httpClient = new HttpClient(handler);

            await OnnxNerModelDownloader.EnsureModelAsync(tempDir, httpClient: httpClient);
            Assert.Equal(4, httpCalls);
            Assert.True(File.Exists(Path.Combine(tempDir, "onnx", "model_quantized.onnx")));
            Assert.True(File.Exists(Path.Combine(tempDir, "vocab.txt")));
            Assert.True(File.Exists(Path.Combine(tempDir, "config.json")));
            Assert.True(File.Exists(Path.Combine(tempDir, "tokenizer_config.json")));

            // Second run must skip all cached files cleanly with zero network requests
            await OnnxNerModelDownloader.EnsureModelAsync(tempDir, httpClient: httpClient);
            Assert.Equal(4, httpCalls);

            // Verify 1-line AddTieredCpuNer(dir, ...) works end-to-end against downloaded directory
            using var engine = PiiEngineBuilder.Create()
                .WithMasterKey("one-line-ner-builder-key-32b!!")
                .AddDefaultRecognizers()
                .AddTieredCpuNer(tempDir, targetKeys: new[] { "notes" }, maxCpuPercent: 25)
                .Build();

            string masked = engine.MaskJson("""{"notes":"User Vikram Patel lives in Mumbai"}""");
            Assert.DoesNotContain("Vikram Patel", masked);
            Assert.DoesNotContain("Mumbai", masked);
        }
        finally
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
    }

    private sealed class FakeHfHandler : HttpMessageHandler
    {
        private readonly Func<string, byte[]?> _resolver;
        public FakeHfHandler(Func<string, byte[]?> resolver) => _resolver = resolver;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            byte[]? payload = _resolver(request.RequestUri!.AbsoluteUri);
            if (payload == null)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));

            var resp = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(payload)
            };
            return Task.FromResult(resp);
        }
    }

    private static string? FindRealModelDirectory()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            string candidate = Path.Combine(dir.FullName, "models", "distilbert-multilingual-ner-int8");
            if (File.Exists(Path.Combine(candidate, "onnx", "model_quantized.onnx")) ||
                File.Exists(Path.Combine(candidate, "onnx", "model_int8.onnx")))
            {
                return candidate;
            }
            dir = dir.Parent;
        }
        return null;
    }
}
