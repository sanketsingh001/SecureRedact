using System.Buffers;
using System.Diagnostics;
using System.Text;
using FintechGuard.Pii.Core;
using FintechGuard.Pii.Ner;

namespace FintechGuard.Pii.LoadTest;

internal static class Program
{
    private static async Task Main(string[] args)
    {
        Console.WriteLine("======================================================================");
        Console.WriteLine("  SecureRedact Production CPU-Only High-Throughput Load Benchmark");
        Console.WriteLine($"  CPU Cores: {Environment.ProcessorCount} | .NET: {Environment.Version}");
        Console.WriteLine("======================================================================");

        string modelPath = ResolveFixturePath("test_ner.onnx");
        string vocabPath = ResolveFixturePath("test_vocab.txt");
        string? realModelDir = ResolveRealModelDirectory();

        string structuredPayload = """
        {
            "event_id": "evt_987654321",
            "timestamp": "2026-10-09T18:00:00Z",
            "data": {
                "transactions": [
                    {
                        "id": "tx_1",
                        "card_number": "4532-0151-1283-0366",
                        "pan": "ABCPE1234F",
                        "aadhaar": "2123 4567 8901",
                        "upi": "vikram.sharma@okhdfcbank",
                        "amount": 1500.50,
                        "status": "TXN_APPROVED_BY_GATEWAY"
                    }
                ]
            }
        }
        """;

        string unstructuredPayload = """
        {
            "raw_dump_1": "Log entry 512. Customer John Doe called.",
            "raw_dump_2": "Nothing but unstructured data here.",
            "feedback": "I spoke to Sanjay Kumar and he was helpful.",
            "unstructured_log": "कस्टमर का नाम रवि है, Issue resolved.",
            "chat_transcript": "User John Doe connected to agent Sanjay Kumar."
        }
        """;

        // Scenario A: Tier 0 Structured Fintech JSON (Zero-Copy UTF-8 & String API)
        using (var tier0Engine = PiiEngineBuilder.Create()
            .WithMasterKey("12345678901234567890123456789012")
            .AddDefaultRecognizers()
            .SetMinConfidence(0.80)
            .Build() as PiiEngine)
        {
            WarmUp(tier0Engine!, structuredPayload);
            RunParallelBenchmark("SCENARIO A1: Tier 0 Structured JSON (MaskJson string)", tier0Engine!, structuredPayload, 100_000, useUtf8Span: false);
            RunParallelBenchmark("SCENARIO A2: Tier 0 Structured JSON (MaskJsonUtf8 zero-copy)", tier0Engine!, structuredPayload, 100_000, useUtf8Span: true);
        }

        // Scenario B: Tier 0 + Tier 1 Pure-CPU Contextual NER (No ONNX model, no GPU)
        using (var tier1Engine = PiiEngineBuilder.Create()
            .WithMasterKey("12345678901234567890123456789012")
            .AddDefaultRecognizers()
            .AddContextualNerRecognizer(opts =>
            {
                opts.TargetKeys = new[] { "chat_transcript", "feedback", "raw_dump_1", "raw_dump_2", "unstructured_log" };
            })
            .Build() as PiiEngine)
        {
            WarmUp(tier1Engine!, unstructuredPayload);
            RunParallelBenchmark("SCENARIO B: Tier 0 + Tier 1 Pure-CPU Contextual NER (5 unstructured fields)", tier1Engine!, unstructuredPayload, 50_000, useUtf8Span: false);
        }

        // Scenario C: Tier 0 + Tier 2 Synthetic ONNX Fixture (Direct vs Micro-Batched)
        if (File.Exists(modelPath) && File.Exists(vocabPath))
        {
            using (var directOnnx = PiiEngineBuilder.Create()
                .WithMasterKey("12345678901234567890123456789012")
                .AddDefaultRecognizers()
                .AddOnnxNerRecognizer(new OnnxNerOptions
                {
                    ModelPath = modelPath,
                    VocabPath = vocabPath,
                    TargetKeys = new[] { "chat_transcript", "feedback", "raw_dump_1", "raw_dump_2", "unstructured_log" },
                    IntraOpNumThreads = 1,
                    InterOpNumThreads = 1,
                    EnableMicroBatching = false
                })
                .Build() as PiiEngine)
            {
                WarmUp(directOnnx!, unstructuredPayload);
                RunParallelBenchmark("SCENARIO C1: Tier 0 + Tier 2 Synthetic ONNX Fixture (Direct per-field)", directOnnx!, unstructuredPayload, 10_000, useUtf8Span: false);
            }

            using var batchedRecognizer = new OnnxNerRecognizer(new OnnxNerOptions
            {
                ModelPath = modelPath,
                VocabPath = vocabPath,
                TargetKeys = new[] { "chat_transcript", "feedback", "raw_dump_1", "raw_dump_2", "unstructured_log" },
                IntraOpNumThreads = 1,
                InterOpNumThreads = 1,
                EnableMicroBatching = true,
                MaxBatchSize = 16,
                MaxBatchWaitMs = 2
            });

            await RunAsyncBatchBenchmark("SCENARIO C2: Tier 2 Synthetic ONNX Fixture (Channel Micro-Batching)", batchedRecognizer, "User John Doe connected to agent Sanjay Kumar.", 10_000);
        }

        // Scenario D: REAL 6-Layer INT8 Multilingual DistilBERT ONNX (128.9 MB, Hindi + Hinglish + English)
        if (realModelDir != null)
        {
            await RunRealTransformerBenchmarksAsync(realModelDir, structuredPayload);
        }
        else
        {
            Console.WriteLine("\nSkipping Scenario D: Real INT8 model not found at models/distilbert-multilingual-ner-int8.");
            Console.WriteLine("Run: python scripts/download_ner_model.py");
        }
    }

    private static async Task RunRealTransformerBenchmarksAsync(string realModelDir, string structuredPayload)
    {
        var realOpts = OnnxNerOptions.FromHuggingFaceDirectory(
            realModelDir,
            targetKeys: new[] { "chat_transcript", "notes" },
            minConfidence: 0.70,
            enableMicroBatching: false,
            intraOpNumThreads: 1,
            excludedTerms: OnnxNerOptions.DefaultFintechExcludedTerms);
        double modelSizeMb = new FileInfo(realOpts.ModelPath).Length / (1024.0 * 1024.0);

        Console.WriteLine("\n======================================================================");
        Console.WriteLine("  REAL MODEL: Xenova/distilbert-base-multilingual-cased-ner-hrl (Quantized)");
        Console.WriteLine($"  Model File: {Path.GetFileName(realOpts.ModelPath)} ({modelSizeMb:F2} MB) in {realModelDir}");
        Console.WriteLine("======================================================================");

        string[] auditSamples =
        [
            "Customer Sanjay Kumar transferred Rs 25,000 from Bengaluru to Priya Sharma in Mumbai.",
            "Hinglish: User Vikram Patel called support from Indiranagar, Bengaluru regarding UPI.",
            "Hindi: ग्राहक संजय कुमार मुंबई से कॉल कर रहे हैं और प्रिया शर्मा दिल्ली में रहती हैं।",
            "Hindi short: कस्टमर का नाम रवि वर्मा है और वह पुणे में रहता है।",
            "Address: Please dispatch debit card for Rajesh Nair to 42 MG Road, Kochi, Kerala.",
            "Negative trap: NEFT settlement confirmed for transaction TXN_998120 with status APPROVED."
        ];

        using (var directRecognizer = new OnnxNerRecognizer(realOpts))
        {
            Console.WriteLine("\n--- REAL MODEL ACCURACY AUDIT (Tier 2 Quantized DistilBERT Standalone) ---");
            foreach (string sample in auditSamples)
            {
                var swSample = Stopwatch.StartNew();
                var matches = directRecognizer.Recognize(sample).ToList();
                swSample.Stop();
                string summary = matches.Count == 0
                    ? "(none)"
                    : string.Join(", ", matches.Select(m => $"{m.Type}:\"{m.RawValue}\"({m.Confidence:F2})"));
                Console.WriteLine($"  [{swSample.Elapsed.TotalMilliseconds:F1} ms] {sample}");
                Console.WriteLine($"           -> {summary}");
            }

            // Warm-up & Scenario D1: Direct parallel inference across CPU cores
            string benchText = "Customer Sanjay Kumar transferred Rs 25,000 from Bengaluru to Priya Sharma in Mumbai.";
            for (int w = 0; w < 8; w++)
                directRecognizer.Recognize(benchText);

            const int directCount = 200;
            double[] d1LatMs = new double[directCount];
            var swD1 = Stopwatch.StartNew();
            Parallel.For(0, directCount, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, i =>
            {
                long t0 = Stopwatch.GetTimestamp();
                directRecognizer.Recognize(benchText);
                d1LatMs[i] = (Stopwatch.GetTimestamp() - t0) * 1000.0 / Stopwatch.Frequency;
            });
            swD1.Stop();
            Array.Sort(d1LatMs);

            Console.WriteLine($"\n--- SCENARIO D1: REAL Quantized DistilBERT Multilingual (Direct Parallel, {directCount} inferences) ---");
            Console.WriteLine($"  Throughput:   {directCount / swD1.Elapsed.TotalSeconds:N1} ONNX inferences/sec");
            Console.WriteLine($"  Latency (ms): p50={d1LatMs[(int)(directCount * 0.50)]:F2} | p95={d1LatMs[(int)(directCount * 0.95)]:F2} | p99={d1LatMs[(int)(directCount * 0.99)]:F2}");
        }

        // Combined Tier 0 + Tier 1 + Real Quantized Tier 2 Accuracy Audit
        using (var combinedEngine = (PiiEngine)PiiEngineBuilder.Create()
            .WithMasterKey("12345678901234567890123456789012")
            .AddDefaultRecognizers()
            .AddTieredCpuNer(
                configureTier1: t1 => t1.TargetKeys = new[] { "notes" },
                tier2Options: OnnxNerOptions.FromHuggingFaceDirectory(
                    realModelDir,
                    targetKeys: new[] { "notes" },
                    minConfidence: 0.70,
                    enableMicroBatching: false,
                    intraOpNumThreads: 1,
                    excludedTerms: OnnxNerOptions.DefaultFintechExcludedTerms))
            .Build())
        {
            Console.WriteLine("\n--- COMBINED PIPELINE AUDIT (Tier 0 + Tier 1 Contextual + Tier 2 Quantized DistilBERT) ---");
            foreach (string sample in auditSamples)
            {
                string payload = System.Text.Json.JsonSerializer.Serialize(new { notes = sample });
                var auditResult = combinedEngine.MaskJsonWithAudit(payload);
                string detections = auditResult.Detections.Count == 0
                    ? "(none)"
                    : string.Join(", ", auditResult.Detections.Select(d => $"{d.Type}[{d.RecognizerName}]({d.Confidence:F2})"));
                Console.WriteLine($"  {sample}");
                Console.WriteLine($"           -> Detections: {detections}");
            }
        }

        // Scenario D2: Real Quantized DistilBERT with Multi-Worker Channel Micro-Batching
        int batchWorkers = Math.Max(2, Environment.ProcessorCount / 2);
        var batchedOpts = OnnxNerOptions.FromHuggingFaceDirectory(
            realModelDir,
            targetKeys: new[] { "chat_transcript", "notes" },
            minConfidence: 0.70,
            enableMicroBatching: true,
            intraOpNumThreads: 1,
            batchWorkerCount: batchWorkers,
            excludedTerms: OnnxNerOptions.DefaultFintechExcludedTerms);
        batchedOpts.MaxBatchSize = 8;
        batchedOpts.MaxBatchWaitMs = 2;

        using (var batchedReal = new OnnxNerRecognizer(batchedOpts))
        {
            string benchText = "Customer Sanjay Kumar transferred Rs 25,000 from Bengaluru to Priya Sharma in Mumbai.";
            for (int w = 0; w < 16; w++)
                await batchedReal.RecognizeAsync(benchText);

            const int batchTotal = 400;
            var swD2 = Stopwatch.StartNew();
            int remaining = batchTotal;
            var workers = Enumerable.Range(0, 32).Select(async _ =>
            {
                while (Interlocked.Decrement(ref remaining) >= 0)
                {
                    await batchedReal.RecognizeAsync(benchText);
                }
            });
            await Task.WhenAll(workers);
            swD2.Stop();

            Console.WriteLine($"\n--- SCENARIO D2: REAL Quantized DistilBERT Multilingual (Micro-Batched, {batchWorkers} workers, 32 concurrent, {batchTotal} inferences) ---");
            Console.WriteLine($"  Throughput:   {batchTotal / swD2.Elapsed.TotalSeconds:N1} batched ONNX inferences/sec (avg {swD2.Elapsed.TotalMilliseconds / batchTotal:F2} ms/op)");
        }

        // Scenario D3: Production Cascaded Fintech Gateway Simulation (90% Tier-0 structured + 10% escalated to Real Quantized DistilBERT)
        using var gatewayEngine = (PiiEngine)PiiEngineBuilder.Create()
            .WithMasterKey("12345678901234567890123456789012")
            .AddDefaultRecognizers()
            .AddTieredCpuNer(
                configureTier1: t1 => t1.TargetKeys = new[] { "notes" },
                tier2Options: OnnxNerOptions.FromHuggingFaceDirectory(
                    realModelDir,
                    targetKeys: new[] { "chat_transcript" },
                    minConfidence: 0.70,
                    enableMicroBatching: false,
                    intraOpNumThreads: 1,
                    excludedTerms: OnnxNerOptions.DefaultFintechExcludedTerms))
            .Build();

        string escalatedPayload = """
        {
            "event_id": "evt_chat_001",
            "card_number": "4532-0151-1283-0366",
            "chat_transcript": "Customer Sanjay Kumar called from Bengaluru regarding Priya Sharma in Mumbai."
        }
        """;

        for (int w = 0; w < 20; w++)
            gatewayEngine.MaskJson(w % 10 == 0 ? escalatedPayload : structuredPayload);

        const int gatewayTotal = 3_000;
        var swD3 = Stopwatch.StartNew();
        Parallel.For(0, gatewayTotal, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, i =>
        {
            gatewayEngine.MaskJson(i % 10 == 0 ? escalatedPayload : structuredPayload);
        });
        swD3.Stop();

        Console.WriteLine($"\n--- SCENARIO D3: Production Cascaded Gateway (90% Tier-0+1 / 10% Real INT8 DistilBERT, {gatewayTotal:N0} payloads) ---");
        Console.WriteLine($"  Combined TPS: {gatewayTotal / swD3.Elapsed.TotalSeconds:N1} payloads/sec ({swD3.Elapsed.TotalMilliseconds / gatewayTotal:F3} ms avg/payload)");
    }

    private static void WarmUp(IPiiEngine engine, string payload)
    {
        byte[] utf8 = Encoding.UTF8.GetBytes(payload);
        var buf = new ArrayBufferWriter<byte>(utf8.Length + 256);
        for (int i = 0; i < 200; i++)
        {
            engine.MaskJson(payload);
            buf.Clear();
            engine.MaskJsonUtf8(utf8, buf);
        }
    }

    private static void RunParallelBenchmark(string title, IPiiEngine engine, string payload, int iterations, bool useUtf8Span)
    {
        Console.WriteLine($"\n--- {title} ({iterations:N0} payloads) ---");
        byte[] payloadUtf8 = Encoding.UTF8.GetBytes(payload);

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        int gen0Before = GC.CollectionCount(0);
        int gen1Before = GC.CollectionCount(1);
        int gen2Before = GC.CollectionCount(2);
        long allocBefore = GC.GetTotalAllocatedBytes(precise: true);

        double[] latenciesUs = new double[iterations];
        var sw = Stopwatch.StartNew();

        Parallel.For(
            0,
            iterations,
            new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
            () => new ArrayBufferWriter<byte>(payloadUtf8.Length + 256),
            (i, _, localBuf) =>
            {
                long t0 = Stopwatch.GetTimestamp();
                if (useUtf8Span)
                {
                    localBuf.Clear();
                    engine.MaskJsonUtf8(payloadUtf8, localBuf);
                }
                else
                {
                    engine.MaskJson(payload);
                }
                latenciesUs[i] = (Stopwatch.GetTimestamp() - t0) * 1_000_000.0 / Stopwatch.Frequency;
                return localBuf;
            },
            _ => { });

        sw.Stop();
        long allocAfter = GC.GetTotalAllocatedBytes(precise: true);

        Array.Sort(latenciesUs);
        double elapsedSec = sw.Elapsed.TotalSeconds;
        double tps = iterations / elapsedSec;
        double mbPerSec = ((double)iterations * payloadUtf8.Length / (1024.0 * 1024.0)) / elapsedSec;
        double p50Ms = latenciesUs[(int)(iterations * 0.50)] / 1000.0;
        double p95Ms = latenciesUs[(int)(iterations * 0.95)] / 1000.0;
        double p99Ms = latenciesUs[(int)(iterations * 0.99)] / 1000.0;
        long bytesPerPayload = (allocAfter - allocBefore) / iterations;

        Console.WriteLine($"  Throughput:   {tps:N0} payloads/sec ({mbPerSec:F2} MB/s)");
        Console.WriteLine($"  Latency (ms): p50={p50Ms:F3} | p95={p95Ms:F3} | p99={p99Ms:F3}");
        Console.WriteLine($"  Memory/Op:    {bytesPerPayload:N0} B/payload | GC Gen0={GC.CollectionCount(0) - gen0Before}, Gen1={GC.CollectionCount(1) - gen1Before}, Gen2={GC.CollectionCount(2) - gen2Before}");
    }

    private static async Task RunAsyncBatchBenchmark(string title, OnnxNerRecognizer recognizer, string text, int iterations)
    {
        Console.WriteLine($"\n--- {title} ({iterations:N0} inferences) ---");
        for (int i = 0; i < 64; i++)
            await recognizer.RecognizeAsync(text);

        var sw = Stopwatch.StartNew();
        int remaining = iterations;
        var workers = Enumerable.Range(0, 64).Select(async _ =>
        {
            while (Interlocked.Decrement(ref remaining) >= 0)
            {
                await recognizer.RecognizeAsync(text);
            }
        });
        await Task.WhenAll(workers);
        sw.Stop();

        double tps = iterations / sw.Elapsed.TotalSeconds;
        Console.WriteLine($"  Throughput:   {tps:N0} batched ONNX inferences/sec (avg {sw.Elapsed.TotalMilliseconds / iterations:F3} ms/op)");
    }

    private static string ResolveFixturePath(string fileName)
    {
        string direct = Path.Combine(AppContext.BaseDirectory, fileName);
        if (File.Exists(direct))
            return direct;

        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            string candidate = Path.Combine(dir.FullName, "tests", "FintechGuard.Pii.Tests", "TestData", fileName);
            if (File.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }
        return direct;
    }

    private static string? ResolveRealModelDirectory()
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
