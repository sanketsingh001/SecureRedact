using System;
using System.Diagnostics;
using System.Text;
using FintechGuard.Pii.Core;
using FintechGuard.Pii.Ner;

namespace FintechGuard.Pii.LoadTest;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Initializing FintechGuard.Pii Engine for Load Test...");
        
        string modelPath = "dummy_ner.onnx";
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "dummy_ner.onnx");
            if (File.Exists(candidate)) { modelPath = candidate; break; }
            dir = dir.Parent;
        }

        var engine = PiiEngineBuilder.Create()
            .WithMasterKey("12345678901234567890123456789012") // 32-byte AES key
            .AddDefaultRecognizers()
            .SetMinConfidence(0.80)
            .WithKeyHints(hints => 
            {
                hints.AddHint("secret_pan", PiiType.Pan, 0.30);
            })
            // Target ALL fields that might contain bad/unstructured data
            .AddOnnxNerRecognizer(modelPath: modelPath, targetKeys: new[] { "chat_transcript", "notes", "raw_dump", "feedback", "unstructured_log" })
            .Build();

        string normalPayload = """
        {
            "event_id": "evt_987654321",
            "timestamp": "2026-10-09T18:00:00Z",
            "data": {
                "transactions": [
                    {
                        "id": "tx_1",
                        "card_number": "4532 0151 1283 0366",
                        "amount": 1500.50,
                        "metadata": {
                            "support_tickets": [
                                {
                                    "ticket_id": "T-998",
                                    "history": {
                                        "chat_transcript": "कस्टमर का नाम रवि है, कार्ड नंबर 4532... है"
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
        """;

        string worstCasePayload = """
        {
            "raw_dump_1": "Log entry 512. Customer John Doe called.",
            "raw_dump_2": "Nothing but unstructured data here.",
            "feedback": "I spoke to Sanjay Kumar and he was helpful.",
            "unstructured_log": "कस्टमर का नाम रवि है, Issue resolved.",
            "chat_transcript": "User John Doe connected to agent Sanjay Kumar."
        }
        """;

        Console.WriteLine("Pre-warming engine (JIT)...");
        for (int i = 0; i < 100; i++)
        {
            engine.MaskJsonWithAudit(normalPayload);
            engine.MaskJsonWithAudit(worstCasePayload);
        }

        RunTest("SCENARIO A: Normal Payload (Structured Data, 1 ML Field)", engine, normalPayload, 100_000);
        RunTest("SCENARIO B: Worst Case 'Bad Data' Payload (5 ML Fields, 0.5ms blocking each)", engine, worstCasePayload, 20_000);
    }

    static void RunTest(string testName, IPiiEngine engine, string payload, int iterations)
    {
        Console.WriteLine($"\nStarting {testName} - {iterations:N0} payloads...");
        
        var sw = Stopwatch.StartNew();
        
        int processedCount = 0;
        int piiElementsMasked = 0;
        long totalBytes = 0;
        var payloadBytes = Encoding.UTF8.GetByteCount(payload);

        Parallel.For(0, iterations, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, i =>
        {
            var result = engine.MaskJsonWithAudit(payload);
            Interlocked.Increment(ref processedCount);
            Interlocked.Add(ref piiElementsMasked, result.PiiFieldCount);
            Interlocked.Add(ref totalBytes, payloadBytes);
        });

        sw.Stop();

        double elapsedSeconds = sw.Elapsed.TotalSeconds;
        double tps = processedCount / elapsedSeconds;
        double mbPerSecond = (totalBytes / 1024.0 / 1024.0) / elapsedSeconds;

        Console.WriteLine("-------------------------");
        Console.WriteLine($"THROUGHPUT (TPS):  {tps:N0} Transactions / Second");
        Console.WriteLine($"DATA SPEED:        {mbPerSecond:F2} MB / Second");
        Console.WriteLine($"AVG LATENCY:       {(elapsedSeconds * 1000) / processedCount:F4} ms per payload");
        Console.WriteLine("-------------------------\n");
    }
}
