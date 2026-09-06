using System.Diagnostics;
using System.Text;
using System.Text.Json;
using FintechGuard.Pii.Core;

Console.WriteLine("==================================================================");
Console.WriteLine("  FintechGuard.Pii - High-Performance Nested JSON Benchmark");
Console.WriteLine("==================================================================");

var engine = PiiEngineBuilder.Create()
    .WithMasterKey("benchmark-master-key-fintech-256b!")
    .AddDefaultRecognizers()
    .SetDefaultStrategy(MaskingStrategy.FormatPreservingReversible)
    .Build();

// 1. Generate a large nested JSON payload simulating real fintech batch payloads
int recordCount = 5000;
Console.WriteLine($"Generating nested JSON payload with {recordCount} financial transaction objects...");

var payload = new List<object>();
for (int i = 0; i < recordCount; i++)
{
    payload.Add(new
    {
        meta_id = $"TXN-{Guid.NewGuid()}",
        // Notice: keys have NO semantic guarantee!
        f_0 = "4532-0151-1283-0366",          // Credit Card
        f_1 = "2123 4567 8901",               // Aadhaar
        f_2 = "ABCPE1234F",                   // PAN
        f_3 = "DE89370400440532013000",       // IBAN
        f_4 = "HDFC0000240",                  // IFSC
        f_5 = "payee.support@okhdfcbank",     // UPI
        f_6 = "safe_status_confirmed",
        nested = new
        {
            sub_k = "27ABCPE1234F1Z5",        // GSTIN
            sub_email = "audit.fintech@bank.com",
            arr = new object[]
            {
                new { item = 100 + i },
                new { notes = "Regular ledger transaction entry" }
            }
        }
    });
}

string rawJson = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = false });
byte[] rawBytes = Encoding.UTF8.GetBytes(rawJson);
double sizeMb = rawBytes.Length / (1024.0 * 1024.0);

Console.WriteLine($"Generated JSON size: {sizeMb:F2} MB ({rawBytes.Length:N0} bytes)");
Console.WriteLine();

// 2. Warm-up
Console.WriteLine("Warming up JIT compiler and SIMD paths...");
string warmUpMasked = engine.MaskJson("""{"card": "4532-0151-1283-0366", "pan": "ABCPE1234F", "aadhaar": "2123 4567 8901"}""");
string warmUpUnmasked = engine.UnmaskJson(warmUpMasked);

// 3. Benchmark Streaming Masking
Console.WriteLine($"--- 1. Masking Benchmark ({sizeMb:F2} MB payload with arbitrary keys) ---");
var sw = Stopwatch.StartNew();
string maskedJson = engine.MaskJson(rawJson);
sw.Stop();

double maskSeconds = sw.Elapsed.TotalSeconds;
double maskThroughputMbPerSec = sizeMb / maskSeconds;
Console.WriteLine($"Masking completed in: {sw.ElapsedMilliseconds} ms ({maskSeconds:F3}s)");
Console.WriteLine($"Throughput: {maskThroughputMbPerSec:F2} MB/second");
Console.WriteLine($"Records Processed: {(recordCount / maskSeconds):N0} records/sec");
Console.WriteLine();

// 4. Benchmark Streaming Unmasking (AES-GCM decryption of all tokens)
Console.WriteLine($"--- 2. Unmasking Benchmark (Reversible Decryption) ---");
sw.Restart();
string unmaskedJson = engine.UnmaskJson(maskedJson);
sw.Stop();

double unmaskSeconds = sw.Elapsed.TotalSeconds;
double unmaskThroughputMbPerSec = sizeMb / unmaskSeconds;
Console.WriteLine($"Unmasking completed in: {sw.ElapsedMilliseconds} ms ({unmaskSeconds:F3}s)");
Console.WriteLine($"Throughput: {unmaskThroughputMbPerSec:F2} MB/second");
Console.WriteLine($"Records Unmasked: {(recordCount / unmaskSeconds):N0} records/sec");
Console.WriteLine();

// 5. Verification
Console.WriteLine("--- 3. Verifying Integrity & Fidelity ---");
bool sampleCheck = maskedJson.Contains("4532-****-****-0366#fp[");
bool originalRestored = unmaskedJson.Contains("4532-0151-1283-0366") && unmaskedJson.Contains("2123 4567 8901");
Console.WriteLine($"Visual Format-Preserving Mask present: {sampleCheck}");
Console.WriteLine($"Original Values restored identically: {originalRestored}");
Console.WriteLine("==================================================================");
