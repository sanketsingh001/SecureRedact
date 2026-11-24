# SecureRedact (`FintechGuard.Pii`)

> **Production-Grade, CPU-Only .NET 8 & 10 PII Masking, Format-Preserving AES-256-GCM Tokenization & Tiered NER Engine for Fintech Systems.**  
> Built for arbitrary-key nested JSON/NDJSON payloads with explicit server CPU limits and zero GPU requirements.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Target](https://img.shields.io/badge/.NET-8.0%20|%2010.0-blue.svg)](#)
[![Security](https://img.shields.io/badge/Security-AES--256--GCM-orange.svg)](#)

---

## 1. What You Need to Use SecureRedact

| Requirement | Details |
| :--- | :--- |
| **Runtime** | **.NET 8.0** or **.NET 10.0** (multi-targeted). |
| **Hardware** | **Standard CPU only** — no GPU, CUDA, or Python installation required in production. |
| **Packages** | Pick only what your service uses:<br>• `SecureRedact` — core JSON/NDJSON/POCO PII masking & crypto engine.<br>• `SecureRedact.AspNetCore` — automatic HTTP JSON request/response middleware + CPU backpressure.<br>• `SecureRedact.Ner` — optional CPU-only Tier 1 (lexicon/rules) + Tier 2 (ONNX transformer) NER for names, addresses & orgs. |
| **Encryption Key** | • **Permanent redaction only (`CreateOneWay()`):** No key required.<br>• **Reversible tokenization (`#fp[...]`, `ENC{...}`):** Supply a 32-byte KMS key ring (`WithKeyRing` — recommended for production) or master passphrase (`WithMasterKey`), plus an optional HMAC key (`WithHashKey`) for `MaskingStrategy.Hash`. |
| **ONNX Weights *(Tier 2 NER only)*** | Only needed if you enable neural NER for free-text fields (`chat_transcript`, `notes`). Download automatically from C# at startup/deploy via `OnnxNerModelDownloader.EnsureModelAsync(...)` (~`130 MB`, outbound HTTPS to Hugging Face once, cached locally). Not needed for Tier 0 financial/ID detection or Tier 1 rule-based NER. |

```bash
dotnet add package SecureRedact
# Optional:
dotnet add package SecureRedact.AspNetCore
dotnet add package SecureRedact.Ner
```

---

## 2. Quick Start (1–2 Lines)

### Option A — Core JSON / String / NDJSON Masking (`SecureRedact`)

```csharp
using FintechGuard.Pii.Core;

// Reversible AES-256-GCM masking (Passphrase or KeyRing), capped to ~25% of server CPU cores:
using var engine = PiiEngine.CreateDefault(
    masterKey: Environment.GetEnvironmentVariable("PII_MASTER_KEY"),
    maxCpuPercent: 25);

string masked = engine.MaskJson(rawJson);
string restored = engine.UnmaskJson(masked);

// Or zero-key permanent redaction:
using var oneWay = PiiEngine.CreateOneWay(maxCpuPercent: 25);
string redacted = oneWay.MaskJson(rawJson);
```

For production key rotation from a KMS / Key Vault:
```csharp
using var engine = PiiEngine.CreateWithKeyRing(
    activeKeyId: "k2",
    keyRing: new Dictionary<string, byte[]>
    {
        ["k1"] = legacyKeyBytes32,
        ["k2"] = activeKeyBytes32
    },
    maxCpuPercent: 25);
```

### Option B — ASP.NET Core Automatic HTTP Middleware (`SecureRedact.AspNetCore`)

Add a `SecureRedact` section to `appsettings.json` (inject `MasterKey` via User Secrets / Key Vault / environment variables in production):
```json
{
  "SecureRedact": {
    "MasterKey": "",
    "MaxCpuPercent": 25,
    "ConcurrencyAcquireTimeoutMs": 2000,
    "MaxBodySizeBytes": 10485760,
    "ExcludePaths": [ "/health", "/metrics" ]
  }
}
```

Wire it up in `Program.cs` in 2 lines:
```csharp
using FintechGuard.Pii.AspNetCore;

builder.Services.AddPiiMasking(builder.Configuration.GetSection("SecureRedact"));

var app = builder.Build();
app.UsePiiMasking();
```
*If `MasterKey` and `MasterKeyBytes` are both omitted, the middleware safely falls back to `OneWayRedaction` instead of throwing.*

### Zero-Copy UTF-8, NDJSON Streaming & POCO Attributes
```csharp
using System.Buffers;
using FintechGuard.Pii.Attributes;
using FintechGuard.Pii.Serialization;

// Zero-copy UTF-8 JSON:
var output = new ArrayBufferWriter<byte>(inputUtf8.Length + 256);
engine.MaskJsonUtf8(inputUtf8, output);

// Constant-memory NDJSON / multijson stream:
await engine.MaskNdjsonStreamAsync(inputNdjsonStream, outputNdjsonStream);

// Strongly-typed POCO redaction:
public class TransactionDto
{
    [PiiMask(PiiType.CreditCard, MaskingStrategy.OneWayRedaction, MaskChar = '#')]
    public string CardNumber { get; set; } = string.Empty;

    [CustomPiiRule(@"LOAN-\d{6}", Strategy = MaskingStrategy.FormatPreservingReversible, KeepPrefix = 5, KeepSuffix = 2)]
    public string LoanRef { get; set; } = string.Empty;

    [PiiIgnore]
    public string PublicReference { get; set; } = string.Empty;
}

string safeJson = engine.SerializeWithMasking(dto);
var restoredDto = engine.DeserializeAndUnmask<TransactionDto>(safeJson);
```

---

## 3. CPU-Only High-Throughput Architecture (No GPU Required)

SecureRedact uses a **3-tier cascaded CPU architecture** so structured financial payloads run at native-JSON speeds while unstructured text escalates only when needed:

1. **Tier 0 — SIMD Character-Bitmask Gate + Zero-Copy Streaming Structured Engine (`SecureRedact`)**
   - Single-pass `TextFeatures.Analyze` bitmask skips irrelevant recognizers per JSON string token.
   - Strictly $O(n)$ linear scanners (Credit/Debit Cards with IIN/BIN + Luhn, Indian Mobile, NPCI UPI `@`-handle lookup) and `RegexOptions.NonBacktracking` DFAs (PAN, GSTIN with Modulo-36 checksum, Aadhaar with Verhoeff checksum, IBAN with ISO-13616 lengths + Mod-97, SSN, IFSC, Email, IPv4/IPv6, E.164 Phone, context-gated DOB).
   - Versioned AES-256-GCM tokenization (`#fp[...]` and `ENC{...}`) with key-ID (`kid`) rotation headers, thread-local `AesGcm` instances, and keyed HMAC-SHA256 hashing (`MaskingStrategy.Hash`).

2. **Tier 1 — Sub-Millisecond Pure-CPU Contextual & Lexicon NER (`SecureRedact.Ner`)**
   - `ContextualNerRecognizer` uses an $O(n)$ case-insensitive Aho-Corasick automaton, English & Hindi Devanagari triggers, curated Indian + global name lexicons, and structural address extraction with banking stopword filtering. Zero ONNX weights required.

3. **Tier 2 — Quantized CPU ONNX Token-Classification NER (`SecureRedact.Ner`)**
   - `OnnxNerRecognizer` executes `BertTokenizer` encoding with Devanagari-safe regex pre-tokenization (`[\w\p{M}]+|[^\w\p{M}\s]`), exact UTF-16 `EncodedToken.Offset` alignment, left/right WordPiece boundary snapping, sliding windows (`MaxWindowsPerField = 8` CPU DoS cap), softmax BIO/BIOES decoding, and anti-spinning `SessionOptions`.

---

## 4. Easy Tiered CPU NER Setup (`SecureRedact.Ner`)

### Pure-.NET Model Download + 1-Line Engine Registration (No Python Needed)

```csharp
using FintechGuard.Pii.Core;
using FintechGuard.Pii.Ner;

// 1. Download & cache Xenova/distilbert-base-multilingual-cased-ner-hrl (~130 MB) once on startup:
string modelDir = Path.Combine(AppContext.BaseDirectory, "models", "distilbert-multilingual-ner");
await OnnxNerModelDownloader.EnsureModelAsync(modelDir);

// 2. Attach Tier 1 + Tier 2 CPU NER capped to 25% host CPU & scoped to free-text JSON keys:
using var engine = PiiEngineBuilder.Create()
    .WithKeyRing("k2", keyRing)
    .WithMaxCpuUsage(25, acquireTimeout: TimeSpan.FromSeconds(2))
    .AddDefaultRecognizers()
    .AddTieredCpuNer(
        modelDir,
        targetKeys: ["chat_transcript", "notes", "address_line"],
        maxCpuPercent: 25)
    .Build();
```

*(Need a reproducible offline script for Docker image builds instead? `pip install huggingface_hub && python scripts/download_ner_model.py` populates `models/distilbert-multilingual-ner-int8`.)*

> **Production Threading Rule:** Keep `EnableMicroBatching = false` (the default in `FromHuggingFaceDirectory` and `AddTieredCpuNer`) when running ONNX inside `PiiEngine` or ASP.NET Core middleware — direct parallel execution is both faster on multi-core CPUs (`172.3` vs `150.5 inf/s` on 8 cores) and avoids sync-over-async blocking. Only set `EnableMicroBatching = true` when calling `OnnxNerRecognizer.RecognizeAsync(...)` directly from async workers.

### CPU-Only ONNX Model Selection Guide

| Hugging Face ONNX Model | ONNX File & Size | Depth & Languages | CPU Tradeoff & Recommendation |
| :--- | :--- | :--- | :--- |
| **`Xenova/distilbert-base-multilingual-cased-ner-hrl`** | `onnx/model_quantized.onnx` (`129.09 MB`) | 6 layers, 104 langs (Hindi Devanagari + English + Hinglish) | **Recommended.** 1.49x faster and markedly higher Indian/Hindi recall than symmetric `model_int8.onnx`; 1.82x faster than 12-layer mBERT. |
| `Xenova/bert-base-multilingual-cased-ner-hrl` | `onnx/model_quantized.onnx` (`170.2 MB`) | 12 layers, 104 langs (Hindi + English) | Higher-capacity fallback (~1.82x slower on CPU with similar Indian entity recall). |
| `onnx-community/distilbert-NER-ONNX` | `onnx/model_int8.onnx` (`62.7 MB`) | 6 layers, English-only | Fast English-only option; no Hindi/Devanagari NER support. |
| `onnx-community/piiranha-v1-detect-personal-information-ONNX` | `onnx/model_int8.onnx` (`302.5 MB`) | 12-layer DeBERTa-v2, European langs | ~2.3x larger, no Hindi support, and most PII labels overlap with deterministic Tier 0 recognizers. |

---

## 5. Server CPU Limiting, Backpressure & Security Controls

On shared application hosts, cap CPU consumption explicitly across every layer so traffic spikes never starve core API threads:

- **Core Engine (`PiiEngineBuilder.WithMaxCpuUsage(pct)` / `WithMaxConcurrency(n, timeout)`):** Limits concurrent engine calls using a fair `SemaphoreSlim` bulkhead and honors `PiiErrorBehavior` (`Redact`, `PassThrough`, `Throw`) on slot timeout.
- **ONNX NER (`OnnxNerOptions.WithMaxCpuUsage(pct)`, `MaxWindowsPerField`, `DisableThreadSpinning`):** Disables ONNX Runtime intra/inter-op worker busy-spinning (`allow_spinning = 0` by default), restricts simultaneous transformer runs, and caps worst-case sliding windows per oversized text field (`8` by default).
- **ASP.NET Core Middleware (`PiiMaskingOptions.MaxCpuPercent` / `MaxConcurrentRequests`):**
  - Acquires `WaitAsync` **only around inbound/outbound JSON CPU masking** — never held across downstream `await _next(context)` I/O.
  - Under overload with `ConcurrencyLimitBehavior.RejectWith503`, responds fail-closed with HTTP `503 Service Unavailable` + `Retry-After: 1` (never forwards unmasked PII).
  - Handles `ContentLength` and chunked/HTTP2 streams, passes binary downloads & SSE (`text/event-stream`) through with zero buffering, enforces `RejectWith413` on oversized bodies, and restores `HttpContext.Response.Body` on downstream exceptions.

---

## 6. Observability & Resilience

- **OpenTelemetry Meter (`FintechGuard.PiiEngine`)** (`PiiMetrics`):
  - `pii.payloads.processed` (Counter)
  - `pii.elements.masked` (Counter tagged by `pii_type`)
  - `pii.processing.errors` (Counter tagged by `error_type`)
  - `pii.processing.duration` (Histogram in `ms`)
- **ActivitySource (`FintechGuard.PiiEngine`)** (`PiiTracing`)
- **Audit Results (`MaskJsonWithAudit`)**: `HasPii`, `PiiFieldCount`, `DurationMs`, and per-detection `Type`, `RecognizerName`, `Confidence`, `JsonPath`, and `FullJsonPath`.

---

## 7. Verification, Benchmarks & Commands

Verified across both **`.NET 8.0` (`8.0.26`)** and **`.NET 10.0` (`10.0.9`)** on an 8-core Windows CPU (Release build, no GPU):

- **Unit & Integration Tests:** **80 / 80 passed on `net8.0`** and **80 / 80 passed on `net10.0`** (`0` failures, `0` skipped, `0` build warnings/errors).
- **LoadTest (`tests/FintechGuard.Pii.LoadTest`):**
  - **Tier 0 Structured JSON (`MaskJson` string, 100k payloads):** `44,391 payloads/sec` (`19.69 MB/s`), p50=`0.129 ms`, p95=`0.204 ms`, p99=`1.097 ms`, `0` Gen1/Gen2 GCs
  - **Tier 0 Structured JSON (`MaskJsonUtf8` zero-copy, 100k payloads):** `88,869 payloads/sec` (`39.41 MB/s`), p50=`0.049 ms`, p95=`0.121 ms`, p99=`0.808 ms`, `0` Gen1/Gen2 GCs
  - **Tier 0 + Tier 1 Pure-CPU Contextual NER (5 unstructured fields, 50k payloads):** `34,890 payloads/sec` (`11.78 MB/s`), p50=`0.184 ms`, p95=`0.360 ms`, p99=`1.125 ms`, `0` Gen1/Gen2 GCs
  - **Tier 0 + Tier 2 Synthetic ONNX Fixture (direct per-field, 10k payloads):** `9,853 payloads/sec` (`3.33 MB/s`), p50=`0.613 ms`, p95=`1.611 ms`, p99=`3.094 ms`, `0` Gen1/Gen2 GCs
  - **Tier 2 Synthetic ONNX Fixture (`EnableMicroBatching = true`, 10k inferences):** `38,407 batched ONNX inferences/sec` (`0.026 ms` avg/op)
  - **Real 6-Layer Quantized Multilingual DistilBERT (`Xenova/distilbert-base-multilingual-cased-ner-hrl`, `model_quantized.onnx`, `129.09 MB`):**
    - **Standalone Direct Parallel (8 cores, `IntraOpNumThreads=1`, 200 inferences):** `172.3 ONNX inferences/sec`, p50=`42.56 ms`, p95=`57.61 ms`, p99=`75.86 ms`
    - **Standalone Micro-Batched (4 batch workers, 32 concurrent callers, 400 inferences):** `150.5 batched ONNX inferences/sec` (`6.64 ms` avg/op)
    - **Production Cascaded Gateway (90% Tier 0+1 / 10% escalated to Real DistilBERT, 3,000 payloads):** `2,181.0 payloads/sec` (`0.459 ms` avg/payload)
    - **Real-Model Accuracy Audit (with `DefaultFintechExcludedTerms`):** Cleanly masks Indian English (`Sanjay Kumar`, `Bengaluru`, `Priya Sharma`, `Mumbai`, `Rajesh Nair`, `MG Road`, `Kochi`, `Kerala`), Hinglish (`Vikram Patel`, `Indiranagar`, `Bengaluru`), and Hindi Devanagari (`संजय कुमार`, `मुंबई`, `प्रिया शर्मा`, `दिल्ली`, `रवि वर्मा`, `पुणे`), with `0` false positives on the `NEFT` banking trap.
- **Single-Threaded Batch (`benchmarks/FintechGuard.Pii.Benchmarks`, 5,000 nested objects / `1.81 MB`):**
  - **Masking:** `4,968 records/sec` (`1.80 MB/s`, `1,006 ms`)
  - **Unmasking:** `37,884 records/sec` (`13.72 MB/s`, `131 ms`)
  - **Integrity:** 100% lossless round-trip fidelity verified.

```bash
dotnet build FintechGuard.slnx -c Release
dotnet test FintechGuard.slnx -c Release --no-build
dotnet run -c Release --project benchmarks/FintechGuard.Pii.Benchmarks
dotnet run -c Release --project tests/FintechGuard.Pii.LoadTest
```

---

## 8. NuGet Packages (`1.3.0`)

| Package | Description |
| :--- | :--- |
| **`SecureRedact`** | Core zero-copy PII masking, reversible AES-256-GCM key-ring tokenization, CPU concurrency controls, 1-line factories, and statutory validators (`net8.0;net10.0`). |
| **`SecureRedact.AspNetCore`** | Chunked-safe, fail-closed ASP.NET Core request/response masking middleware with `IConfiguration` binding and non-blocking CPU backpressure (`net8.0;net10.0`). |
| **`SecureRedact.Ner`** | Tier 1 pure-CPU Aho-Corasick contextual NER + Tier 2 quantized ONNX NER with pure-.NET model downloader, CPU caps, and micro-batching (`net8.0;net10.0`). |
