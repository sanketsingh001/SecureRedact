# SecureRedact (FintechGuard.Pii)

> **High-Throughput .NET 10 PII Masking & Format-Preserving Reversible Tokenization Engine for Fintech Payloads.**
> Designed for deeply nested, arbitrary-key JSON payloads where key names have no semantic guarantee.

[![Build & Test](https://img.shields.io/badge/tests-50%20passed-brightgreen.svg)](#)
[![Target](https://img.shields.io/badge/.NET-10.0-blue.svg)](#)
[![Security](https://img.shields.io/badge/Security-AES--256--GCM-orange.svg)](#)

---

## 1. Why FintechGuard.Pii vs Microsoft Presidio?

| Capability | Microsoft Presidio (Python) | FintechGuard.Pii (.NET 10) |
| :--- | :--- | :--- |
| **Throughput & Speed** | Slow Python GIL; ~100-300 records/sec on nested dicts | **3,500+ records/sec (Masking)**, **52,000+ records/sec (Unmasking)** |
| **Nested JSON Support** | Clunky manual dictionary recursion | **Native streaming** via `Utf8JsonReader` and `Utf8JsonWriter` |
| **Arbitrary Key Names** | Relies heavily on key hints or heavy spaCy NLP | **Algorithmic check digits** (Luhn, Verhoeff, Mod-97) — zero key dependence |
| **Reversible Unmasking** | ❌ None (One-way redaction/hash only) | ✅ **Built-in Reversible Cryptographic Tokenization** (AES-256-GCM) |
| **"Feels Like Masking"** | Replaces with `<CREDIT_CARD>` tag | **Format-preserving mask** (`4532-****-****-0366#fp[...]`) |
| **Indian Fintech PII** | Bare minimum | **Full statutory suite**: Aadhaar, PAN, GSTIN, IFSC, UPI, DL, Voter ID, Passport |
| **Memory Footprint** | 500MB – 1.5GB (PyTorch/spaCy) | **~25MB** (Zero-alloc `Span<char>` & direct UTF-8 streaming) |

---

## 2. Key Capabilities

### A. Arbitrary Key Names (Zero Key Dependency)
In fintech pipelines, JSON keys can be anything (`"k0"`, `"f7"`, `"col_3"`, `"data"`). FintechGuard.Pii detects PII by inspecting the **values mathematically**:
- **Credit/Debit Cards (PAN)**: Validated via the **Luhn Algorithm (Modulo 10)**. Random 16-digit sequences fail Luhn ~90% of the time, virtually eliminating false positives.
- **Indian Aadhaar Card**: Validated via the **Verhoeff Algorithm** (Dihedral group $D_8$). Detects 100% of single-digit errors and over 95% of adjacent transpositions.
- **Indian Income Tax PAN**: Validated via structural entity syntax (validates the 4th character entity type: `P` for Person, `C` for Company, `H` for HUF, `F` for Firm, etc.).
- **GSTIN**: 15-character validation with statutory state code checks (01 to 38), embedded PAN validation, and required 'Z' digit.
- **Bank IFSC**: 11-character bank code verification (`^[A-Z]{4}0[A-Z0-9]{6}$`).
- **UPI VPA**: Validated across top Indian PSP and bank handles (`@okhdfcbank`, `@paytm`, `@ybl`, etc.).
- **Global IBAN**: Validated using **ISO 7064 Modulo 97**.
- **US SSN**: Strict area (no 000, 666, 9xx), group (no 00), and serial (no 0000) verification.
- **Email, IP, and Phone**: RFC-compliant patterns and octet ranges.

---

### B. "Encryption Which Feels Like Masking"
Downstream logging systems, analytics, or junior engineers see what looks like standard masked data. But authorized compliance services with the Master Key can restore the data identically:

| PII Type | Raw Value | Masked Output (Feels Like Masking) | After `UnmaskJson()` |
| :--- | :--- | :--- | :--- |
| **Credit Card** | `4532-0151-1283-0366` | `4532-****-****-0366#fp[uBzpCFHU3eKcr...]` | `4532-0151-1283-0366` |
| **Aadhaar** | `2123 4567 8901` | `XXXX XXXX 8901#fp[Ip2HjHMR83wW...]` | `2123 4567 8901` |
| **PAN Card** | `ABCPE1234F` | `AB****1234F#fp[9aB1kL...]` | `ABCPE1234F` |
| **UPI ID** | `rohit.sharma@okhdfcbank` | `ro***a@okhdfcbank#fp[3mINQ4...]` | `rohit.sharma@okhdfcbank` |
| **Email** | `audit.fintech@bank.com` | `a*****h@bank.com#fp[bVzQvn...]` | `audit.fintech@bank.com` |

---

## 3. Quick Start

### 1. Fluent Builder Setup
```csharp
using FintechGuard.Pii.Core;

var engine = PiiEngineBuilder.Create()
    .WithMasterKey("your-32-byte-secret-master-key!") // AES-256-GCM
    .AddDefaultRecognizers()                         // Indian + Global PII
    .SetDefaultStrategy(MaskingStrategy.FormatPreservingReversible)
    .Build();
```

### 2. Arbitrary-Key Nested JSON Masking & Unmasking
```csharp
string arbitraryJson = """
{
  "k_random_1": "4532-0151-1283-0366",
  "nested": {
    "f_99": "2123 4567 8901",
    "arr": [
      { "item_id": "ABCPE1234F" },
      { "status": "TXN_APPROVED" }
    ]
  }
}
""";

// Mask nested JSON (Streaming Utf8JsonReader/Writer)
string maskedJson = engine.MaskJson(arbitraryJson);

// Unmask nested JSON back to original values
string unmaskedJson = engine.UnmaskJson(maskedJson);
```

---

## 4. POCO / DTO C# Model Support

For strongly-typed C# models, use declarative attributes:

```csharp
using FintechGuard.Pii.Attributes;
using FintechGuard.Pii.Serialization;

public class TransactionDto
{
    public string TransactionId { get; set; }

    [PiiMask(PiiType.CreditCard)]
    public string CardNumber { get; set; }

    [PiiMask(PiiType.Pan)]
    public string CustomerPan { get; set; }

    [PiiIgnore] // Never mask this field even if it matches a pattern
    public string PublicIdentifier { get; set; }

    public decimal Amount { get; set; }
}

// 1. Serialize with automatic masking:
string json = engine.SerializeWithMasking(dto);

// 2. Deserialize with automatic unmasking (for authorized services):
var restoredDto = engine.DeserializeAndUnmask<TransactionDto>(json);
```

---

## 5. Adding Custom Rules and Recognizers

You can register custom internal account numbers, loan IDs, or custom fintech patterns:

```csharp
var engine = PiiEngineBuilder.Create()
    .WithMasterKey("fintech-key-256bit!")
    .AddDefaultRecognizers()
    .AddCustomRecognizer(
        name: "FintechLoanId",
        pattern: @"LOAN-\d{8}",
        piiType: PiiType.Custom,
        customTypeName: "LoanId",
        validator: val => val.EndsWith("99") // Optional custom C# predicate
    )
    .Build();
```

---

## 6. Performance Benchmarks

Tested on .NET 10.0 (Release Build) with 5,000 deeply nested transaction objects (35,000+ PII values):

- **Payload Size**: 1.81 MB
- **Masking Speed**: **3,681 records/sec** (includes full AES-256-GCM authenticated encryption + Luhn + Verhoeff checks)
- **Unmasking Speed**: **52,925 records/sec** (19.17 MB/second)
- **Integrity**: 100% byte-for-byte fidelity restored on unmask.

---

## 7. ASP.NET Core Middleware (`FintechGuard.Pii.AspNetCore`)

Protect your entire API surface with a single line of code. The middleware transparently masks PII in all request and response JSON bodies.

### One-Liner Integration
```csharp
// Program.cs
builder.Services.AddPiiMasking(options =>
{
    options.MasterKey = "your-32-byte-secret-master-key!";
    options.MaskRequests = true;
    options.MaskResponses = true;
    options.ExcludePaths = ["/health", "/metrics", "/swagger"];
});

var app = builder.Build();
app.UsePiiMasking();
```

### Or Inline (No DI Required)
```csharp
app.UsePiiMasking(options =>
{
    options.MasterKey = "your-key";
    options.ExcludePaths = ["/health"];
});
```

### What Happens Automatically:
- **Inbound Requests**: JSON bodies with PII (credit cards, Aadhaar, PAN, etc.) are masked before reaching your controllers.
- **Outbound Responses**: JSON response bodies are scanned and PII is masked before reaching the client.
- **Excluded Paths**: Health checks, metrics, and swagger are skipped for performance.
- **Large Payloads**: Bodies larger than `MaxBodySizeBytes` (default 10 MB) are passed through without scanning.

---

## 8. LLM Privacy Proxy (`FintechGuard.Pii.LlmProxy`)

Protect customer PII when sending prompts to OpenAI, Gemini, Claude, or any LLM API. Masks PII before it leaves your network, unmasks tokens in responses.

### Simple Prompt Masking
```csharp
var proxy = LlmPrivacyProxy.Create(options =>
{
    options.MasterKey = "your-key";
});

// Before sending to LLM:
string safePrompt = proxy.MaskPrompt("Analyze transaction for card 4532-0151-1283-0366");
// safePrompt: "Analyze transaction for card 4532-****-****-0366#fp[...]"

// After receiving LLM response (if it echoed back tokens):
string restored = proxy.UnmaskResponse(llmResponse);
```

### Transparent HttpClient Integration
```csharp
// Works with any LLM SDK that uses HttpClient
var client = PiiSafeClientFactory.CreateForOpenAI(engine, "sk-your-api-key");
// All requests through this client automatically mask PII in prompts
// All responses automatically unmask reversible tokens
var response = await client.PostAsync("/v1/chat/completions", content);
```

### Audit Before Sending
```csharp
// See exactly what PII would be sent to the LLM
var detections = proxy.AuditPrompt("Customer card is 4532-0151-1283-0366, UPI is rohit.sharma@okhdfcbank");
// Returns: [CreditCard: 4532-0151-1283-0366, UpiId: rohit.sharma@okhdfcbank]
```

### Supported LLM Providers
- **OpenAI** (GPT-4, GPT-4o, o1, etc.)
- **Google Gemini**
- **Anthropic Claude**
- **Any custom endpoint** via `PiiSafeClientFactory.Create(engine, "https://your-llm.com")`

---

## 9. Interactive Web API Sample (`samples/FintechGuard.WebApi`)

An out-of-the-box ASP.NET Core Web API demonstrating real-time masking, unmasking, and edge cases:

- **`POST /api/pii/mask`**: Masks arbitrary nested JSON payloads with format-preserving reversible tokens (`#ENC:v1:...`).
- **`POST /api/pii/unmask`**: Restores the original payload using the authenticated master key.
- **`POST /api/pii/detect`**: Audits and reports all PII types and locations without altering the payload.
- **`GET /api/pii/sample-edge-cases`**: Returns real-world fintech edge cases (deeply nested objects, arrays, false-positive test cases, statutory ID formats).

Run the sample:
```bash
dotnet run --project samples/FintechGuard.WebApi
```

