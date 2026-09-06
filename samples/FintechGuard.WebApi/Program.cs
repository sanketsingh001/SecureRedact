using System.Text.Json;
using FintechGuard.Pii.AspNetCore;
using FintechGuard.Pii.Core;

var builder = WebApplication.CreateBuilder(args);

// 1. Configure FintechGuard.Pii in Dependency Injection
string masterKey = builder.Configuration["FintechGuard:MasterKey"] ?? "fintech-super-secret-master-key-32b!";
builder.Services.AddPiiMasking(options =>
{
    options.MasterKey = masterKey;
    options.UseIndianFintechRecognizers = true;
    options.UseGlobalFintechRecognizers = true;
    options.DefaultStrategy = MaskingStrategy.FormatPreservingReversible;
});

var app = builder.Build();

// 2. Interactive Web Dashboard for testing directly in any browser
app.MapGet("/", () => Results.Content("""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>FintechGuard.Pii - Enterprise Web API Playground</title>
  <style>
    :root {
      --bg: #0d1117;
      --card: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --accent: #58a6ff;
      --green: #2ea043;
      --purple: #8957e5;
      --code-bg: #090d13;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 24px;
      line-height: 1.5;
    }
    .header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      margin-bottom: 24px;
    }
    h1 { color: #f0f6fc; margin: 0 0 8px 0; font-size: 24px; }
    p { margin: 0; color: #8b949e; }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      font-size: 12px;
      font-weight: 600;
      border-radius: 12px;
      background: #238636;
      color: #fff;
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      display: flex;
      flex-direction: column;
    }
    .card-title {
      font-weight: 600;
      font-size: 16px;
      margin-bottom: 12px;
      color: #f0f6fc;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    textarea {
      width: 100%;
      height: 380px;
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: #79c0ff;
      font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
      font-size: 13px;
      padding: 12px;
      box-sizing: border-box;
      resize: vertical;
    }
    .actions {
      display: flex;
      gap: 10px;
      margin-top: 12px;
      flex-wrap: wrap;
    }
    button {
      background: var(--accent);
      color: #fff;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
      font-size: 13px;
      transition: opacity 0.2s;
    }
    button:hover { opacity: 0.85; }
    button.btn-green { background: var(--green); }
    button.btn-purple { background: var(--purple); }
    button.btn-gray { background: #30363d; color: #c9d1d9; }
    .footer-endpoints {
      margin-top: 24px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }
    .footer-endpoints code {
      background: var(--code-bg);
      padding: 2px 6px;
      border-radius: 4px;
      color: #ff7b72;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡️ FintechGuard.Pii Web API Host <span class="badge">Active & Ready</span></h1>
    <p>High-throughput .NET 10 PII masking, tokenization & format-preserving unmasking engine for arbitrary-key nested JSON payloads.</p>
  </div>

  <div class="grid">
    <div class="card">
      <div class="card-title">
        <span>Input JSON Payload</span>
        <button class="btn-gray" onclick="loadSample()">📥 Load Edge-Case JSON</button>
      </div>
      <textarea id="inputText" placeholder="Paste your arbitrary nested JSON or text here..."></textarea>
      <div class="actions">
        <button class="btn-purple" onclick="callApi('/api/mask')">🔒 Mask / Tokenize</button>
        <button class="btn-green" onclick="callApi('/api/unmask')">🔓 Unmask Reversible Tokens</button>
        <button onclick="callApi('/api/scan')">🔍 Scan PII Matches</button>
        <button class="btn-gray" onclick="clearBoxes()">🧹 Clear</button>
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        <span id="outputTitle">Engine Output</span>
        <span id="statusText" style="font-size: 12px; color: #8b949e;">Waiting for execution...</span>
      </div>
      <textarea id="outputText" readonly placeholder="Output from FintechGuard.Pii will appear here..."></textarea>
      <div class="actions">
        <button class="btn-gray" onclick="copyToInput()">⬅️ Use Output as Input</button>
      </div>
    </div>
  </div>

  <div class="footer-endpoints">
    <h3 style="margin-top: 0; color: #f0f6fc;">Available REST Minimal API Endpoints</h3>
    <ul>
      <li><code>GET /api/sample-edgecases</code> &mdash; Returns the complete master test JSON covering 20+ edge cases and negative traps.</li>
      <li><code>POST /api/mask</code> &mdash; Pass raw JSON body to mask & tokenize using format-preserving AES-256-GCM tokens.</li>
      <li><code>POST /api/unmask</code> &mdash; Pass masked JSON body to restore format-preserving tokens back to original plaintext.</li>
      <li><code>POST /api/scan</code> &mdash; Scans input text and returns JSON array of detected PII entities with confidence & offsets.</li>
      <li><code>POST /api/orders/process</code> &mdash; Sample fintech transaction endpoint demonstrating POCO redaction before logging.</li>
    </ul>
  </div>

  <script>
    async function loadSample() {
      document.getElementById('statusText').innerText = 'Loading edge-case JSON...';
      try {
        const res = await fetch('/api/sample-edgecases');
        const data = await res.json();
        document.getElementById('inputText').value = JSON.stringify(data, null, 2);
        document.getElementById('statusText').innerText = 'Loaded master edge cases.';
      } catch (err) {
        document.getElementById('statusText').innerText = 'Error loading sample: ' + err;
      }
    }

    async function callApi(endpoint) {
      const inputVal = document.getElementById('inputText').value.trim();
      if (!inputVal) {
        alert('Please enter or load a JSON payload first!');
        return;
      }

      document.getElementById('statusText').innerText = 'Processing ' + endpoint + '...';
      const startTime = performance.now();
      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: inputVal
        });

        const elapsed = (performance.now() - startTime).toFixed(2);
        const text = await res.text();
        try {
          const parsed = JSON.parse(text);
          document.getElementById('outputText').value = JSON.stringify(parsed, null, 2);
        } catch {
          document.getElementById('outputText').value = text;
        }
        document.getElementById('statusText').innerText = `Completed in ${elapsed} ms (HTTP ${res.status})`;
      } catch (err) {
        document.getElementById('statusText').innerText = 'Failed: ' + err;
      }
    }

    function copyToInput() {
      document.getElementById('inputText').value = document.getElementById('outputText').value;
    }

    function clearBoxes() {
      document.getElementById('inputText').value = '';
      document.getElementById('outputText').value = '';
      document.getElementById('statusText').innerText = 'Waiting for execution...';
    }

    // Auto-load sample on startup
    window.addEventListener('DOMContentLoaded', loadSample);
  </script>
</body>
</html>
""", "text/html"));

// 3. GET /api/sample-edgecases - Returns the master edge case JSON test payload
app.MapGet("/api/sample-edgecases", async () =>
{
    string[] candidatePaths =
    [
        Path.Combine(AppContext.BaseDirectory, "edge_cases.json"),
        Path.Combine(Directory.GetCurrentDirectory(), "edge_cases.json"),
        Path.Combine(Directory.GetCurrentDirectory(), "samples", "FintechGuard.WebApi", "edge_cases.json")
    ];

    string? foundPath = candidatePaths.FirstOrDefault(File.Exists);
    if (foundPath != null)
    {
        string json = await File.ReadAllTextAsync(foundPath);
        return Results.Content(json, "application/json");
    }

    return Results.NotFound(new { error = "edge_cases.json not found" });
});

// 4. POST /api/mask - Developer-controlled JSON masking with AES-256-GCM format-preserving tokens
app.MapPost("/api/mask", async (HttpContext context, IPiiEngine engine) =>
{
    using var reader = new StreamReader(context.Request.Body);
    string rawJson = await reader.ReadToEndAsync();
    if (string.IsNullOrWhiteSpace(rawJson))
    {
        return Results.BadRequest(new { error = "Request body cannot be empty" });
    }

    string maskedJson = engine.MaskJson(rawJson);
    return Results.Content(maskedJson, "application/json");
});

// 5. POST /api/unmask - Developer-controlled JSON unmasking restoring original plaintext
app.MapPost("/api/unmask", async (HttpContext context, IPiiEngine engine) =>
{
    using var reader = new StreamReader(context.Request.Body);
    string maskedJson = await reader.ReadToEndAsync();
    if (string.IsNullOrWhiteSpace(maskedJson))
    {
        return Results.BadRequest(new { error = "Request body cannot be empty" });
    }

    string unmaskedJson = engine.UnmaskJson(maskedJson);
    return Results.Content(unmaskedJson, "application/json");
});

// 6. POST /api/scan - Scan text or JSON and return detected PII matches
app.MapPost("/api/scan", async (HttpContext context, IPiiEngine engine) =>
{
    using var reader = new StreamReader(context.Request.Body);
    string text = await reader.ReadToEndAsync();
    if (string.IsNullOrWhiteSpace(text))
    {
        return Results.BadRequest(new { error = "Request body cannot be empty" });
    }

    var matches = engine.Scan(text);
    return Results.Ok(new
    {
        total_detected = matches.Count,
        matches = matches.Select(m => new
        {
            type = m.Type.ToString(),
            type_id = (int)m.Type,
            confidence = m.Confidence,
            value = m.RawValue,
            index = m.Index,
            length = m.Length
        })
    });
});

// 7. POST /api/mask-scoped - Demonstrates developer fine-grained control via JsonMaskingScope
app.MapPost("/api/mask-scoped", async (ScopedMaskRequest request, IPiiEngine engine) =>
{
    if (string.IsNullOrWhiteSpace(request.JsonPayload))
    {
        return Results.BadRequest(new { error = "JsonPayload cannot be empty" });
    }

    var scope = new JsonMaskingScope
    {
        IncludeTypes = request.IncludeTypes?.Select(Enum.Parse<PiiType>).ToHashSet(),
        ExcludeTypes = request.ExcludeTypes?.Select(Enum.Parse<PiiType>).ToHashSet(),
        ExcludeKeys = request.ExcludeKeys?.ToHashSet(),
        IncludeKeys = request.IncludeKeys?.ToHashSet(),
        StrategyOverride = request.StrategyOverride.HasValue ? (MaskingStrategy)request.StrategyOverride.Value : null
    };

    string masked = engine.MaskJson(request.JsonPayload, scope);
    return Results.Content(masked, "application/json");
});

// 8. POST /api/orders/process - Real-world fintech POCO endpoint demonstration
app.MapPost("/api/orders/process", (OrderPaymentRequest order, ILogger<Program> logger, IPiiEngine engine) =>
{
    // Real-world scenario: Developer masks the sensitive payment data before logging to console or Datadog/Splunk
    string rawOrderJson = JsonSerializer.Serialize(order);
    string maskedOrderJson = engine.MaskJson(rawOrderJson);

    logger.LogInformation("Processing Order {OrderId} securely: {MaskedPayload}", order.OrderId, maskedOrderJson);

    return Results.Ok(new
    {
        status = "SUCCESS",
        order_id = order.OrderId,
        amount = order.Amount,
        currency = order.Currency,
        secure_audit_payload = JsonDocument.Parse(maskedOrderJson).RootElement,
        message = "Order processed. PII was masked with reversible format-preserving tokens for audit compliance."
    });
});

// 9. POST /api/key-demo - Demonstrates key rotation, wrong key security, and token anatomy
app.MapPost("/api/key-demo", (KeyDemoRequest? request) =>
{
    string testKey1 = request?.Key1 ?? "bank-master-key-2026-v1-supersecret!";
    string testKey2 = request?.Key2 ?? "bank-master-key-2026-v2-different!";
    string rawValue = request?.Value ?? "4532-0151-1283-0366";

    // Build two distinct engines with different master keys
    var engineKey1 = PiiEngineBuilder.Create()
        .WithMasterKey(testKey1)
        .AddDefaultRecognizers()
        .SetDefaultStrategy(MaskingStrategy.FormatPreservingReversible)
        .Build();

    var engineKey2 = PiiEngineBuilder.Create()
        .WithMasterKey(testKey2)
        .AddDefaultRecognizers()
        .SetDefaultStrategy(MaskingStrategy.FormatPreservingReversible)
        .Build();

    // 1. Mask with Key 1
    string maskedWithKey1 = engineKey1.MaskValue(rawValue);

    // 2. Try unmask with matching Key 1
    bool successKey1 = engineKey1.TryUnmaskValue(maskedWithKey1, out string? unmaskedWithKey1);

    // 3. Try unmask with WRONG Key 2 (cryptographic AEAD authentication tag validation)
    bool successKey2 = engineKey2.TryUnmaskValue(maskedWithKey1, out string? unmaskedWithKey2);

    // 4. Token breakdown
    int fpIdx = maskedWithKey1.IndexOf("#fp[");
    string visualMask = fpIdx >= 0 ? maskedWithKey1[..fpIdx] : maskedWithKey1;
    string cipherPayload = (fpIdx >= 0 && maskedWithKey1.EndsWith(']')) 
        ? maskedWithKey1.Substring(fpIdx + 4, maskedWithKey1.Length - fpIdx - 5) 
        : "";

    return Results.Ok(new
    {
        original_plaintext = rawValue,
        key_1_used_for_masking = testKey1,
        key_2_different_key = testKey2,
        masked_output = maskedWithKey1,
        token_breakdown = new
        {
            visual_mask = visualMask,
            format_preserving_tag = "#fp[...]",
            authenticated_ciphertext_base64url = cipherPayload,
            cryptographic_algorithm = "AES-256-GCM (Authenticated Encryption with Associated Data)"
        },
        unmask_with_correct_key_1 = new
        {
            success = successKey1,
            restored_value = unmaskedWithKey1,
            status = successKey1 ? "MATCHES_ORIGINAL_IDENTICALLY" : "FAILED"
        },
        unmask_with_wrong_key_2 = new
        {
            success = successKey2,
            restored_value = unmaskedWithKey2,
            status = successKey2 ? "UNEXPECTED_SUCCESS" : "AUTHENTICATION_TAG_VERIFICATION_FAILED_SECURELY",
            explanation = "AES-GCM validates the 128-bit authentication tag. A different key fails tag verification; no plaintext is ever leaked."
        }
    });
});

app.Run();

public record KeyDemoRequest(
    string? Key1 = null,
    string? Key2 = null,
    string? Value = null
);

// DTOs for scoped and sample order endpoints
public record ScopedMaskRequest(
    string JsonPayload,
    List<string>? IncludeTypes = null,
    List<string>? ExcludeTypes = null,
    List<string>? ExcludeKeys = null,
    List<string>? IncludeKeys = null,
    int? StrategyOverride = null
);

public record OrderPaymentRequest(
    string OrderId,
    decimal Amount,
    string Currency,
    string CardNumber,
    string CustomerPan,
    string CustomerUpi,
    string CustomerEmail,
    string ClientIp
);
