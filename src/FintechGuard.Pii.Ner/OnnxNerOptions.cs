using System.Text.Json;
using FintechGuard.Pii.Core;
using Microsoft.ML.Tokenizers;

namespace FintechGuard.Pii.Ner;

/// <summary>
/// Configuration for real CPU-optimized ONNX token-classification NER (<see cref="OnnxNerRecognizer"/>).
/// </summary>
public sealed class OnnxNerOptions
{
    public static readonly IReadOnlyDictionary<int, string> DefaultBioLabels = new Dictionary<int, string>
    {
        [0] = "O",
        [1] = "B-PER",
        [2] = "I-PER",
        [3] = "B-ORG",
        [4] = "I-ORG",
        [5] = "B-LOC",
        [6] = "I-LOC",
        [7] = "B-MISC",
        [8] = "I-MISC"
    };

    public static readonly IReadOnlyDictionary<string, PiiType> DefaultEntityTypeMap =
        new Dictionary<string, PiiType>(StringComparer.OrdinalIgnoreCase)
        {
            ["PER"] = PiiType.PersonName,
            ["PERSON"] = PiiType.PersonName,
            ["LOC"] = PiiType.Address,
            ["GPE"] = PiiType.Address,
            ["ADDR"] = PiiType.Address,
            ["ADDRESS"] = PiiType.Address,
            ["ORG"] = PiiType.Organization
        };

    public static readonly IReadOnlySet<string> DefaultFintechExcludedTerms =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "NEFT", "RTGS", "IMPS", "UPI", "IFSC", "KYC", "SWIFT", "SEPA", "ACH", "IBAN",
            "PAN", "GSTIN", "EMI", "OTP", "Customer", "User", "Agent", "ग्राहक", "कस्टमर"
        };

    /// <summary>
    /// Auto-discovers a Hugging Face / Optimum exported ONNX NER model directory containing
    /// an ONNX graph (preferring dynamic quantized <c>model_quantized.onnx</c>, then <c>model_int8.onnx</c>),
    /// <c>vocab.txt</c>, <c>config.json</c> (<c>id2label</c>), and <c>tokenizer_config.json</c> (<c>do_lower_case</c>).
    /// </summary>
    public static OnnxNerOptions FromHuggingFaceDirectory(
        string modelDirectory,
        string[]? targetKeys = null,
        double minConfidence = 0.75,
        bool enableMicroBatching = false,
        int intraOpNumThreads = 1,
        int batchWorkerCount = 1,
        IReadOnlySet<string>? excludedTerms = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(modelDirectory);
        if (!Directory.Exists(modelDirectory))
            throw new DirectoryNotFoundException($"ONNX NER model directory not found: '{modelDirectory}'.");

        string[] candidateModels =
        [
            Path.Combine(modelDirectory, "model_quantized.onnx"),
            Path.Combine(modelDirectory, "onnx", "model_quantized.onnx"),
            Path.Combine(modelDirectory, "model_int8.onnx"),
            Path.Combine(modelDirectory, "onnx", "model_int8.onnx"),
            Path.Combine(modelDirectory, "model_uint8.onnx"),
            Path.Combine(modelDirectory, "onnx", "model_uint8.onnx"),
            Path.Combine(modelDirectory, "model.onnx"),
            Path.Combine(modelDirectory, "onnx", "model.onnx"),
        ];

        string? modelPath = candidateModels.FirstOrDefault(File.Exists);
        if (modelPath == null)
        {
            throw new FileNotFoundException(
                $"No ONNX model file (model_int8.onnx, model_quantized.onnx, model_uint8.onnx, or model.onnx) found in '{modelDirectory}'.");
        }

        string vocabCandidate = Path.Combine(modelDirectory, "vocab.txt");
        string? vocabPath = File.Exists(vocabCandidate) ? vocabCandidate : null;

        IReadOnlyDictionary<int, string> idToLabel = DefaultBioLabels;
        string configPath = Path.Combine(modelDirectory, "config.json");
        if (File.Exists(configPath))
        {
            using var stream = File.OpenRead(configPath);
            using var doc = JsonDocument.Parse(stream);
            if (doc.RootElement.TryGetProperty("id2label", out var id2LabelElem) &&
                id2LabelElem.ValueKind == JsonValueKind.Object)
            {
                var parsedLabels = new Dictionary<int, string>();
                foreach (var prop in id2LabelElem.EnumerateObject())
                {
                    if (int.TryParse(prop.Name, out int id) && prop.Value.ValueKind == JsonValueKind.String)
                    {
                        parsedLabels[id] = prop.Value.GetString()!;
                    }
                }
                if (parsedLabels.Count > 0)
                    idToLabel = parsedLabels;
            }
        }

        bool lowerCase = false;
        string tokConfigPath = Path.Combine(modelDirectory, "tokenizer_config.json");
        if (File.Exists(tokConfigPath))
        {
            using var stream = File.OpenRead(tokConfigPath);
            using var doc = JsonDocument.Parse(stream);
            if (doc.RootElement.TryGetProperty("do_lower_case", out var lowerProp) &&
                (lowerProp.ValueKind == JsonValueKind.True || lowerProp.ValueKind == JsonValueKind.False))
            {
                lowerCase = lowerProp.GetBoolean();
            }
        }

        return new OnnxNerOptions
        {
            ModelPath = modelPath,
            VocabPath = vocabPath,
            IdToLabel = idToLabel,
            LowerCaseBeforeTokenization = lowerCase,
            TargetKeys = targetKeys ?? Array.Empty<string>(),
            MinConfidence = minConfidence,
            EnableMicroBatching = enableMicroBatching,
            IntraOpNumThreads = Math.Max(1, intraOpNumThreads),
            InterOpNumThreads = 1,
            BatchWorkerCount = Math.Max(1, batchWorkerCount),
            ExcludedTerms = excludedTerms
        };
    }

    /// <summary>
    /// Downloads (if absent) the default multilingual quantized CPU ONNX NER model into <paramref name="modelDirectory"/>
    /// using pure .NET and returns ready-to-use <see cref="OnnxNerOptions"/> with fintech term filtering and CPU caps applied.
    /// </summary>
    public static async Task<OnnxNerOptions> EnsureDefaultModelAndCreateAsync(
        string modelDirectory,
        string[]? targetKeys = null,
        int maxCpuPercent = 25,
        double minConfidence = 0.70,
        string? hfToken = null,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        await OnnxNerModelDownloader.EnsureModelAsync(
            modelDirectory,
            hfToken: hfToken,
            progress: progress,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        var opts = FromHuggingFaceDirectory(
            modelDirectory,
            targetKeys: targetKeys,
            minConfidence: minConfidence,
            enableMicroBatching: false,
            intraOpNumThreads: 1,
            excludedTerms: DefaultFintechExcludedTerms);

        if (maxCpuPercent > 0)
            opts.WithMaxCpuUsage(maxCpuPercent);

        return opts;
    }

    /// <summary>
    /// Path to the quantized INT8 or FP32 ONNX token-classification model.
    /// </summary>
    public required string ModelPath { get; init; }

    /// <summary>
    /// Path to BERT WordPiece vocab.txt. If null, looks for vocab.txt alongside <see cref="ModelPath"/> unless <see cref="CustomTokenizer"/> is supplied.
    /// </summary>
    public string? VocabPath { get; init; }

    /// <summary>
    /// Optional pre-constructed <see cref="Tokenizer"/> (e.g. SentencePieceTokenizer, WordPieceTokenizer, or custom BertTokenizer).
    /// </summary>
    public Tokenizer? CustomTokenizer { get; init; }

    /// <summary>
    /// Recognizer display name for audit telemetry.
    /// </summary>
    public string Name { get; set; } = "ONNX_NER_Model";

    /// <summary>
    /// Whether BertTokenizer lowercases text before tokenization. Default: false (preserves casing for cased NER models).
    /// </summary>
    public bool LowerCaseBeforeTokenization { get; set; } = false;

    /// <summary>
    /// Model class index to BIO/BIOES label mapping.
    /// </summary>
    public IReadOnlyDictionary<int, string> IdToLabel { get; set; } = DefaultBioLabels;

    /// <summary>
    /// Maps NER entity group names (e.g. PER, LOC, ORG) to <see cref="PiiType"/>.
    /// </summary>
    public IReadOnlyDictionary<string, PiiType> EntityTypeMap { get; set; } = DefaultEntityTypeMap;

    /// <summary>
    /// Maximum token length per inference window (including [CLS] and [SEP]). Default: 128.
    /// </summary>
    public int MaxSequenceLength { get; set; } = 128;

    /// <summary>
    /// Overlapping token stride for long texts exceeding <see cref="MaxSequenceLength"/>. Default: 32.
    /// </summary>
    public int SlidingWindowStride { get; set; } = 32;

    /// <summary>
    /// ONNX Runtime intra-op threads per session call. Keep low (1-2) on concurrent CPU servers to avoid OpenMP thread thrashing.
    /// </summary>
    public int IntraOpNumThreads { get; set; } = 1;

    /// <summary>
    /// ONNX Runtime inter-op threads. Default: 1.
    /// </summary>
    public int InterOpNumThreads { get; set; } = 1;

    /// <summary>
    /// JSON property names to selectively run ONNX inference on (matched on identifier boundaries).
    /// </summary>
    public string[] TargetKeys { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Minimum average softmax confidence required to emit a span match. Default: 0.75.
    /// </summary>
    public double MinConfidence { get; set; } = 0.75;

    /// <summary>
    /// Enables dynamic Channel-based micro-batching across concurrent requests to saturate CPU AVX2/AVX-512 SIMD throughput.
    /// </summary>
    public bool EnableMicroBatching { get; set; } = false;

    /// <summary>
    /// Maximum items combined per micro-batch. Default: 16.
    /// </summary>
    public int MaxBatchSize { get; set; } = 16;

    /// <summary>
    /// Maximum wait time in milliseconds before flushing a partial micro-batch. Default: 3 ms.
    /// </summary>
    public int MaxBatchWaitMs { get; set; } = 3;

    /// <summary>
    /// Bounded queue capacity for pending micro-batch items. Default: 1024.
    /// </summary>
    public int MaxBatchQueueCapacity { get; set; } = 1024;

    /// <summary>
    /// Number of concurrent micro-batch consumer tasks when <see cref="EnableMicroBatching"/> is true. Default: 1.
    /// </summary>
    public int BatchWorkerCount { get; set; } = 1;

    /// <summary>
    /// Optional set of exact surface forms (e.g. banking acronyms/honorifics) excluded from emitted NER matches. Default: null.
    /// </summary>
    public IReadOnlySet<string>? ExcludedTerms { get; set; }

    /// <summary>
    /// Maximum number of concurrent ONNX Runtime inference calls allowed across threads (0 = unlimited). Default: 0.
    /// </summary>
    public int MaxConcurrentInferences { get; set; } = 0;

    /// <summary>
    /// Maximum number of 128-token sliding windows inspected per JSON field (0 = unlimited). Default: 8 (CPU DoS protection).
    /// </summary>
    public int MaxWindowsPerField { get; set; } = 8;

    /// <summary>
    /// Disables ONNX Runtime intra/inter-op worker busy-spinning so shared servers do not burn idle CPU. Default: true.
    /// </summary>
    public bool DisableThreadSpinning { get; set; } = true;

    /// <summary>
    /// Configures ONNX inference threads, anti-spinning, and concurrency bulkhead to stay within approximately <paramref name="maxCpuPercent"/>% of host CPU cores.
    /// </summary>
    public OnnxNerOptions WithMaxCpuUsage(int maxCpuPercent)
    {
        int slots = PiiEngineOptions.CalculateConcurrencyForCpuPercent(maxCpuPercent, threadsPerOperation: 1);
        IntraOpNumThreads = 1;
        InterOpNumThreads = 1;
        DisableThreadSpinning = true;
        MaxConcurrentInferences = slots;
        BatchWorkerCount = Math.Min(Math.Max(1, BatchWorkerCount), slots);
        return this;
    }
}
