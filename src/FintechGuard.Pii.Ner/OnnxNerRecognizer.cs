using System.Text.RegularExpressions;
using FintechGuard.Pii.Context;
using FintechGuard.Pii.Core;
using FintechGuard.Pii.Recognizers;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using Microsoft.ML.Tokenizers;

namespace FintechGuard.Pii.Ner;

/// <summary>
/// Tier 2 CPU-optimized ONNX Token-Classification NER recognizer (e.g. INT8 quantized BERT / DistilBERT / mDeBERTa NER).
/// Performs genuine WordPiece/Tokenizer encoding with exact UTF-16 character Offset mapping, sliding windows,
/// softmax BIO decoding, and optional Channel-based micro-batching.
/// </summary>
public sealed class OnnxNerRecognizer : IFastPiiRecognizer, IDisposable
{
    private static readonly Regex IndicSafePreTokenizeRegex =
        new(@"[\w\p{M}]+|[^\w\p{M}\s]", RegexOptions.Compiled, TimeSpan.FromMilliseconds(100));

    public string Name => _options.Name;
    public PiiType PiiType => PiiType.PersonName;

    private readonly OnnxNerOptions _options;
    private readonly InferenceSession _session;
    private readonly Tokenizer _tokenizer;
    private readonly string _inputIdsName;
    private readonly string? _attentionMaskName;
    private readonly string? _tokenTypeIdsName;
    private readonly string _outputName;
    private readonly long _clsTokenId;
    private readonly long _sepTokenId;
    private readonly long _padTokenId;
    private readonly SemaphoreSlim? _inferenceGate;
    private readonly OnnxMicroBatcher? _microBatcher;
    private volatile bool _disposed;

    public OnnxNerRecognizer(OnnxNerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.ModelPath))
            throw new ArgumentException("OnnxNerOptions.ModelPath must be a valid path to an ONNX model.", nameof(options));
        if (!File.Exists(options.ModelPath))
            throw new FileNotFoundException($"ONNX NER model file was not found at '{options.ModelPath}'.", options.ModelPath);

        _options = options;
        _tokenizer = ResolveTokenizer(options);

        if (_tokenizer is BertTokenizer bert)
        {
            _clsTokenId = bert.ClassificationTokenId;
            _sepTokenId = bert.SeparatorTokenId;
            _padTokenId = bert.PaddingTokenId;
        }
        else
        {
            _clsTokenId = 101;
            _sepTokenId = 102;
            _padTokenId = 0;
        }

        var sessionOpts = new SessionOptions
        {
            GraphOptimizationLevel = GraphOptimizationLevel.ORT_ENABLE_ALL,
            ExecutionMode = ExecutionMode.ORT_SEQUENTIAL,
            IntraOpNumThreads = Math.Max(1, options.IntraOpNumThreads),
            InterOpNumThreads = Math.Max(1, options.InterOpNumThreads),
            EnableMemoryPattern = true,
            EnableCpuMemArena = true
        };
        if (options.DisableThreadSpinning)
        {
            sessionOpts.AddSessionConfigEntry("session.intra_op.allow_spinning", "0");
            sessionOpts.AddSessionConfigEntry("session.inter_op.allow_spinning", "0");
        }
        sessionOpts.AppendExecutionProvider_CPU(0);

        _session = new InferenceSession(options.ModelPath, sessionOpts);

        if (options.MaxConcurrentInferences > 0)
            _inferenceGate = new SemaphoreSlim(options.MaxConcurrentInferences, options.MaxConcurrentInferences);

        _inputIdsName = ResolveInputName(_session, "input_ids") ?? _session.InputMetadata.Keys.First();
        _attentionMaskName = ResolveInputName(_session, "attention_mask");
        _tokenTypeIdsName = ResolveInputName(_session, "token_type_ids");
        _outputName = _session.OutputMetadata.ContainsKey("logits")
            ? "logits"
            : _session.OutputMetadata.Keys.First();

        if (options.EnableMicroBatching)
        {
            _microBatcher = new OnnxMicroBatcher(
                _session,
                _options,
                _inputIdsName,
                _attentionMaskName,
                _tokenTypeIdsName,
                _outputName,
                _padTokenId,
                _inferenceGate);
        }
    }

    public bool MightMatch(in TextFeatures features)
    {
        return features.Length >= 2 && (features.HasAsciiUpper || features.HasAsciiLower || features.HasNonAscii);
    }

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Array.Empty<PiiMatch>();

        var features = TextFeatures.Analyze(text.AsSpan());
        if (!MightMatch(in features))
            return Array.Empty<PiiMatch>();

        var list = new List<PiiMatch>();
        var ctx = new RecognitionContext();
        RecognizeInto(text, in ctx, in features, list);
        return list;
    }

    public IEnumerable<PiiMatch> Recognize(string text, RecognitionContext context)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Array.Empty<PiiMatch>();

        var features = TextFeatures.Analyze(text.AsSpan());
        if (!MightMatch(in features))
            return Array.Empty<PiiMatch>();

        var list = new List<PiiMatch>();
        RecognizeInto(text, in context, in features, list);
        return list;
    }

    public void RecognizeInto(string text, in RecognitionContext context, in TextFeatures features, List<PiiMatch> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (string.IsNullOrWhiteSpace(text) || !MightMatch(in features))
            return;

        if (_options.TargetKeys.Length > 0 && context.PropertyName != null)
        {
            if (!KeyHintRegistry.MatchesAnyTargetKey(context.PropertyName, _options.TargetKeys))
                return;
        }

        var windows = BuildWindows(text);
        if (windows.Count == 0)
            return;

        var rawMatches = new List<PiiMatch>();
        for (int w = 0; w < windows.Count; w++)
        {
            var (inputIds, tokenInfos) = windows[w];
            IReadOnlyList<PiiMatch> decoded = _microBatcher != null
                ? _microBatcher.InferWindow(text, inputIds, tokenInfos)
                : RunSingleWindowSync(text, inputIds, tokenInfos);

            for (int i = 0; i < decoded.Count; i++)
                rawMatches.Add(decoded[i]);
        }

        BioEntityDecoder.MergeWindowMatches(rawMatches, destination);
    }

    /// <summary>
    /// Asynchronously executes ONNX NER inference, leveraging micro-batching without blocking thread-pool threads when enabled.
    /// </summary>
    public async Task<IReadOnlyList<PiiMatch>> RecognizeAsync(
        string text,
        RecognitionContext? context = null,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (string.IsNullOrWhiteSpace(text))
            return Array.Empty<PiiMatch>();

        if (_options.TargetKeys.Length > 0 && context?.PropertyName != null)
        {
            if (!KeyHintRegistry.MatchesAnyTargetKey(context.PropertyName, _options.TargetKeys))
                return Array.Empty<PiiMatch>();
        }

        var windows = BuildWindows(text);
        if (windows.Count == 0)
            return Array.Empty<PiiMatch>();

        var rawMatches = new List<PiiMatch>();
        for (int w = 0; w < windows.Count; w++)
        {
            var (inputIds, tokenInfos) = windows[w];
            IReadOnlyList<PiiMatch> decoded = _microBatcher != null
                ? await _microBatcher.InferWindowAsync(text, inputIds, tokenInfos, cancellationToken).ConfigureAwait(false)
                : RunSingleWindowSync(text, inputIds, tokenInfos);

            for (int i = 0; i < decoded.Count; i++)
                rawMatches.Add(decoded[i]);
        }

        var merged = new List<PiiMatch>(rawMatches.Count);
        BioEntityDecoder.MergeWindowMatches(rawMatches, merged);
        return merged;
    }

    private IReadOnlyList<PiiMatch> RunSingleWindowSync(string originalText, long[] inputIds, OnnxTokenWindowItem[] tokenInfos)
    {
        int seqLen = inputIds.Length;
        var dims = new[] { 1, seqLen };

        var attentionMask = new long[seqLen];
        Array.Fill(attentionMask, 1L);

        var inputs = new List<NamedOnnxValue>(3)
        {
            NamedOnnxValue.CreateFromTensor(_inputIdsName, new DenseTensor<long>(inputIds, dims))
        };

        if (_attentionMaskName != null)
            inputs.Add(NamedOnnxValue.CreateFromTensor(_attentionMaskName, new DenseTensor<long>(attentionMask, dims)));

        if (_tokenTypeIdsName != null)
            inputs.Add(NamedOnnxValue.CreateFromTensor(_tokenTypeIdsName, new DenseTensor<long>(new long[seqLen], dims)));

        bool acquired = false;
        try
        {
            if (_inferenceGate != null)
            {
                _inferenceGate.Wait();
                acquired = true;
            }

            using var results = _session.Run(inputs);
            var logits = results.First(r => r.Name == _outputName).AsTensor<float>();
            return BioEntityDecoder.DecodeWindow(originalText, logits, batchRowIndex: 0, tokenInfos.AsSpan(), _options);
        }
        finally
        {
            if (acquired) _inferenceGate!.Release();
        }
    }

    private List<(long[] InputIds, OnnxTokenWindowItem[] TokenInfos)> BuildWindows(string text)
    {
        IReadOnlyList<EncodedToken> rawTokens = _tokenizer.EncodeToTokens(
            text,
            out _,
            considerPreTokenization: true,
            considerNormalization: true);

        if (rawTokens.Count == 0)
            return new List<(long[], OnnxTokenWindowItem[])>(0);

        // Strip [CLS]/[SEP] if the custom tokenizer already inserted them so sliding windows are uniform
        int startIdx = 0;
        int endIdx = rawTokens.Count;
        if (rawTokens[0].Id == _clsTokenId) startIdx++;
        if (endIdx > startIdx && rawTokens[endIdx - 1].Id == _sepTokenId) endIdx--;

        int contentCount = endIdx - startIdx;
        if (contentCount <= 0)
            return new List<(long[], OnnxTokenWindowItem[])>(0);

        int maxContentTokens = Math.Max(2, _options.MaxSequenceLength - 2);
        int stride = Math.Clamp(_options.SlidingWindowStride, 0, maxContentTokens - 1);
        int step = Math.Max(1, maxContentTokens - stride);

        var windows = new List<(long[], OnnxTokenWindowItem[])>(1);
        int pos = 0;

        while (pos < contentCount)
        {
            if (_options.MaxWindowsPerField > 0 && windows.Count >= _options.MaxWindowsPerField)
                break;

            int take = Math.Min(maxContentTokens, contentCount - pos);
            int seqLen = take + 2;

            var inputIds = new long[seqLen];
            var tokenInfos = new OnnxTokenWindowItem[seqLen];

            inputIds[0] = _clsTokenId;
            tokenInfos[0] = new OnnxTokenWindowItem(0, 0, IsSpecial: true, IsSubword: false);

            for (int k = 0; k < take; k++)
            {
                var tok = rawTokens[startIdx + pos + k];
                inputIds[k + 1] = tok.Id;
                int offsetStart = tok.Offset.Start.GetOffset(text.Length);
                int offsetEnd = tok.Offset.End.GetOffset(text.Length);
                bool isSubword = tok.Value != null && tok.Value.StartsWith("##", StringComparison.Ordinal);
                tokenInfos[k + 1] = new OnnxTokenWindowItem(offsetStart, offsetEnd, IsSpecial: false, IsSubword: isSubword);
            }

            inputIds[seqLen - 1] = _sepTokenId;
            tokenInfos[seqLen - 1] = new OnnxTokenWindowItem(0, 0, IsSpecial: true, IsSubword: false);

            windows.Add((inputIds, tokenInfos));

            if (pos + take >= contentCount)
                break;

            pos += step;
        }

        return windows;
    }

    private static Tokenizer ResolveTokenizer(OnnxNerOptions options)
    {
        if (options.CustomTokenizer != null)
            return options.CustomTokenizer;

        string? vocabPath = options.VocabPath;
        if (string.IsNullOrWhiteSpace(vocabPath))
        {
            string? dir = Path.GetDirectoryName(options.ModelPath);
            if (!string.IsNullOrEmpty(dir))
            {
                string candidate = Path.Combine(dir, "vocab.txt");
                if (File.Exists(candidate))
                    vocabPath = candidate;
            }
        }

        if (string.IsNullOrWhiteSpace(vocabPath) || !File.Exists(vocabPath))
        {
            throw new FileNotFoundException(
                "A BERT WordPiece vocab.txt file (OnnxNerOptions.VocabPath) or CustomTokenizer is required for OnnxNerRecognizer.",
                vocabPath ?? "vocab.txt");
        }

        return BertTokenizer.Create(vocabPath, new BertOptions
        {
            ApplyBasicTokenization = false,
            LowerCaseBeforeTokenization = options.LowerCaseBeforeTokenization,
            RemoveNonSpacingMarks = options.LowerCaseBeforeTokenization,
            PreTokenizer = new RegexPreTokenizer(IndicSafePreTokenizeRegex, specialTokens: null),
            Normalizer = options.LowerCaseBeforeTokenization ? LowerCaseNormalizer.Instance : null
        });
    }

    private static string? ResolveInputName(InferenceSession session, string preferredName)
    {
        foreach (var key in session.InputMetadata.Keys)
        {
            if (string.Equals(key, preferredName, StringComparison.OrdinalIgnoreCase))
                return key;
        }
        return null;
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        _microBatcher?.Dispose();
        _session.Dispose();
        _inferenceGate?.Dispose();
    }
}
