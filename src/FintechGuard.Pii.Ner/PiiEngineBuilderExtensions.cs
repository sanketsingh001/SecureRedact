using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Ner;

/// <summary>
/// Builder extensions for attaching Tier 1 pure-CPU Contextual NER and Tier 2 tokenized ONNX NER to <see cref="PiiEngineBuilder"/>.
/// </summary>
public static class PiiEngineBuilderExtensions
{
    /// <summary>
    /// Adds Tier 1 sub-millisecond pure-CPU Contextual &amp; Gazetteer NER (English + Hindi Devanagari names, addresses, and optional orgs)
    /// without requiring any ONNX model or GPU.
    /// </summary>
    public static PiiEngineBuilder AddContextualNerRecognizer(
        this PiiEngineBuilder builder,
        Action<ContextualNerOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        var options = new ContextualNerOptions();
        configure?.Invoke(options);
        builder.AddRecognizer(new ContextualNerRecognizer(options));
        return builder;
    }

    /// <summary>
    /// Adds Tier 2 CPU-optimized tokenized ONNX token-classification NER.
    /// </summary>
    public static PiiEngineBuilder AddOnnxNerRecognizer(
        this PiiEngineBuilder builder,
        OnnxNerOptions options)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(options);
        builder.AddRecognizer(new OnnxNerRecognizer(options));
        return builder;
    }

    /// <summary>
    /// Configures the recommended cascaded CPU-only NER pipeline: Tier 1 Contextual/Lexicon NER plus optional Tier 2 ONNX NER.
    /// </summary>
    public static PiiEngineBuilder AddTieredCpuNer(
        this PiiEngineBuilder builder,
        Action<ContextualNerOptions>? configureTier1 = null,
        OnnxNerOptions? tier2Options = null)
    {
        builder.AddContextualNerRecognizer(configureTier1);
        if (tier2Options != null)
            builder.AddOnnxNerRecognizer(tier2Options);
        return builder;
    }

    /// <summary>
    /// One-line setup for the cascaded Tier 1 + Tier 2 CPU NER pipeline from a local Hugging Face ONNX directory,
    /// automatically enabling fintech domain exclusions, CPU bounds, and target key filtering.
    /// </summary>
    public static PiiEngineBuilder AddTieredCpuNer(
        this PiiEngineBuilder builder,
        string onnxModelDirectory,
        string[]? targetKeys = null,
        int maxCpuPercent = 25,
        double minConfidence = 0.70)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(onnxModelDirectory);

        string[] keys = targetKeys ?? Array.Empty<string>();
        builder.AddContextualNerRecognizer(opts => opts.TargetKeys = keys);

        var tier2 = OnnxNerOptions.FromHuggingFaceDirectory(
            onnxModelDirectory,
            targetKeys: keys,
            minConfidence: minConfidence,
            enableMicroBatching: false,
            intraOpNumThreads: 1,
            excludedTerms: OnnxNerOptions.DefaultFintechExcludedTerms);

        if (maxCpuPercent > 0)
            tier2.WithMaxCpuUsage(maxCpuPercent);

        builder.AddOnnxNerRecognizer(tier2);
        return builder;
    }
}
