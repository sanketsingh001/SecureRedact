using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.Ner;

public static class PiiEngineBuilderExtensions
{
    /// <summary>
    /// Adds an ONNX-based NER recognizer to detect names, addresses, and organizations.
    /// The recognizer uses contextual hints from JSON property names to optimize performance.
    /// </summary>
    public static PiiEngineBuilder AddOnnxNerRecognizer(
        this PiiEngineBuilder builder, 
        string modelPath, 
        string[]? targetKeys = null,
        double confidence = 0.85)
    {
        builder.AddRecognizer(new OnnxNerRecognizer(modelPath, targetKeys: targetKeys, confidence: confidence));
        return builder;
    }
}
