using FintechGuard.Pii.Crypto;
using FintechGuard.Pii.Recognizers;

namespace FintechGuard.Pii.Core;

public class PiiEngineOptions
{
    public IReversibleCrypto? CryptoProvider { get; set; }
    public List<IPiiRecognizer> Recognizers { get; } = new();
    public MaskingStrategy DefaultStrategy { get; set; } = MaskingStrategy.FormatPreservingReversible;
    public Dictionary<PiiType, MaskingStrategy> StrategyOverrides { get; } = new();
    public char MaskCharacter { get; set; } = '*';

    /// <summary>
    /// Action to take when an unrecoverable error occurs (e.g. malformed JSON).
    /// </summary>
    public PiiErrorBehavior ErrorBehavior { get; set; } = PiiErrorBehavior.Throw;

    /// <summary>
    /// The minimum confidence score (0.0 to 1.0) required to mask a value. Default is 0.8.
    /// </summary>
    public double MinConfidence { get; set; } = 0.80;

    /// <summary>
    /// Registry for context-aware confidence boosting based on JSON keys.
    /// </summary>
    public FintechGuard.Pii.Context.KeyHintRegistry KeyHints { get; } = new();

    public MaskingStrategy GetStrategy(PiiType type)
    {
        return StrategyOverrides.TryGetValue(type, out var strategy) ? strategy : DefaultStrategy;
    }
}
