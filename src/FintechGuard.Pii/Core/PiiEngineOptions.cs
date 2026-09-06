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

    public MaskingStrategy GetStrategy(PiiType type)
    {
        return StrategyOverrides.TryGetValue(type, out var strategy) ? strategy : DefaultStrategy;
    }
}
