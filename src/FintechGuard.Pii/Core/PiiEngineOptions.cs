using FintechGuard.Pii.Crypto;
using FintechGuard.Pii.Recognizers;

namespace FintechGuard.Pii.Core;

public class PiiEngineOptions
{
    public IReversibleCrypto? CryptoProvider { get; set; }
    public byte[]? HashKey { get; set; }
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

    /// <summary>
    /// Maximum concurrent operations allowed inside this engine instance (0 = unlimited). Default: 0.
    /// </summary>
    public int MaxConcurrentOperations { get; set; } = 0;

    /// <summary>
    /// Maximum wait duration for a CPU concurrency slot when <see cref="MaxConcurrentOperations"/> &gt; 0. Default: infinite wait.
    /// </summary>
    public TimeSpan ConcurrencyAcquireTimeout { get; set; } = Timeout.InfiniteTimeSpan;

    /// <summary>
    /// Calculates a safe concurrency limit targeting approximately <paramref name="maxCpuPercent"/>% of host CPU cores.
    /// </summary>
    public static int CalculateConcurrencyForCpuPercent(int maxCpuPercent, int threadsPerOperation = 1)
    {
        if (maxCpuPercent < 1 || maxCpuPercent > 100)
            throw new ArgumentOutOfRangeException(nameof(maxCpuPercent), "CPU percentage must be between 1 and 100.");

        int effectiveThreadsPerOp = Math.Max(1, threadsPerOperation);
        int allowedCores = Math.Max(1, (int)Math.Floor(Environment.ProcessorCount * (maxCpuPercent / 100.0)));
        return Math.Max(1, allowedCores / effectiveThreadsPerOp);
    }

    public MaskingStrategy GetStrategy(PiiType type)
    {
        return StrategyOverrides.TryGetValue(type, out var strategy) ? strategy : DefaultStrategy;
    }
}
