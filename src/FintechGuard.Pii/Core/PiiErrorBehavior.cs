namespace FintechGuard.Pii.Core;

/// <summary>
/// Defines how the PiiEngine behaves when it encounters an unrecoverable error (e.g., malformed JSON).
/// </summary>
public enum PiiErrorBehavior
{
    /// <summary>
    /// Fails loudly by throwing a PiiProcessingException. (Default for development)
    /// </summary>
    Throw = 0,

    /// <summary>
    /// Catches the exception, logs it via IPiiDiagnostics, and passes the raw data through unmasked. 
    /// Ensures pipelines do not drop data due to parsing errors.
    /// </summary>
    PassThrough = 1,

    /// <summary>
    /// Catches the exception and redacts/replaces the entire payload to prevent any accidental leakage.
    /// </summary>
    Redact = 2
}
