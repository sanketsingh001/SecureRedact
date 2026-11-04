namespace FintechGuard.Pii.Core;

/// <summary>
/// Exception thrown when the PII engine encounters an unrecoverable error during processing,
/// such as malformed JSON, and the ErrorBehavior is configured to Throw.
/// </summary>
public class PiiProcessingException : Exception
{
    public PiiProcessingException(string message) : base(message) { }
    public PiiProcessingException(string message, Exception innerException) : base(message, innerException) { }
}
