namespace FintechGuard.Pii.AzureDataExplorer;

/// <summary>
/// Configuration options for the SecureRedact ADX decorator.
/// </summary>
public sealed class SecureAdxOptions
{
    /// <summary>
    /// Optional callback invoked when a blob-URI based ingestion is attempted.
    /// Since blob URIs cannot be transparently intercepted and masked inline, this lets
    /// you log or alert when an unmasked blob path is submitted.
    /// Parameters: (blobUri, tableName)
    /// </summary>
    public Action<string, string>? OnUnmaskedBlobIngestion { get; set; }
}
