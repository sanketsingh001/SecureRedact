using System.Data;
using Kusto.Data.Common;
using Kusto.Data.Ingestion;
using Kusto.Ingest;
using FintechGuard.Pii.Core;

namespace FintechGuard.Pii.AzureDataExplorer;

/// <summary>
/// Wraps an existing <see cref="IKustoIngestClient"/> and transparently masks all PII in JSON
/// streams and files before they are forwarded to Azure Data Explorer (Kusto).
/// </summary>
public sealed class SecureKustoIngestClient : IKustoIngestClient
{
    private readonly IKustoIngestClient _inner;
    private readonly IPiiEngine _engine;
    private readonly SecureAdxOptions _options;

    internal SecureKustoIngestClient(IKustoIngestClient inner, IPiiEngine engine, SecureAdxOptions options)
    {
        _inner = inner;
        _engine = engine;
        _options = options;
    }

    // -----------------------------------------------------------------------
    // Stream Ingestion — Primary path for EventHub / Kafka data into ADX
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    public Task<IKustoIngestionResult> IngestFromStreamAsync(
        Stream stream,
        KustoIngestionProperties ingestionProperties,
        StreamSourceOptions? sourceOptions = null)
    {
        var sanitized = SanitizeStream(stream, ingestionProperties.Format);
        return _inner.IngestFromStreamAsync(sanitized, ingestionProperties, sourceOptions);
    }

    /// <inheritdoc/>
    public Task<IKustoIngestionResult> IngestFromStreamAsync(
        Stream stream,
        KustoIngestionProperties ingestionProperties,
        StreamSourceOptions sourceOptions,
        CancellationToken ct)
    {
        var sanitized = SanitizeStream(stream, ingestionProperties.Format);
        return _inner.IngestFromStreamAsync(sanitized, ingestionProperties, sourceOptions, ct);
    }

    // -----------------------------------------------------------------------
    // File Ingestion — Read file as stream, mask, then ingest via stream API
    // (IKustoIngestClient in v14 does not expose IngestFromFileAsync on the interface)
    // -----------------------------------------------------------------------

    /// <summary>
    /// Reads a local file, masks its PII content in-memory, and ingests via streaming.
    /// </summary>
    public Task<IKustoIngestionResult> IngestFromMaskedFileAsync(
        string filePath,
        KustoIngestionProperties ingestionProperties)
    {
        using var fileStream = File.OpenRead(filePath);
        var sanitized = SanitizeStream(fileStream, ingestionProperties.Format);
        return _inner.IngestFromStreamAsync(sanitized, ingestionProperties);
    }

    // -----------------------------------------------------------------------
    // Blob/Storage URI Ingestion — Cannot intercept in-place; alert & pass through
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    public Task<IKustoIngestionResult> IngestFromStorageAsync(
        string uri,
        KustoIngestionProperties ingestionProperties,
        StorageSourceOptions? sourceOptions = null)
    {
        _options.OnUnmaskedBlobIngestion?.Invoke(uri, ingestionProperties.TableName);
        return _inner.IngestFromStorageAsync(uri, ingestionProperties, sourceOptions);
    }

    // -----------------------------------------------------------------------
    // DataReader Ingestion — Typed relational rows; not a JSON stream, pass through
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    public Task<IKustoIngestionResult> IngestFromDataReaderAsync(
        IDataReader dataReader,
        KustoIngestionProperties ingestionProperties,
        DataReaderSourceOptions? sourceOptions = null)
        => _inner.IngestFromDataReaderAsync(dataReader, ingestionProperties, sourceOptions);

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private MemoryStream SanitizeStream(Stream input, DataSourceFormat? format)
    {
        var output = new MemoryStream();

        if (!ShouldMask(format))
        {
            input.CopyTo(output);
            output.Position = 0;
            return output;
        }

        _engine.MaskJsonStream(input, output);
        output.Position = 0;
        return output;
    }

    private static bool ShouldMask(DataSourceFormat? format)
    {
        if (format == null) return true; // Default: JSON assumed if format not specified

        return format.Value switch
        {
            DataSourceFormat.json       => true,
            DataSourceFormat.multijson  => true,
            DataSourceFormat.singlejson => true,
            // CSV, TSV, Parquet, Avro — not JSON, pass through unchanged
            _ => false
        };
    }

    public void Dispose() => _inner.Dispose();
}
