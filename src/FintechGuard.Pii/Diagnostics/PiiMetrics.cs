using System.Diagnostics.Metrics;

namespace FintechGuard.Pii.Diagnostics;

/// <summary>
/// Provides zero-overhead, native .NET metrics that can be scraped by OpenTelemetry, Prometheus, or Azure App Insights.
/// These metrics incur absolutely zero overhead if no telemetry listener is attached.
/// </summary>
public static class PiiMetrics
{
    public static readonly string MeterName = "FintechGuard.PiiEngine";
    public static readonly string Version = "1.0.0";
    
    private static readonly Meter Meter = new(MeterName, Version);

    /// <summary>
    /// Tracks the total number of JSON payloads or strings processed.
    /// </summary>
    public static readonly Counter<long> PayloadsProcessed = Meter.CreateCounter<long>(
        "pii.payloads.processed", 
        "payloads", 
        "Total number of payloads successfully processed.");

    /// <summary>
    /// Tracks the exact count of PII data points masked, tagged by PiiType.
    /// </summary>
    public static readonly Counter<long> ElementsMasked = Meter.CreateCounter<long>(
        "pii.elements.masked", 
        "elements", 
        "Count of distinct PII elements detected and masked.");

    /// <summary>
    /// Tracks errors like malformed JSON or Regex Timeouts.
    /// </summary>
    public static readonly Counter<long> ProcessingErrors = Meter.CreateCounter<long>(
        "pii.processing.errors", 
        "errors", 
        "Count of errors encountered during stream processing.");
}
