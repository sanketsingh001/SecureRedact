using System.Diagnostics;

namespace FintechGuard.Pii.Diagnostics;

/// <summary>
/// Provides zero-overhead, native .NET distributed tracing using ActivitySource.
/// Allows deep integration into Azure App Insights or OpenTelemetry spans.
/// </summary>
public static class PiiTracing
{
    public static readonly string SourceName = "FintechGuard.PiiEngine";
    public static readonly string Version = "1.0.0";
    
    public static readonly ActivitySource Source = new(SourceName, Version);
}
