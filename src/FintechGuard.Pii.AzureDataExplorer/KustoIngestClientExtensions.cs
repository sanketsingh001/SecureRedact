using Kusto.Ingest;
using FintechGuard.Pii.Core;
using Microsoft.Extensions.DependencyInjection;

namespace FintechGuard.Pii.AzureDataExplorer;

/// <summary>
/// Extension methods to wrap an <see cref="IKustoIngestClient"/> with transparent PII masking.
/// </summary>
public static class KustoIngestClientExtensions
{
    /// <summary>
    /// Wraps the <see cref="IKustoIngestClient"/> so that every JSON stream or file
    /// ingested into Azure Data Explorer is automatically PII-masked using SecureRedact
    /// before the data leaves your service.
    /// </summary>
    /// <param name="inner">The real Kusto ingest client to wrap.</param>
    /// <param name="engine">The configured <see cref="IPiiEngine"/> singleton.</param>
    /// <param name="configure">Optional: configure <see cref="SecureAdxOptions"/>.</param>
    /// <returns>
    /// A <see cref="IKustoIngestClient"/> decorator that transparently masks PII.
    /// </returns>
    /// <example>
    /// <code>
    /// // In Program.cs — the only change your team ever needs to make:
    /// services.AddSingleton&lt;IKustoIngestClient&gt;(sp =>
    /// {
    ///     var kcsb = new KustoConnectionStringBuilder("https://mycluster.kusto.windows.net")
    ///         .WithAadApplicationKeyAuthentication(clientId, key, tenantId);
    ///     var rawClient = KustoIngestFactory.CreateQueuedIngestClient(kcsb);
    ///     var engine = sp.GetRequiredService&lt;IPiiEngine&gt;();
    ///     return rawClient.WithSecureRedact(engine); // Done!
    /// });
    /// </code>
    /// </example>
    public static IKustoIngestClient WithSecureRedact(
        this IKustoIngestClient inner,
        IPiiEngine engine,
        Action<SecureAdxOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(engine);

        var options = new SecureAdxOptions();
        configure?.Invoke(options);

        return new SecureKustoIngestClient(inner, engine, options);
    }

    /// <summary>
    /// Registers all SecureRedact ADX services in the DI container.
    /// Automatically wraps the provided <see cref="IKustoIngestClient"/> factory
    /// with the PII masking decorator.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddSecureRedactForAdx(
    ///     kustoFactory: sp => KustoIngestFactory.CreateQueuedIngestClient(kcsb),
    ///     piiMasterKey: "your-32-byte-master-key!",
    ///     configure: opts => opts.OnUnmaskedBlobIngestion = (uri, table) =>
    ///         logger.LogWarning("Unmasked blob ingested: {Uri} -> {Table}", uri, table));
    /// </code>
    /// </example>
    public static IServiceCollection AddSecureRedactForAdx(
        this IServiceCollection services,
        Func<IServiceProvider, IKustoIngestClient> kustoFactory,
        string piiMasterKey,
        Action<SecureAdxOptions>? configure = null)
    {
        // Register the PiiEngine singleton only if not already registered
        if (services.All(s => s.ServiceType != typeof(IPiiEngine)))
        {
            services.AddSingleton<IPiiEngine>(_ =>
                PiiEngineBuilder.Create()
                    .WithMasterKey(piiMasterKey)
                    .AddDefaultRecognizers()
                    .Build());
        }

        // Register the wrapped IKustoIngestClient
        services.AddSingleton<IKustoIngestClient>(sp =>
        {
            var rawClient = kustoFactory(sp);
            var engine = sp.GetRequiredService<IPiiEngine>();
            return rawClient.WithSecureRedact(engine, configure);
        });

        return services;
    }
}
