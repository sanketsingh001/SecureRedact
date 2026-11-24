using FintechGuard.Pii.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace FintechGuard.Pii.AspNetCore;

/// <summary>
/// Extension methods for integrating FintechGuard.Pii into ASP.NET Core applications.
/// </summary>
public static class PiiMaskingExtensions
{
    /// <summary>
    /// Registers SecureRedact PII masking services with zero-config defaults (OneWayRedaction).
    /// </summary>
    public static IServiceCollection AddPiiMasking(this IServiceCollection services)
        => services.AddPiiMasking(_ => { });

    /// <summary>
    /// Registers SecureRedact PII masking services bound from an <see cref="IConfiguration"/> section (e.g. <c>"SecureRedact"</c>),
    /// with optional code overrides.
    /// </summary>
    public static IServiceCollection AddPiiMasking(
        this IServiceCollection services,
        IConfiguration configurationSection,
        Action<PiiMaskingOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(configurationSection);

        return services.AddPiiMasking(options =>
        {
            configurationSection.Bind(options);
            configure?.Invoke(options);
        });
    }

    /// <summary>
    /// Registers FintechGuard.Pii services in the DI container.
    /// </summary>
    public static IServiceCollection AddPiiMasking(this IServiceCollection services, Action<PiiMaskingOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);

        var options = new PiiMaskingOptions();
        configure(options);

        services.AddSingleton(options);
        services.AddSingleton<IPiiEngine>(_ => BuildEngine(options));

        return services;
    }

    /// <summary>
    /// Adds the PII masking middleware to the ASP.NET Core pipeline.
    /// Requires AddPiiMasking() to be called in ConfigureServices first.
    /// </summary>
    public static IApplicationBuilder UsePiiMasking(this IApplicationBuilder app)
    {
        var engine = app.ApplicationServices.GetRequiredService<IPiiEngine>();
        var options = app.ApplicationServices.GetRequiredService<PiiMaskingOptions>();

        return app.UseMiddleware<PiiMaskingMiddleware>(engine, options);
    }

    /// <summary>
    /// Adds PII masking middleware with inline configuration (no DI registration required).
    /// </summary>
    public static IApplicationBuilder UsePiiMasking(this IApplicationBuilder app, Action<PiiMaskingOptions> configure)
    {
        var options = new PiiMaskingOptions();
        configure(options);

        var engine = BuildEngine(options);
        return app.UseMiddleware<PiiMaskingMiddleware>(engine, options);
    }

    private static IPiiEngine BuildEngine(PiiMaskingOptions options)
    {
        var builder = PiiEngineBuilder.Create();
        bool hasKey = false;

        if (options.MasterKeyBytes != null && options.MasterKeyBytes.Length > 0)
        {
            builder.WithMasterKey(options.MasterKeyBytes);
            hasKey = true;
        }
        else if (!string.IsNullOrEmpty(options.MasterKey))
        {
            builder.WithMasterKey(options.MasterKey);
            hasKey = true;
        }

        if (options.UseIndianFintechRecognizers)
            builder.AddIndianFintechRecognizers();

        if (options.UseGlobalFintechRecognizers)
            builder.AddGlobalFintechRecognizers();

        MaskingStrategy effectiveStrategy = options.DefaultStrategy;
        if (!hasKey && (effectiveStrategy == MaskingStrategy.FormatPreservingReversible ||
                        effectiveStrategy == MaskingStrategy.ReversibleCryptoToken))
        {
            effectiveStrategy = MaskingStrategy.OneWayRedaction;
        }

        builder.SetDefaultStrategy(effectiveStrategy);
        options.ConfigureEngine?.Invoke(builder);

        return builder.Build();
    }
}
