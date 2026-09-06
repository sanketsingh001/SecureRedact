using FintechGuard.Pii.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace FintechGuard.Pii.AspNetCore;

/// <summary>
/// Extension methods for integrating FintechGuard.Pii into ASP.NET Core applications.
/// </summary>
public static class PiiMaskingExtensions
{
    /// <summary>
    /// Registers FintechGuard.Pii services in the DI container.
    /// Call this in your Program.cs / Startup.cs ConfigureServices.
    /// </summary>
    public static IServiceCollection AddPiiMasking(this IServiceCollection services, Action<PiiMaskingOptions> configure)
    {
        var options = new PiiMaskingOptions();
        configure(options);

        // Build the PiiEngine based on options
        var builder = PiiEngineBuilder.Create();

        if (options.MasterKeyBytes != null)
            builder.WithMasterKey(options.MasterKeyBytes);
        else if (!string.IsNullOrEmpty(options.MasterKey))
            builder.WithMasterKey(options.MasterKey);

        if (options.UseIndianFintechRecognizers)
            builder.AddIndianFintechRecognizers();

        if (options.UseGlobalFintechRecognizers)
            builder.AddGlobalFintechRecognizers();

        builder.SetDefaultStrategy(options.DefaultStrategy);

        // Allow consumer to add custom recognizers and overrides
        options.ConfigureEngine?.Invoke(builder);

        var engine = builder.Build();

        services.AddSingleton(options);
        services.AddSingleton<IPiiEngine>(engine);

        return services;
    }

    /// <summary>
    /// Adds the PII masking middleware to the ASP.NET Core pipeline.
    /// This automatically masks PII in request and response JSON bodies.
    ///
    /// Usage:
    ///   app.UsePiiMasking();
    ///
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
    ///
    /// Usage:
    ///   app.UsePiiMasking(options => {
    ///       options.MasterKey = "your-key";
    ///       options.ExcludePaths = ["/health", "/metrics"];
    ///   });
    /// </summary>
    public static IApplicationBuilder UsePiiMasking(this IApplicationBuilder app, Action<PiiMaskingOptions> configure)
    {
        var options = new PiiMaskingOptions();
        configure(options);

        var builder = PiiEngineBuilder.Create();

        if (options.MasterKeyBytes != null)
            builder.WithMasterKey(options.MasterKeyBytes);
        else if (!string.IsNullOrEmpty(options.MasterKey))
            builder.WithMasterKey(options.MasterKey);

        if (options.UseIndianFintechRecognizers)
            builder.AddIndianFintechRecognizers();

        if (options.UseGlobalFintechRecognizers)
            builder.AddGlobalFintechRecognizers();

        builder.SetDefaultStrategy(options.DefaultStrategy);
        options.ConfigureEngine?.Invoke(builder);

        var engine = builder.Build();

        return app.UseMiddleware<PiiMaskingMiddleware>(engine, options);
    }
}
