using System.Text;
using FintechGuard.Pii.Core;
using Microsoft.AspNetCore.Http;

namespace FintechGuard.Pii.AspNetCore;

/// <summary>
/// ASP.NET Core middleware that automatically scans and masks PII in HTTP request and response JSON bodies.
/// Operates transparently in the pipeline — downstream controllers receive masked data, upstream clients receive masked responses.
/// </summary>
public sealed class PiiMaskingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IPiiEngine _engine;
    private readonly PiiMaskingOptions _options;

    public PiiMaskingMiddleware(RequestDelegate next, IPiiEngine engine, PiiMaskingOptions options)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // 1. Check exclusions
        if (ShouldSkip(context))
        {
            await _next(context);
            return;
        }

        // 2. Process request body (mask or unmask inbound JSON)
        if (context.Request.Body != null && context.Request.ContentLength > 0 &&
            context.Request.ContentLength <= _options.MaxBodySizeBytes &&
            IsJsonContentType(context.Request.ContentType))
        {
            if (_options.MaskRequests || _options.UnmaskRequests)
            {
                context.Request.EnableBuffering();
                string originalBody = await ReadStreamAsync(context.Request.Body);
                context.Request.Body.Position = 0;

                if (!string.IsNullOrWhiteSpace(originalBody))
                {
                    string processedBody;
                    if (_options.UnmaskRequests)
                    {
                        processedBody = _engine.UnmaskJson(originalBody);
                    }
                    else
                    {
                        processedBody = _engine.MaskJson(originalBody);
                    }

                    var processedBytes = Encoding.UTF8.GetBytes(processedBody);
                    context.Request.Body = new MemoryStream(processedBytes);
                    context.Request.ContentLength = processedBytes.Length;
                }
            }
        }

        // 3. Process response body (mask outbound JSON)
        if (_options.MaskResponses)
        {
            var originalResponseStream = context.Response.Body;
            using var capturedResponseStream = new MemoryStream();
            context.Response.Body = capturedResponseStream;

            await _next(context);

            capturedResponseStream.Position = 0;

            if (IsJsonContentType(context.Response.ContentType) &&
                capturedResponseStream.Length > 0 &&
                capturedResponseStream.Length <= _options.MaxBodySizeBytes)
            {
                string responseBody = await ReadStreamAsync(capturedResponseStream);

                if (!string.IsNullOrWhiteSpace(responseBody))
                {
                    string maskedResponse = _engine.MaskJson(responseBody);
                    var maskedBytes = Encoding.UTF8.GetBytes(maskedResponse);

                    context.Response.ContentLength = maskedBytes.Length;
                    await originalResponseStream.WriteAsync(maskedBytes);
                }
                else
                {
                    capturedResponseStream.Position = 0;
                    await capturedResponseStream.CopyToAsync(originalResponseStream);
                }
            }
            else
            {
                capturedResponseStream.Position = 0;
                await capturedResponseStream.CopyToAsync(originalResponseStream);
            }

            context.Response.Body = originalResponseStream;
        }
        else
        {
            await _next(context);
        }
    }

    private bool ShouldSkip(HttpContext context)
    {
        // Skip excluded HTTP methods
        if (_options.ExcludeMethods.Contains(context.Request.Method))
            return true;

        // Skip excluded paths
        string path = context.Request.Path.Value ?? string.Empty;
        foreach (string excludedPath in _options.ExcludePaths)
        {
            if (path.StartsWith(excludedPath, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private bool IsJsonContentType(string? contentType)
    {
        if (string.IsNullOrEmpty(contentType))
            return false;

        foreach (var ct in _options.ProcessContentTypes)
        {
            if (contentType.Contains(ct, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static async Task<string> ReadStreamAsync(Stream stream)
    {
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        string content = await reader.ReadToEndAsync();
        stream.Position = 0;
        return content;
    }
}
