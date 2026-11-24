using System.Net;
using System.Net.Http.Headers;
using System.Text;
using FintechGuard.Pii.AspNetCore;
using FintechGuard.Pii.Core;
using FintechGuard.Pii.Recognizers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace FintechGuard.Pii.Tests;

public class AspNetCoreMiddlewareTests
{
    private static IHost CreateTestHost(Action<PiiMaskingOptions> configureOptions, Action<IApplicationBuilder> configureRoutes)
    {
        return new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddPiiMasking(configureOptions);
                });
                webBuilder.Configure(app =>
                {
                    app.UsePiiMasking();
                    configureRoutes(app);
                });
            })
            .Start();
    }

    [Fact]
    public async Task ChunkedRequestWithoutContentLength_AndJsonResponse_AreBothMasked()
    {
        string? controllerReceivedBody = null;

        using var host = CreateTestHost(
            opts =>
            {
                opts.MasterKey = "aspnet-middleware-test-key-256!!";
                opts.MaskRequests = true;
                opts.MaskResponses = true;
            },
            app => app.Run(async ctx =>
            {
                using var reader = new StreamReader(ctx.Request.Body, Encoding.UTF8);
                controllerReceivedBody = await reader.ReadToEndAsync();
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync("""{"pan":"ABCPE1234F"}""");
            }));

        var client = host.GetTestClient();
        var streamContent = new StreamContent(new MemoryStream(Encoding.UTF8.GetBytes("""{"card":"4532-0151-1283-0366"}""")));
        streamContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        // Force null ContentLength (simulates chunked / HTTP/2 streaming)
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/pay") { Content = streamContent };
        request.Headers.TransferEncodingChunked = true;
        streamContent.Headers.ContentLength = null;

        var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        Assert.NotNull(controllerReceivedBody);
        Assert.DoesNotContain("4532-0151-1283-0366", controllerReceivedBody);
        Assert.Contains("4532-****-****-0366#fp[", controllerReceivedBody);

        string responseBody = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("ABCPE1234F", responseBody);
        Assert.Contains("AB****234F#fp[", responseBody);
    }

    [Fact]
    public async Task OversizedRequestAndResponse_Return413FailClosed()
    {
        using var host = CreateTestHost(
            opts =>
            {
                opts.MasterKey = "aspnet-middleware-test-key-256!!";
                opts.MaxBodySizeBytes = 64;
                opts.OversizedBehavior = OversizedPayloadBehavior.RejectWith413;
            },
            app => app.Run(async ctx =>
            {
                if (ctx.Request.Path == "/big-response")
                {
                    ctx.Response.ContentType = "application/json";
                    await ctx.Response.WriteAsync("""{"card":"4532-0151-1283-0366","padding":"0123456789012345678901234567890123456789"}""");
                    return;
                }

                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync("""{"ok":true}""");
            }));

        var client = host.GetTestClient();

        // 1. Oversized request
        var bigReq = new StringContent(
            """{"card":"4532-0151-1283-0366","extra":"0123456789012345678901234567890123456789"}""",
            Encoding.UTF8,
            "application/json");
        var reqResp = await client.PostAsync("/api/pay", bigReq);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, reqResp.StatusCode);

        // 2. Oversized response
        var resResp = await client.GetAsync("/big-response");
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resResp.StatusCode);
        string body = await resResp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("4532-0151-1283-0366", body);
    }

    [Fact]
    public async Task NonJsonAndBinaryResponses_PassThroughWithoutBuffering_AndExceptionsRestoreStream()
    {
        bool streamRestoredAfterThrow = false;

        using var host = CreateTestHost(
            opts =>
            {
                opts.MasterKey = null; // Must gracefully fall back to OneWayRedaction!
                opts.MaxBodySizeBytes = 32;
            },
            app =>
            {
                app.Use(async (ctx, next) =>
                {
                    var outerBody = ctx.Response.Body;
                    try
                    {
                        await next();
                    }
                    catch (InvalidOperationException)
                    {
                        streamRestoredAfterThrow = ReferenceEquals(ctx.Response.Body, outerBody) && ctx.Response.Body.CanWrite;
                        ctx.Response.StatusCode = 500;
                        await ctx.Response.WriteAsync("handled");
                    }
                });

                app.Run(async ctx =>
                {
                    if (ctx.Request.Path == "/binary")
                    {
                        ctx.Response.ContentType = "application/octet-stream";
                        byte[] payload = new byte[128];
                        Array.Fill(payload, (byte)0x5A);
                        await ctx.Response.Body.WriteAsync(payload);
                        return;
                    }

                    if (ctx.Request.Path == "/boom")
                    {
                        throw new InvalidOperationException("downstream failure");
                    }

                    ctx.Response.ContentType = "application/json";
                    await ctx.Response.WriteAsync("""{"pan":"ABCPE1234F"}""");
                });
            });

        var client = host.GetTestClient();

        // 1. Binary > MaxBodySizeBytes passes through untouched
        var binResp = await client.GetAsync("/binary");
        Assert.Equal(HttpStatusCode.OK, binResp.StatusCode);
        Assert.Equal(128, (await binResp.Content.ReadAsByteArrayAsync()).Length);

        // 2. Exception restores original Response.Body cleanly
        var errResp = await client.GetAsync("/boom");
        Assert.Equal(HttpStatusCode.InternalServerError, errResp.StatusCode);
        Assert.True(streamRestoredAfterThrow);

        // 3. Null MasterKey falls back to OneWayRedaction without throwing
        var jsonResp = await client.GetAsync("/ok");
        Assert.Equal(HttpStatusCode.OK, jsonResp.StatusCode);
        string text = await jsonResp.Content.ReadAsStringAsync();
        Assert.Equal("""{"pan":"AB****234F"}""", text);
    }

    [Fact]
    public async Task CpuConcurrencyBulkhead_RejectsExcessConcurrentMaskingWith503()
    {
        using var enteredGate = new ManualResetEventSlim(false);
        using var releaseGate = new ManualResetEventSlim(false);

        using var host = CreateTestHost(
            opts =>
            {
                opts.MasterKey = "aspnet-middleware-test-key-256!!";
                opts.MaxConcurrentRequests = 1;
                opts.ConcurrencyAcquireTimeoutMs = 40;
                opts.ConcurrencyExceededBehavior = ConcurrencyLimitBehavior.RejectWith503;
                opts.MaskResponses = false;
                opts.ConfigureEngine = b => b.AddRecognizer(new BlockingGateRecognizer(enteredGate, releaseGate));
            },
            app => app.Run(async ctx =>
            {
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync("""{"ok":true}""");
            }));

        var client = host.GetTestClient();

        var firstTask = Task.Run(() => client.PostAsync(
            "/api/pay",
            new StringContent("""{"pan":"ABCPE1234F"}""", Encoding.UTF8, "application/json")));

        Assert.True(enteredGate.Wait(TimeSpan.FromSeconds(5)));

        var secondResp = await client.PostAsync(
            "/api/pay",
            new StringContent("""{"pan":"ABCPE1234F"}""", Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, secondResp.StatusCode);
        Assert.True(secondResp.Headers.TryGetValues("Retry-After", out var retryValues));
        Assert.Contains("1", retryValues);

        releaseGate.Set();
        var firstResp = await firstTask;
        Assert.Equal(HttpStatusCode.OK, firstResp.StatusCode);
    }

    [Fact]
    public async Task AddPiiMasking_BindsFromIConfigurationSection_AndMasksRequests()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SecureRedact:MasterKey"] = "config-bound-secret-key-256bits!!",
                ["SecureRedact:MaxCpuPercent"] = "25",
                ["SecureRedact:ExcludePaths:0"] = "/health"
            })
            .Build();

        using var host = new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services.AddPiiMasking(config.GetSection("SecureRedact"));
                });
                webBuilder.Configure(app =>
                {
                    app.UsePiiMasking();
                    app.Run(async ctx =>
                    {
                        using var reader = new StreamReader(ctx.Request.Body, Encoding.UTF8);
                        string body = await reader.ReadToEndAsync();
                        ctx.Response.ContentType = "application/json";
                        await ctx.Response.WriteAsync(body);
                    });
                });
            })
            .Start();

        var client = host.GetTestClient();
        var resp = await client.PostAsync(
            "/api/tx",
            new StringContent("""{"pan":"ABCPE1234F"}""", Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string reply = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("ABCPE1234F", reply);
        Assert.Contains("AB****234F#fp[", reply);

        // Health endpoint excluded via config passes through unmasked
        var healthResp = await client.PostAsync(
            "/health",
            new StringContent("""{"pan":"ABCPE1234F"}""", Encoding.UTF8, "application/json"));
        Assert.Contains("ABCPE1234F", await healthResp.Content.ReadAsStringAsync());
    }

    private sealed class BlockingGateRecognizer : IPiiRecognizer
    {
        private readonly ManualResetEventSlim _entered;
        private readonly ManualResetEventSlim _release;

        public BlockingGateRecognizer(ManualResetEventSlim entered, ManualResetEventSlim release)
        {
            _entered = entered;
            _release = release;
        }

        public string Name => "BlockingGate";
        public PiiType PiiType => PiiType.Custom;

        public IEnumerable<PiiMatch> Recognize(string text)
        {
            _entered.Set();
            _release.Wait(TimeSpan.FromSeconds(5));
            return Array.Empty<PiiMatch>();
        }

        public IEnumerable<PiiMatch> Recognize(string text, RecognitionContext context) => Recognize(text);
    }
}
