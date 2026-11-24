using System.Buffers;
using System.Text;
using FintechGuard.Pii.Core;
using Microsoft.AspNetCore.Http;

namespace FintechGuard.Pii.AspNetCore;

/// <summary>
/// High-throughput ASP.NET Core middleware that masks PII in JSON request/response bodies using pooled UTF-8 buffers,
/// handles chunked/HTTP2 requests without ContentLength, skips binary/SSE response buffering, and enforces fail-closed limits.
/// </summary>
public sealed class PiiMaskingMiddleware : IDisposable
{
    private static readonly byte[] PayloadTooLargeBody =
        Encoding.UTF8.GetBytes(@"{""error"":""Payload exceeds maximum allowed size for PII inspection.""}");

    private static readonly byte[] ServiceUnavailableBody =
        Encoding.UTF8.GetBytes(@"{""error"":""PII inspection CPU capacity limit reached. Please retry shortly.""}");

    private readonly RequestDelegate _next;
    private readonly IPiiEngine _engine;
    private readonly PiiMaskingOptions _options;
    private readonly SemaphoreSlim? _concurrencyGate;

    public PiiMaskingMiddleware(RequestDelegate next, IPiiEngine engine, PiiMaskingOptions options)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _options = options ?? throw new ArgumentNullException(nameof(options));

        int limit = _options.MaxConcurrentRequests > 0
            ? _options.MaxConcurrentRequests
            : (_options.MaxCpuPercent > 0
                ? PiiEngineOptions.CalculateConcurrencyForCpuPercent(_options.MaxCpuPercent)
                : 0);

        if (limit > 0)
            _concurrencyGate = new SemaphoreSlim(limit, limit);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (ShouldSkip(context))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // 1. Inbound request body (handles ContentLength AND chunked/HTTP2 streams where ContentLength == null)
        if ((_options.MaskRequests || _options.UnmaskRequests) &&
            IsJsonContentType(context.Request.ContentType))
        {
            long? contentLength = context.Request.ContentLength;
            if (contentLength.HasValue && contentLength.Value > _options.MaxBodySizeBytes)
            {
                if (_options.OversizedBehavior == OversizedPayloadBehavior.RejectWith413)
                {
                    await Write413Async(context).ConfigureAwait(false);
                    return;
                }
            }
            else if (!contentLength.HasValue || contentLength.Value > 0)
            {
                if (_options.OversizedBehavior == OversizedPayloadBehavior.PassThrough)
                    context.Request.EnableBuffering();

                using var inputBuffer = new PooledByteBufferWriter(4096);
                bool exceededLimit = await ReadBodyUpToLimitAsync(
                    context.Request.Body,
                    inputBuffer,
                    _options.MaxBodySizeBytes,
                    context.RequestAborted).ConfigureAwait(false);

                if (exceededLimit)
                {
                    if (_options.OversizedBehavior == OversizedPayloadBehavior.RejectWith413)
                    {
                        await Write413Async(context).ConfigureAwait(false);
                        return;
                    }

                    if (context.Request.Body.CanSeek)
                        context.Request.Body.Position = 0;
                }
                else if (inputBuffer.WrittenCount > 0)
                {
                    bool inSlotAcquired = false;
                    byte[] replacementBytes;
                    try
                    {
                        inSlotAcquired = await TryEnterCpuSlotAsync(context.RequestAborted).ConfigureAwait(false);
                        replacementBytes = TransformBufferedRequest(inputBuffer, _options.UnmaskRequests);
                    }
                    catch (TimeoutException)
                    {
                        await Write503Async(context, context.Response.Body).ConfigureAwait(false);
                        return;
                    }
                    finally
                    {
                        if (inSlotAcquired) _concurrencyGate!.Release();
                    }

                    var replacementStream = new MemoryStream(replacementBytes, writable: false);
                    context.Response.RegisterForDispose(replacementStream);
                    context.Request.Body = replacementStream;
                    context.Request.ContentLength = replacementBytes.Length;
                }
                else if (context.Request.Body.CanSeek)
                {
                    context.Request.Body.Position = 0;
                }
            }
        }

        // 2. Outbound response body (selective buffering only when Content-Type matches configured JSON types)
        if (!_options.MaskResponses)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        Stream originalResponseStream = context.Response.Body;
        using var bufferingStream = new SelectiveResponseBufferingStream(
            originalResponseStream,
            context,
            this);

        context.Response.Body = bufferingStream;
        try
        {
            await _next(context).ConfigureAwait(false);

            if (bufferingStream.OversizedRejected)
            {
                if (!context.Response.HasStarted)
                {
                    context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
                    context.Response.ContentType = "application/json";
                    context.Response.ContentLength = PayloadTooLargeBody.Length;
                    await originalResponseStream.WriteAsync(PayloadTooLargeBody, context.RequestAborted).ConfigureAwait(false);
                }
            }
            else if (bufferingStream.HasBufferedJson)
            {
                bool outSlotAcquired = false;
                using var maskedResponse = new PooledByteBufferWriter(bufferingStream.BufferedLength + 256);
                try
                {
                    outSlotAcquired = await TryEnterCpuSlotAsync(context.RequestAborted).ConfigureAwait(false);
                    MaskBufferedResponse(bufferingStream, maskedResponse);
                }
                catch (TimeoutException)
                {
                    await Write503Async(context, originalResponseStream).ConfigureAwait(false);
                    return;
                }
                finally
                {
                    if (outSlotAcquired) _concurrencyGate!.Release();
                }

                if (!context.Response.HasStarted)
                    context.Response.ContentLength = maskedResponse.WrittenCount;

                await originalResponseStream.WriteAsync(maskedResponse.WrittenMemory, context.RequestAborted).ConfigureAwait(false);
            }
        }
        finally
        {
            context.Response.Body = originalResponseStream;
        }
    }

    private bool ShouldSkip(HttpContext context)
    {
        if (_options.ExcludeMethods.Contains(context.Request.Method))
            return true;

        string path = context.Request.Path.Value ?? string.Empty;
        foreach (string excludedPath in _options.ExcludePaths)
        {
            if (path.StartsWith(excludedPath, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    internal bool IsJsonContentType(string? contentType)
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

    private byte[] TransformBufferedRequest(PooledByteBufferWriter inputBuffer, bool unmask)
    {
        using var maskedBuffer = new PooledByteBufferWriter(inputBuffer.WrittenCount + 256);
        if (unmask)
            _engine.UnmaskJsonUtf8(inputBuffer.WrittenSpan, maskedBuffer);
        else
            _engine.MaskJsonUtf8(inputBuffer.WrittenSpan, maskedBuffer);

        return maskedBuffer.DetachBufferCopy();
    }

    private void MaskBufferedResponse(SelectiveResponseBufferingStream bufferingStream, PooledByteBufferWriter maskedResponse)
    {
        _engine.MaskJsonUtf8(bufferingStream.BufferedSpan, maskedResponse);
    }

    private async Task<bool> TryEnterCpuSlotAsync(CancellationToken ct)
    {
        if (_concurrencyGate == null)
            return false;

        if (_options.ConcurrencyExceededBehavior == ConcurrencyLimitBehavior.Wait)
        {
            await _concurrencyGate.WaitAsync(ct).ConfigureAwait(false);
            return true;
        }

        int timeoutMs = Math.Max(0, _options.ConcurrencyAcquireTimeoutMs);
        if (!await _concurrencyGate.WaitAsync(timeoutMs, ct).ConfigureAwait(false))
            throw new TimeoutException("CPU concurrency bulkhead limit reached.");

        return true;
    }

    private static async Task Write413Async(HttpContext context)
    {
        if (!context.Response.HasStarted)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            context.Response.ContentType = "application/json";
            context.Response.ContentLength = PayloadTooLargeBody.Length;
            await context.Response.Body.WriteAsync(PayloadTooLargeBody, context.RequestAborted).ConfigureAwait(false);
        }
    }

    private static async Task Write503Async(HttpContext context, Stream targetStream)
    {
        if (!context.Response.HasStarted)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            context.Response.Headers["Retry-After"] = "1";
            context.Response.ContentType = "application/json";
            context.Response.ContentLength = ServiceUnavailableBody.Length;
            await targetStream.WriteAsync(ServiceUnavailableBody, context.RequestAborted).ConfigureAwait(false);
        }
    }

    public void Dispose()
    {
        _concurrencyGate?.Dispose();
    }

    private static async Task<bool> ReadBodyUpToLimitAsync(
        Stream body,
        PooledByteBufferWriter destination,
        long maxBytes,
        CancellationToken ct)
    {
        byte[] chunk = ArrayPool<byte>.Shared.Rent(16384);
        long total = 0;
        try
        {
            while (true)
            {
                int read = await body.ReadAsync(chunk.AsMemory(), ct).ConfigureAwait(false);
                if (read <= 0)
                    return false;

                total += read;
                if (total > maxBytes)
                    return true;

                CopyChunkToWriter(chunk, read, destination);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(chunk);
        }
    }

    private static void CopyChunkToWriter(byte[] chunk, int count, PooledByteBufferWriter destination)
    {
        Span<byte> dst = destination.GetSpan(count);
        chunk.AsSpan(0, count).CopyTo(dst);
        destination.Advance(count);
    }

    private sealed class SelectiveResponseBufferingStream : Stream
    {
        private readonly Stream _inner;
        private readonly HttpContext _context;
        private readonly PiiMaskingMiddleware _middleware;
        private PooledByteBufferWriter? _buffer;
        private bool _modeDecided;
        private bool _passthrough;

        public bool OversizedRejected { get; private set; }
        public bool HasBufferedJson => !_passthrough && !OversizedRejected && _buffer != null && _buffer.WrittenCount > 0;
        public int BufferedLength => _buffer?.WrittenCount ?? 0;
        public ReadOnlySpan<byte> BufferedSpan => _buffer != null ? _buffer.WrittenSpan : ReadOnlySpan<byte>.Empty;

        public SelectiveResponseBufferingStream(Stream inner, HttpContext context, PiiMaskingMiddleware middleware)
        {
            _inner = inner;
            _context = context;
            _middleware = middleware;
        }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => _buffer?.WrittenCount ?? 0;
        public override long Position
        {
            get => _buffer?.WrittenCount ?? 0;
            set => throw new NotSupportedException();
        }

        private bool EnsureModeAndCheckPassthrough()
        {
            if (!_modeDecided)
            {
                _modeDecided = true;
                if (!_middleware.IsJsonContentType(_context.Response.ContentType))
                {
                    _passthrough = true;
                }
                else
                {
                    _buffer = new PooledByteBufferWriter(4096);
                }
            }
            return _passthrough;
        }

        public override void Write(byte[] buffer, int offset, int count) =>
            Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (OversizedRejected || buffer.IsEmpty)
                return;

            if (EnsureModeAndCheckPassthrough())
            {
                _inner.Write(buffer);
                return;
            }

            long nextSize = (long)_buffer!.WrittenCount + buffer.Length;
            if (nextSize > _middleware._options.MaxBodySizeBytes)
            {
                if (_middleware._options.OversizedBehavior == OversizedPayloadBehavior.RejectWith413)
                {
                    OversizedRejected = true;
                    _buffer.Dispose();
                    _buffer = null;
                    return;
                }

                _passthrough = true;
                if (_buffer.WrittenCount > 0)
                    _inner.Write(_buffer.WrittenSpan);
                _buffer.Dispose();
                _buffer = null;
                _inner.Write(buffer);
                return;
            }

            Span<byte> dst = _buffer.GetSpan(buffer.Length);
            buffer.CopyTo(dst);
            _buffer.Advance(buffer.Length);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (OversizedRejected || buffer.IsEmpty)
                return;

            if (EnsureModeAndCheckPassthrough())
            {
                await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
                return;
            }

            long nextSize = (long)_buffer!.WrittenCount + buffer.Length;
            if (nextSize > _middleware._options.MaxBodySizeBytes)
            {
                if (_middleware._options.OversizedBehavior == OversizedPayloadBehavior.RejectWith413)
                {
                    OversizedRejected = true;
                    _buffer.Dispose();
                    _buffer = null;
                    return;
                }

                _passthrough = true;
                if (_buffer.WrittenCount > 0)
                    await _inner.WriteAsync(_buffer.WrittenMemory, cancellationToken).ConfigureAwait(false);
                _buffer.Dispose();
                _buffer = null;
                await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
                return;
            }

            AppendToBuffer(buffer.Span);
        }

        private void AppendToBuffer(ReadOnlySpan<byte> span)
        {
            Span<byte> dst = _buffer!.GetSpan(span.Length);
            span.CopyTo(dst);
            _buffer.Advance(span.Length);
        }

        public override void Flush()
        {
            if (_passthrough) _inner.Flush();
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            return _passthrough ? _inner.FlushAsync(cancellationToken) : Task.CompletedTask;
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _buffer?.Dispose();
                _buffer = null;
            }
            base.Dispose(disposing);
        }
    }
}
