using System.Diagnostics;
using System.Threading.Channels;
using FintechGuard.Pii.Core;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;

namespace FintechGuard.Pii.Ner;

/// <summary>
/// Bounded Channel-based dynamic micro-batcher for CPU-only ONNX NER inference.
/// Coalesces concurrent requests up to MaxBatchSize or MaxBatchWaitMs to amortize
/// ONNX Runtime thread-pool and AVX2/AVX-512 matrix overhead across requests.
/// </summary>
internal sealed class OnnxMicroBatcher : IDisposable
{
    private sealed class BatchItem
    {
        public required string OriginalText { get; init; }
        public required long[] InputIds { get; init; }
        public required OnnxTokenWindowItem[] TokenInfos { get; init; }
        public required TaskCompletionSource<IReadOnlyList<PiiMatch>> Completion { get; init; }
    }

    private readonly InferenceSession _session;
    private readonly OnnxNerOptions _options;
    private readonly string _inputIdsName;
    private readonly string? _attentionMaskName;
    private readonly string? _tokenTypeIdsName;
    private readonly string _outputName;
    private readonly long _padTokenId;
    private readonly SemaphoreSlim? _inferenceGate;

    private readonly Channel<BatchItem> _channel;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task[] _workerTasks;
    private volatile bool _disposed;

    public OnnxMicroBatcher(
        InferenceSession session,
        OnnxNerOptions options,
        string inputIdsName,
        string? attentionMaskName,
        string? tokenTypeIdsName,
        string outputName,
        long padTokenId,
        SemaphoreSlim? inferenceGate = null)
    {
        _session = session;
        _options = options;
        _inputIdsName = inputIdsName;
        _attentionMaskName = attentionMaskName;
        _tokenTypeIdsName = tokenTypeIdsName;
        _outputName = outputName;
        _padTokenId = padTokenId;
        _inferenceGate = inferenceGate;

        int workerCount = Math.Max(1, options.BatchWorkerCount);

        _channel = Channel.CreateBounded<BatchItem>(new BoundedChannelOptions(Math.Max(16, options.MaxBatchQueueCapacity))
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = workerCount == 1,
            SingleWriter = false
        });

        _workerTasks = new Task[workerCount];
        for (int i = 0; i < workerCount; i++)
        {
            _workerTasks[i] = Task.Factory.StartNew(
                () => RunLoopAsync(_cts.Token),
                _cts.Token,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default).Unwrap();
        }
    }

    public IReadOnlyList<PiiMatch> InferWindow(string text, long[] inputIds, OnnxTokenWindowItem[] tokenInfos)
    {
        return InferWindowAsync(text, inputIds, tokenInfos, CancellationToken.None).GetAwaiter().GetResult();
    }

    public async Task<IReadOnlyList<PiiMatch>> InferWindowAsync(
        string text,
        long[] inputIds,
        OnnxTokenWindowItem[] tokenInfos,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var tcs = new TaskCompletionSource<IReadOnlyList<PiiMatch>>(TaskCreationOptions.RunContinuationsAsynchronously);
        var item = new BatchItem
        {
            OriginalText = text,
            InputIds = inputIds,
            TokenInfos = tokenInfos,
            Completion = tcs
        };

        await _channel.Writer.WriteAsync(item, cancellationToken).ConfigureAwait(false);
        return await tcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task RunLoopAsync(CancellationToken ct)
    {
        int maxBatch = Math.Max(1, _options.MaxBatchSize);
        int waitMs = Math.Max(1, _options.MaxBatchWaitMs);
        var batch = new List<BatchItem>(maxBatch);

        try
        {
            while (await _channel.Reader.WaitToReadAsync(ct).ConfigureAwait(false))
            {
                batch.Clear();

                if (!_channel.Reader.TryRead(out var first))
                    continue;

                batch.Add(first);

                if (maxBatch > 1)
                {
                    long deadlineTicks = Stopwatch.GetTimestamp() + (long)(waitMs * (Stopwatch.Frequency / 1000.0));
                    while (batch.Count < maxBatch)
                    {
                        if (_channel.Reader.TryRead(out var next))
                        {
                            batch.Add(next);
                            continue;
                        }

                        long remainingTicks = deadlineTicks - Stopwatch.GetTimestamp();
                        if (remainingTicks <= 0)
                            break;

                        int delayMs = Math.Max(1, (int)(remainingTicks * 1000 / Stopwatch.Frequency));
                        using var waitCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                        waitCts.CancelAfter(delayMs);
                        try
                        {
                            if (!await _channel.Reader.WaitToReadAsync(waitCts.Token).ConfigureAwait(false))
                                break;
                        }
                        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                        {
                            break;
                        }
                    }
                }

                ExecuteBatch(batch);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            foreach (var item in batch)
                item.Completion.TrySetException(ex);
        }
        finally
        {
            while (_channel.Reader.TryRead(out var leftover))
                leftover.Completion.TrySetCanceled();
        }
    }

    private void ExecuteBatch(List<BatchItem> batch)
    {
        int batchCount = batch.Count;
        int maxLen = 0;
        for (int b = 0; b < batchCount; b++)
        {
            if (batch[b].InputIds.Length > maxLen)
                maxLen = batch[b].InputIds.Length;
        }

        bool gateAcquired = false;
        try
        {
            var inputIdsFlat = new long[batchCount * maxLen];
            var attentionFlat = new long[batchCount * maxLen];
            if (_padTokenId != 0)
                Array.Fill(inputIdsFlat, _padTokenId);

            for (int b = 0; b < batchCount; b++)
            {
                var ids = batch[b].InputIds;
                int rowOffset = b * maxLen;
                Array.Copy(ids, 0, inputIdsFlat, rowOffset, ids.Length);
                Array.Fill(attentionFlat, 1L, rowOffset, ids.Length);
            }

            var dims = new[] { batchCount, maxLen };
            var inputs = new List<NamedOnnxValue>(3)
            {
                NamedOnnxValue.CreateFromTensor(_inputIdsName, new DenseTensor<long>(inputIdsFlat, dims))
            };

            if (_attentionMaskName != null)
            {
                inputs.Add(NamedOnnxValue.CreateFromTensor(_attentionMaskName, new DenseTensor<long>(attentionFlat, dims)));
            }

            if (_tokenTypeIdsName != null)
            {
                var typeIdsFlat = new long[batchCount * maxLen];
                inputs.Add(NamedOnnxValue.CreateFromTensor(_tokenTypeIdsName, new DenseTensor<long>(typeIdsFlat, dims)));
            }

            if (_inferenceGate != null)
            {
                _inferenceGate.Wait(_cts.Token);
                gateAcquired = true;
            }

            using var results = _session.Run(inputs);
            var logitsTensor = results.First(r => r.Name == _outputName).AsTensor<float>();

            for (int b = 0; b < batchCount; b++)
            {
                var item = batch[b];
                var decoded = BioEntityDecoder.DecodeWindow(
                    item.OriginalText,
                    logitsTensor,
                    b,
                    item.TokenInfos.AsSpan(),
                    _options);
                item.Completion.TrySetResult(decoded);
            }
        }
        catch (OperationCanceledException)
        {
            for (int b = 0; b < batchCount; b++)
                batch[b].Completion.TrySetCanceled();
        }
        catch (Exception ex)
        {
            for (int b = 0; b < batchCount; b++)
                batch[b].Completion.TrySetException(ex);
        }
        finally
        {
            if (gateAcquired) _inferenceGate!.Release();
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        _channel.Writer.TryComplete();
        _cts.Cancel();
        try
        {
            Task.WhenAll(_workerTasks).Wait(TimeSpan.FromSeconds(2));
        }
        catch
        {
        }
        _cts.Dispose();
    }
}
