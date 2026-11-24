using System.Buffers;

namespace FintechGuard.Pii.Core;

/// <summary>
/// High-throughput pooled <see cref="IBufferWriter{T}"/> backed by <see cref="ArrayPool{T}.Shared"/>
/// to avoid per-payload MemoryStream and byte[] heap allocations.
/// </summary>
internal sealed class PooledByteBufferWriter : IBufferWriter<byte>, IDisposable
{
    private byte[] _buffer;
    private int _index;

    public PooledByteBufferWriter(int initialCapacity = 4096)
    {
        _buffer = ArrayPool<byte>.Shared.Rent(Math.Max(256, initialCapacity));
        _index = 0;
    }

    public ReadOnlyMemory<byte> WrittenMemory => _buffer.AsMemory(0, _index);
    public ReadOnlySpan<byte> WrittenSpan => _buffer.AsSpan(0, _index);
    public int WrittenCount => _index;

    public void Clear() => _index = 0;

    public void Advance(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (_index > _buffer.Length - count)
            throw new InvalidOperationException("Cannot advance past the end of the buffer.");
        _index += count;
    }

    public Memory<byte> GetMemory(int sizeHint = 0)
    {
        CheckAndResizeBuffer(sizeHint);
        return _buffer.AsMemory(_index);
    }

    public Span<byte> GetSpan(int sizeHint = 0)
    {
        CheckAndResizeBuffer(sizeHint);
        return _buffer.AsSpan(_index);
    }

    public byte[] DetachBufferCopy()
    {
        return _buffer.AsSpan(0, _index).ToArray();
    }

    private void CheckAndResizeBuffer(int sizeHint)
    {
        if (sizeHint < 0)
            throw new ArgumentOutOfRangeException(nameof(sizeHint));

        if (sizeHint == 0)
            sizeHint = 256;

        int available = _buffer.Length - _index;
        if (sizeHint <= available)
            return;

        int growBy = Math.Max(sizeHint, _buffer.Length);
        int newSize = checked(_buffer.Length + growBy);

        byte[] oldBuffer = _buffer;
        byte[] newBuffer = ArrayPool<byte>.Shared.Rent(newSize);
        Buffer.BlockCopy(oldBuffer, 0, newBuffer, 0, _index);
        _buffer = newBuffer;
        ArrayPool<byte>.Shared.Return(oldBuffer);
    }

    public void Dispose()
    {
        byte[] buffer = _buffer;
        if (buffer.Length > 0)
        {
            _buffer = Array.Empty<byte>();
            ArrayPool<byte>.Shared.Return(buffer);
        }
        _index = 0;
    }
}
