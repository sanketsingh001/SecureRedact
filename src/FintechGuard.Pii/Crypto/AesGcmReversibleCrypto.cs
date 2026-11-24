using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace FintechGuard.Pii.Crypto;

/// <summary>
/// Implements high-throughput authenticated encryption using AES-256-GCM with zero-downtime key rotation
/// via versioned key-ID headers ([0x02][kidLen][kid][nonce:12][tag:16][ciphertext]) and thread-local AesGcm instances.
/// </summary>
public sealed class AesGcmReversibleCrypto : IReversibleCrypto, IDisposable
{
    private const byte WireVersion2 = 0x02;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int StackPlaintextThreshold = 512;
    private const int StackTokenCharThreshold = 1024;
    private static readonly byte[] Pbkdf2Salt = "SecureRedact.AES256GCM.v2"u8.ToArray();
    private static readonly byte[] HmacHkdfInfo = "SecureRedact.HMAC.v1"u8.ToArray();

    private readonly KeyEntry _activeKey;
    private readonly KeyEntry[] _keyRing;
    private readonly byte[] _derivedHashKey;
    private readonly ThreadLocal<Dictionary<string, AesGcm>> _threadLocalAes;
    private volatile bool _disposed;

    private sealed class KeyEntry
    {
        public string KeyId { get; }
        public byte[] KeyIdBytes { get; }
        public byte[] KeyBytes { get; }

        public KeyEntry(string keyId, byte[] keyBytes)
        {
            KeyId = keyId;
            KeyIdBytes = Encoding.UTF8.GetBytes(keyId);
            KeyBytes = (byte[])keyBytes.Clone();
        }
    }

    public AesGcmReversibleCrypto(byte[] key)
        : this("k1", new Dictionary<string, byte[]>(StringComparer.Ordinal) { ["k1"] = key ?? throw new ArgumentNullException(nameof(key)) })
    {
    }

    public AesGcmReversibleCrypto(string activeKeyId, IReadOnlyDictionary<string, byte[]> keyRing)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(activeKeyId);
        ArgumentNullException.ThrowIfNull(keyRing);

        if (keyRing.Count == 0)
            throw new ArgumentException("Key ring must contain at least one key.", nameof(keyRing));

        var entries = new KeyEntry[keyRing.Count];
        KeyEntry? active = null;
        int idx = 0;

        foreach (var kvp in keyRing)
        {
            if (string.IsNullOrWhiteSpace(kvp.Key))
                throw new ArgumentException("Key IDs in key ring cannot be empty.", nameof(keyRing));

            int kidByteCount = Encoding.UTF8.GetByteCount(kvp.Key);
            if (kidByteCount == 0 || kidByteCount > 64)
                throw new ArgumentException($"Key ID '{kvp.Key}' UTF-8 byte length must be between 1 and 64 bytes.", nameof(keyRing));

            byte[] rawKey = kvp.Value;
            if (rawKey == null || (rawKey.Length != 16 && rawKey.Length != 24 && rawKey.Length != 32))
                throw new ArgumentException($"AES-GCM key '{kvp.Key}' must be 16, 24, or 32 bytes (128, 192, or 256 bits).", nameof(keyRing));

            var entry = new KeyEntry(kvp.Key, rawKey);
            entries[idx++] = entry;

            if (string.Equals(kvp.Key, activeKeyId, StringComparison.Ordinal))
                active = entry;
        }

        _activeKey = active ?? throw new ArgumentException($"Active key ID '{activeKeyId}' was not found in the key ring.", nameof(activeKeyId));
        _keyRing = entries;
        _derivedHashKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, _activeKey.KeyBytes, 32, salt: null, info: HmacHkdfInfo);
        _threadLocalAes = new ThreadLocal<Dictionary<string, AesGcm>>(
            static () => new Dictionary<string, AesGcm>(StringComparer.Ordinal),
            trackAllValues: true);
    }

    /// <summary>
    /// Derives a 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256 (100,000 iterations).
    /// </summary>
    public static AesGcmReversibleCrypto FromPassphrase(string passphrase, string keyId = "k1")
    {
        if (string.IsNullOrEmpty(passphrase))
            throw new ArgumentException("Passphrase cannot be empty.", nameof(passphrase));

        byte[] keyBytes = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(passphrase),
            Pbkdf2Salt,
            100_000,
            HashAlgorithmName.SHA256,
            32);

        try
        {
            return new AesGcmReversibleCrypto(keyId, new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                [keyId] = keyBytes
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }

    public string Encrypt(string plaintext, string? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ObjectDisposedException.ThrowIf(_disposed, this);

        int maxPlainBytes = Encoding.UTF8.GetMaxByteCount(plaintext.Length);
        int headerLen = 2 + _activeKey.KeyIdBytes.Length;

        byte[]? rentedPlain = null;
        byte[]? rentedCombined = null;
        byte[]? rentedAad = null;

        try
        {
            Span<byte> plainBuf = maxPlainBytes <= StackPlaintextThreshold
                ? stackalloc byte[StackPlaintextThreshold]
                : (rentedPlain = ArrayPool<byte>.Shared.Rent(maxPlainBytes));

            int plainLen = Encoding.UTF8.GetBytes(plaintext.AsSpan(), plainBuf);
            ReadOnlySpan<byte> plainSpan = plainBuf[..plainLen];

            int combinedLen = headerLen + NonceSize + TagSize + plainLen;
            Span<byte> combinedBuf = combinedLen <= StackPlaintextThreshold + 128
                ? stackalloc byte[StackPlaintextThreshold + 128]
                : (rentedCombined = ArrayPool<byte>.Shared.Rent(combinedLen));

            Span<byte> combined = combinedBuf[..combinedLen];
            combined[0] = WireVersion2;
            combined[1] = (byte)_activeKey.KeyIdBytes.Length;
            _activeKey.KeyIdBytes.CopyTo(combined.Slice(2, _activeKey.KeyIdBytes.Length));

            Span<byte> nonce = combined.Slice(headerLen, NonceSize);
            Span<byte> tag = combined.Slice(headerLen + NonceSize, TagSize);
            Span<byte> cipher = combined.Slice(headerLen + NonceSize + TagSize, plainLen);

            RandomNumberGenerator.Fill(nonce);

            int maxAad = associatedData != null ? Encoding.UTF8.GetMaxByteCount(associatedData.Length) : 0;
            Span<byte> aadBuf = maxAad > 0
                ? (maxAad <= 128 ? stackalloc byte[128] : (rentedAad = ArrayPool<byte>.Shared.Rent(maxAad)))
                : Span<byte>.Empty;
            int aadLen = associatedData != null ? Encoding.UTF8.GetBytes(associatedData.AsSpan(), aadBuf) : 0;
            ReadOnlySpan<byte> aadSpan = aadBuf[..aadLen];

            GetAesGcm(_activeKey).Encrypt(nonce, plainSpan, cipher, tag, aadSpan);

            return Base64UrlEncode(combined);
        }
        finally
        {
            if (rentedPlain != null) ArrayPool<byte>.Shared.Return(rentedPlain, clearArray: true);
            if (rentedCombined != null) ArrayPool<byte>.Shared.Return(rentedCombined);
            if (rentedAad != null) ArrayPool<byte>.Shared.Return(rentedAad);
        }
    }

    public string Decrypt(string cipherToken, string? associatedData = null)
    {
        if (!TryDecrypt(cipherToken, out string? plaintext, associatedData))
        {
            throw new CryptographicException("Failed to decrypt or authenticate token. Key mismatch or tampered payload.");
        }

        return plaintext!;
    }

    public bool TryDecrypt(string cipherToken, out string? plaintext, string? associatedData = null)
    {
        plaintext = null;
        if (_disposed || string.IsNullOrWhiteSpace(cipherToken))
            return false;

        int maxDecodedLen = ((cipherToken.Length + 3) / 4) * 3;
        byte[]? rentedDecoded = null;
        byte[]? rentedPlain = null;
        byte[]? rentedAad = null;

        try
        {
            Span<byte> decodedBuf = maxDecodedLen <= StackPlaintextThreshold + 128
                ? stackalloc byte[StackPlaintextThreshold + 128]
                : (rentedDecoded = ArrayPool<byte>.Shared.Rent(maxDecodedLen));

            if (!TryBase64UrlDecode(cipherToken.AsSpan(), decodedBuf, out int decodedLen))
                return false;

            if (decodedLen < NonceSize + TagSize)
                return false;

            ReadOnlySpan<byte> combined = decodedBuf[..decodedLen];

            int maxAad = associatedData != null ? Encoding.UTF8.GetMaxByteCount(associatedData.Length) : 0;
            Span<byte> aadBuf = maxAad > 0
                ? (maxAad <= 128 ? stackalloc byte[128] : (rentedAad = ArrayPool<byte>.Shared.Rent(maxAad)))
                : Span<byte>.Empty;
            int aadLen = associatedData != null ? Encoding.UTF8.GetBytes(associatedData.AsSpan(), aadBuf) : 0;
            ReadOnlySpan<byte> aadSpan = aadBuf[..aadLen];

            // 1. Try v2 versioned wire format: [0x02][kidLen][kid][nonce:12][tag:16][ciphertext]
            if (decodedLen >= 30 && combined[0] == WireVersion2)
            {
                int kidLen = combined[1];
                int v2HeaderLen = 2 + kidLen;
                if (kidLen > 0 && kidLen <= 64 && v2HeaderLen + NonceSize + TagSize <= decodedLen)
                {
                    ReadOnlySpan<byte> kidSpan = combined.Slice(2, kidLen);
                    KeyEntry? matchedKey = FindKeyByUtf8Id(kidSpan);
                    if (matchedKey != null)
                    {
                        ReadOnlySpan<byte> nonce = combined.Slice(v2HeaderLen, NonceSize);
                        ReadOnlySpan<byte> tag = combined.Slice(v2HeaderLen + NonceSize, TagSize);
                        ReadOnlySpan<byte> cipher = combined.Slice(v2HeaderLen + NonceSize + TagSize);

                        Span<byte> plainBuf = cipher.Length <= StackPlaintextThreshold
                            ? stackalloc byte[StackPlaintextThreshold]
                            : (rentedPlain = ArrayPool<byte>.Shared.Rent(cipher.Length));

                        if (TryDecryptWithEntry(matchedKey, nonce, cipher, tag, plainBuf[..cipher.Length], aadSpan, out plaintext))
                            return true;
                    }
                }
            }

            // 2. Fallback to legacy v1 wire format: [nonce:12][tag:16][ciphertext]
            {
                ReadOnlySpan<byte> nonce = combined.Slice(0, NonceSize);
                ReadOnlySpan<byte> tag = combined.Slice(NonceSize, TagSize);
                ReadOnlySpan<byte> cipher = combined.Slice(NonceSize + TagSize);

                Span<byte> plainBuf = cipher.Length <= StackPlaintextThreshold
                    ? stackalloc byte[StackPlaintextThreshold]
                    : (rentedPlain ??= ArrayPool<byte>.Shared.Rent(cipher.Length));

                if (TryDecryptWithEntry(_activeKey, nonce, cipher, tag, plainBuf[..cipher.Length], aadSpan, out plaintext))
                    return true;

                for (int i = 0; i < _keyRing.Length; i++)
                {
                    var entry = _keyRing[i];
                    if (ReferenceEquals(entry, _activeKey))
                        continue;

                    if (TryDecryptWithEntry(entry, nonce, cipher, tag, plainBuf[..cipher.Length], aadSpan, out plaintext))
                        return true;
                }
            }

            return false;
        }
        finally
        {
            if (rentedDecoded != null) ArrayPool<byte>.Shared.Return(rentedDecoded);
            if (rentedPlain != null) ArrayPool<byte>.Shared.Return(rentedPlain, clearArray: true);
            if (rentedAad != null) ArrayPool<byte>.Shared.Return(rentedAad);
        }
    }

    internal ReadOnlySpan<byte> DerivedHashKey => _derivedHashKey;

    private bool TryDecryptWithEntry(
        KeyEntry entry,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> cipher,
        ReadOnlySpan<byte> tag,
        Span<byte> plainDest,
        ReadOnlySpan<byte> aadSpan,
        out string? plaintext)
    {
        try
        {
            GetAesGcm(entry).Decrypt(nonce, cipher, tag, plainDest, aadSpan);
            plaintext = Encoding.UTF8.GetString(plainDest);
            return true;
        }
        catch (CryptographicException)
        {
            plaintext = null;
            return false;
        }
    }

    private KeyEntry? FindKeyByUtf8Id(ReadOnlySpan<byte> kidSpan)
    {
        for (int i = 0; i < _keyRing.Length; i++)
        {
            if (kidSpan.SequenceEqual(_keyRing[i].KeyIdBytes))
                return _keyRing[i];
        }
        return null;
    }

    private AesGcm GetAesGcm(KeyEntry entry)
    {
        var map = _threadLocalAes.Value!;
        if (!map.TryGetValue(entry.KeyId, out var aesGcm))
        {
            aesGcm = new AesGcm(entry.KeyBytes, TagSize);
            map[entry.KeyId] = aesGcm;
        }
        return aesGcm;
    }

    internal static string Base64UrlEncode(ReadOnlySpan<byte> input)
    {
#if NET9_0_OR_GREATER
        return System.Buffers.Text.Base64Url.EncodeToString(input);
#else
        int maxCharLen = ((input.Length + 2) / 3) * 4;
        char[]? rented = null;
        try
        {
            Span<char> chars = maxCharLen <= StackTokenCharThreshold
                ? stackalloc char[StackTokenCharThreshold]
                : (rented = ArrayPool<char>.Shared.Rent(maxCharLen));

            if (!Convert.TryToBase64Chars(input, chars, out int written))
                return Convert.ToBase64String(input).Replace('+', '-').Replace('/', '_').TrimEnd('=');

            while (written > 0 && chars[written - 1] == '=')
                written--;

            for (int i = 0; i < written; i++)
            {
                if (chars[i] == '+') chars[i] = '-';
                else if (chars[i] == '/') chars[i] = '_';
            }

            return new string(chars[..written]);
        }
        finally
        {
            if (rented != null) ArrayPool<char>.Shared.Return(rented);
        }
#endif
    }

    private static bool TryBase64UrlDecode(ReadOnlySpan<char> input, Span<byte> destination, out int bytesWritten)
    {
#if NET9_0_OR_GREATER
        return System.Buffers.Text.Base64Url.TryDecodeFromChars(input, destination, out bytesWritten);
#else
        int mod = input.Length % 4;
        if (mod == 1)
        {
            bytesWritten = 0;
            return false;
        }

        int padding = mod == 0 ? 0 : 4 - mod;
        int paddedLen = input.Length + padding;
        char[]? rented = null;

        try
        {
            Span<char> padded = paddedLen <= StackTokenCharThreshold
                ? stackalloc char[StackTokenCharThreshold]
                : (rented = ArrayPool<char>.Shared.Rent(paddedLen));

            for (int i = 0; i < input.Length; i++)
            {
                char c = input[i];
                padded[i] = c == '-' ? '+' : c == '_' ? '/' : c;
            }
            for (int i = 0; i < padding; i++)
                padded[input.Length + i] = '=';

            return Convert.TryFromBase64Chars(padded[..paddedLen], destination, out bytesWritten);
        }
        finally
        {
            if (rented != null) ArrayPool<char>.Shared.Return(rented);
        }
#endif
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        if (_threadLocalAes.IsValueCreated || true)
        {
            foreach (var dict in _threadLocalAes.Values)
            {
                foreach (var aes in dict.Values)
                {
                    aes.Dispose();
                }
                dict.Clear();
            }
        }
        _threadLocalAes.Dispose();

        for (int i = 0; i < _keyRing.Length; i++)
        {
            CryptographicOperations.ZeroMemory(_keyRing[i].KeyBytes);
        }
        CryptographicOperations.ZeroMemory(_derivedHashKey);
    }
}
