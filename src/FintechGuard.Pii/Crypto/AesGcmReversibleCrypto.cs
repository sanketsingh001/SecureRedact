using System.Security.Cryptography;
using System.Text;

namespace FintechGuard.Pii.Crypto;

/// <summary>
/// Implements high-throughput authenticated encryption using AES-256-GCM.
/// Each encryption produces a unique 12-byte cryptographically random IV/nonce, preventing rainbow-table attacks.
/// The 16-byte authentication tag guarantees ciphertext integrity against tampering.
/// </summary>
public sealed class AesGcmReversibleCrypto : IReversibleCrypto, IDisposable
{
    private readonly byte[] _key;
    private readonly AesGcm _aesGcm;

    public AesGcmReversibleCrypto(byte[] key)
    {
        if (key == null || (key.Length != 16 && key.Length != 24 && key.Length != 32))
        {
            throw new ArgumentException("AES-GCM key must be 16, 24, or 32 bytes (128, 192, or 256 bits).", nameof(key));
        }

        _key = (byte[])key.Clone();
        _aesGcm = new AesGcm(_key, 16);
    }

    /// <summary>
    /// Derives a 256-bit AES key from a passphrase using SHA-256.
    /// </summary>
    public static AesGcmReversibleCrypto FromPassphrase(string passphrase)
    {
        if (string.IsNullOrEmpty(passphrase))
            throw new ArgumentException("Passphrase cannot be empty.", nameof(passphrase));

        byte[] keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(passphrase));
        return new AesGcmReversibleCrypto(keyBytes);
    }

    public string Encrypt(string plaintext, string? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] nonce = new byte[12]; // 96-bit nonce for GCM
        RandomNumberGenerator.Fill(nonce);

        byte[] cipherBytes = new byte[plainBytes.Length];
        byte[] tag = new byte[16]; // 128-bit tag

        byte[]? aadBytes = associatedData != null ? Encoding.UTF8.GetBytes(associatedData) : null;

        _aesGcm.Encrypt(nonce, plainBytes, cipherBytes, tag, aadBytes);

        // Compact binary format: [12-byte nonce][16-byte tag][ciphertext]
        byte[] combined = new byte[12 + 16 + cipherBytes.Length];
        Buffer.BlockCopy(nonce, 0, combined, 0, 12);
        Buffer.BlockCopy(tag, 0, combined, 12, 16);
        Buffer.BlockCopy(cipherBytes, 0, combined, 28, cipherBytes.Length);

        return Base64UrlEncode(combined);
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
        if (string.IsNullOrWhiteSpace(cipherToken))
            return false;

        byte[] combined;
        try
        {
            combined = Base64UrlDecode(cipherToken);
        }
        catch
        {
            return false;
        }

        if (combined.Length < 28) // 12 nonce + 16 tag minimum
            return false;

        ReadOnlySpan<byte> nonce = combined.AsSpan(0, 12);
        ReadOnlySpan<byte> tag = combined.AsSpan(12, 16);
        ReadOnlySpan<byte> cipherBytes = combined.AsSpan(28);

        byte[] plainBytes = new byte[cipherBytes.Length];
        byte[]? aadBytes = associatedData != null ? Encoding.UTF8.GetBytes(associatedData) : null;

        try
        {
            _aesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes, aadBytes);
            plaintext = Encoding.UTF8.GetString(plainBytes);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    private static byte[] Base64UrlDecode(string input)
    {
        string padded = input.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }

    public void Dispose()
    {
        _aesGcm.Dispose();
        CryptographicOperations.ZeroMemory(_key);
    }
}
