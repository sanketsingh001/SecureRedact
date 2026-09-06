namespace FintechGuard.Pii.Crypto;

/// <summary>
/// Provides high-speed authenticated encryption and decryption for reversible PII tokenization.
/// </summary>
public interface IReversibleCrypto
{
    /// <summary>
    /// Encrypts plaintext into a compact authenticated token.
    /// </summary>
    string Encrypt(string plaintext, string? associatedData = null);

    /// <summary>
    /// Decrypts a compact authenticated token back into plaintext.
    /// </summary>
    string Decrypt(string cipherToken, string? associatedData = null);

    /// <summary>
    /// Attempts to decrypt a compact token. Returns false if key is wrong or token is invalid/tampered.
    /// </summary>
    bool TryDecrypt(string cipherToken, out string? plaintext, string? associatedData = null);
}
