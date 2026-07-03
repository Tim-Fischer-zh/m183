namespace Crypto.Core;

/// <summary>
/// Eine Stream-Chiffre (z. B. ChaCha20). Verschlüsselt beliebig lange Daten
/// als Klartext XOR Keystream. Weil XOR seine eigene Umkehrung ist, sind
/// Encrypt und Decrypt dieselbe Operation.
/// </summary>
public interface IStreamCipher
{
    /// <summary>Grösse der Nonce in Bytes (ChaCha20: 12).</summary>
    int NonceSizeInBytes { get; }

    /// <summary>Verschlüsselt den Klartext (Klartext XOR Keystream).</summary>
    byte[] Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext);

    /// <summary>Entschlüsselt den Ciphertext. Identische Operation zu Encrypt.</summary>
    byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext);
}
