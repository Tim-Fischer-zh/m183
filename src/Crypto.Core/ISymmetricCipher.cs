namespace Crypto.Core;

/// <summary>
/// Authentifizierte symmetrische Verschlüsselung (Encrypt-then-MAC).
/// Nonce/IV wird intern erzeugt und im Ausgabe-Blob mitgeführt.
/// </summary>
public interface ISymmetricCipher
{
    /// <summary>Verschlüsselt und authentifiziert den Klartext.</summary>
    byte[] Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext);

    /// <summary>
    /// Prüft die Authentizität und entschlüsselt. Wirft bei Manipulation oder
    /// falschem Schlüssel eine generische Exception (keine Detail-Leaks).
    /// </summary>
    byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> blob);
}
