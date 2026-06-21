namespace Crypto.Core;

/// <summary>
/// Passwort-Hashing mit Salt und Work-Factor (z. B. PBKDF2).
/// </summary>
public interface IPasswordHasher
{
    /// <summary>
    /// Erzeugt einen selbst-beschreibenden Hash-String, der Algorithmus,
    /// Iterationszahl, Salt und Hash enthält (damit später migrierbar).
    /// </summary>
    string Hash(string password);

    /// <summary>Prüft ein Passwort gegen einen gespeicherten Hash-String (constant-time).</summary>
    bool Verify(string password, string storedHash);
}
