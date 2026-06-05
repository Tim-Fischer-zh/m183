namespace Crypto.Core;

/// <summary>
/// Eine kryptografische Hash-Funktion fester Ausgabelänge (z. B. SHA-256).
/// </summary>
public interface IHashFunction
{
    /// <summary>Länge des Hash-Ergebnisses in Bytes (SHA-256: 32).</summary>
    int HashSizeInBytes { get; }

    /// <summary>Berechnet den Hash über die gesamte Eingabe.</summary>
    byte[] Hash(ReadOnlySpan<byte> data);
}
