namespace Crypto.Core;

/// <summary>
/// Message Authentication Code (z. B. HMAC-SHA256) zur Integritätssicherung.
/// </summary>
public interface IMac
{
    /// <summary>Länge des MAC in Bytes.</summary>
    int MacSizeInBytes { get; }

    /// <summary>Berechnet den MAC über die Nachricht mit dem gegebenen Schlüssel.</summary>
    byte[] ComputeMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message);

    /// <summary>Prüft einen erwarteten MAC. MUSS constant-time vergleichen.</summary>
    bool Verify(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> expectedMac);
}
