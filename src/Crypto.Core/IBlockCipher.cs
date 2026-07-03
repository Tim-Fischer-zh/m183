namespace Crypto.Core;

/// <summary>
/// Eine Block-Chiffre mit fester Blockgrösse (z. B. AES-256).
/// Verschlüsselt genau einen Block.
/// </summary>
public interface IBlockCipher
{
    /// <summary>Blockgrösse in Bytes (AES: 16).</summary>
    int BlockSizeInBytes { get; }

    /// <summary>Verschlüsselt einen einzelnen Block mit dem gegebenen Schlüssel.</summary>
    byte[] EncryptBlock(ReadOnlySpan<byte> key, ReadOnlySpan<byte> block);
}
