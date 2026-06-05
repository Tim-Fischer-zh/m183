namespace Crypto.Core;

/// <summary>
/// SHA-256 nach FIPS 180-4.
///
/// Implementierung gemäss docs/krypto-spec/01-sha256.md — selbst zu schreiben.
/// Empfohlene Reihenfolge: ROTR/SHR -> Ch/Maj/Sigma -> Padding ->
/// Message Schedule -> Hauptschleife -> Output (big-endian).
/// </summary>
public sealed class Sha256 : IHashFunction
{
    public int HashSizeInBytes => 32;

    public byte[] Hash(ReadOnlySpan<byte> data)
    {
        byte[] message = data.ToArray();
        var block = new List<byte>(message);
        block.Add(0x80);
        
        for(int i = block.ToArray().Length; i <56; i++)
        {
            block.Add(0x00);
        }

        byte[] padded = block.ToArray();
        
        for(int i = 0; i < padded.Length; i++)
        {
            Console.WriteLine(padded[i].ToString());
        }
        return data.ToArray();
    }
}
