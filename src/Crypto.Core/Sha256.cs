using System;

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
    /*
     * byte   // 8 Bit, 0..255
     * uint   // 32 Bit, 0..2^32-1   
     * ulong  // 64 Bit              
     */
    public int HashSizeInBytes => 32;

    public byte[] Hash(ReadOnlySpan<byte> data)
    {
        Pad(data.ToArray());        
        
        return data.ToArray();
    }

    private static byte[] Pad(ReadOnlySpan<byte> data)
    {
        byte[] message = data.ToArray(); //copy in message
        List<byte> block = new List<byte>(message); // mutable liste 
        ulong bitLen = (ulong)data.Length * 8; // erhaltene data länge, bei abc=24
        
        block.Add(0x80); // ende der nachricht das hinzufügen also "abc" + 0x80 .....
        
        for(int i = block.Count; i <56; i++) // bis index 56 mit 0 auffüllen
        {
            block.Add(0x00);
        }
        
        // byte[] padded = block.ToArray(); // 97 98 99 0 0 0 0 0 0 0 0 0...
        // Console.WriteLine("data: " + data.Length +" " + "padded: " + padded.Length); //3
        
        for (int i = 56; i >= 0; i = i - 8) // da ulong 56 - 0 shiften kann, startet i bei 56 und added von Bitlen via BigEndian zum block   
        {
            block.Add((byte)(bitLen >> i)); // 0000_0010 << 1 = 0000_0100 (null kommt dazu) hier shiften wir aber mit 8er damit es den nächsten byte nimmt
        }
        
        return block.ToArray();
    }

    private static uint RotR(uint x, int n)
    {
        return (x >> n) | (x << (32 - n));
    }

    private static uint Ch(uint e, uint f, uint g)
    {
        return (e & f) ^ (~e & g);
    }

    private static uint Maj(uint a, uint b, uint c)
    {
        return (a & b) ^ (a & c) ^ (b & c);
    }

    private static uint BigSigma0(uint x)
    {
        return RotR(x, 2) ^ RotR(x, 13) ^ RotR(x, 22);
    }

    private static uint BigSigma1(uint x)
    {
        return RotR(x, 6) ^ RotR(x, 11) ^ RotR(x, 25);
    }

    private static uint SmallSigma0(uint x)
    {
        return RotR(x, 7) ^ RotR(x, 18) ^ (x >> 3);
    }

    private static uint SmallSigma1(uint x)
    {
        return RotR(x, 17) ^ RotR(x, 19) ^ (x >> 10);
    }
    
}
