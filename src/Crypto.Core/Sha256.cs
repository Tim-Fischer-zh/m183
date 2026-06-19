using System;
using System.Globalization;
using System.Security.Cryptography;

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
    // Initiale Hash-Werte: Nachkomma-Bits der Quadratwurzeln der ersten 8 Primzahlen
    private static readonly uint[] H0 =
    {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    // Rundenkonstanten: Nachkomma-Bits der Kubikwurzeln der ersten 64 Primzahlen
    private static readonly uint[] K =
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    
    
    public byte[] Hash(ReadOnlySpan<byte> data)
    {
        Pad(data.ToArray());        
        byte[] padded = Pad(data.ToArray());
        uint[] W = B2(B1(padded));
        
        uint[] hash = (uint[])H0.Clone();
        uint a=hash[0], b=hash[1], c=hash[2], d=hash[3],
            e=hash[4], f=hash[5], g=hash[6], h=hash[7];
        
        for (int t = 0; t < 64; t++)
        {
            uint T1 = h + BigSigma1(e) + Ch(e,f,g) + K[t] + W[t];
            uint T2 = BigSigma0(a) + Maj(a,b,c);

            h = g;  g = f;  f = e;  e = d + T1;
            d = c;  c = b;  b = a;  a = T1 + T2;
        }
        
        hash[0]+=a; hash[1]+=b; hash[2]+=c; hash[3]+=d;
        hash[4]+=e; hash[5]+=f; hash[6]+=g; hash[7]+=h;
        byte[] result = new byte[32];
        for (int i = 0; i < 8; i++)
        {
            result[4*i]     = (byte)(hash[i] >> 24);   // höchstwertiges Byte zuerst
            result[4*i + 1] = (byte)(hash[i] >> 16);
            result[4*i + 2] = (byte)(hash[i] >> 8);
            result[4*i + 3] = (byte)(hash[i]);
        }

        return result;
    }

    private static byte[] Pad(ReadOnlySpan<byte> data)
    {
        byte[] message = data.ToArray(); //copy in message
        List<byte> block = new List<byte>(message); // mutable liste 
        ulong bitLen = (ulong)data.Length * 8; // erhaltene data länge, bei abc=24
        
        block.Add(0x80); // Ende der nachricht das hinzufügen also "abc" + 0x80 .....
        
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

    /*  a = 1100
     *  b = 1010
     *  a & b 1000 = 8 AND (beide 1)
     *  a | b 1110 = 14 OR (mind. eins 1) 
     *  a ^ b 0110 = 6 XOR (genau eins 1)
     *  ~a 0011 = 3 NOT (alle Bits kippen)
     */
    
    private static uint RotR(uint x, int n)
    {
        // shift 32bit uint um n, da aber shift Nullen einfüllt, müssen wir die verschobenen bits wieder am Ende einfügen
        return (x >> n) | (x << (32 - n));
    }

    private static uint Ch(uint e, uint f, uint g)
    {
        /*
         * e AND f XOR negiertesE AND g 
         * (e)0011 AND (f)0101 = 0001 
         * (~e)1100 AND (g)1110 = 1100
         * (e&f)0001 XOR (~e&g)1100 = 1101
         */ 
        return (e & f) ^ (~e & g);
    }

    private static uint Maj(uint a, uint b, uint c)
    {
        /*
         * (a AND b) XOR (a AND c) XOR (b AND c)
         */
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

    private static uint[] B1(byte[] data)
    {
        uint[] W = new uint[64];
        for (int i = 0; i < 16; i++)
        {
            W[i] = (uint)data[4 * i] << 24 | (uint)data[4 * i + 1] << 16 | (uint)data[4 * i + 2] << 8 |
                   (uint)data[4 * i + 3];
        }

        return W;
    }

    private static uint[] B2(uint[] W)
    {
        for (int t = 16; t < 64; t++)
        {
            W[t] = SmallSigma1(W[t-2]) + W[t-7] + SmallSigma0(W[t-15]) + W[t-16];
        }

        return W;
    }


    
}
