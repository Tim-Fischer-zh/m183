using System.Runtime.InteropServices.Marshalling;

namespace Crypto.Core;

public class ChaCha20 : IStreamCipher
{
    public int NonceSizeInBytes => 12;
    private static uint RotL(uint x, int n)
    {
        // shift 32bit uint um n, da aber shift Nullen einfüllt, müssen wir die verschobenen bits wieder am Ende einfügen
        return (x << n) | (x >> (32 - n));
    }

    private static void QuarterRound(uint[] s, int a, int b, int c, int d)
    {
        s[a] += s[b];  s[d] ^= s[a];  s[d] = RotL(s[d], 16);
        s[c] += s[d];  s[b] ^= s[c];  s[b] = RotL(s[b], 12);
        s[a] += s[b];  s[d] ^= s[a];  s[d] = RotL(s[d], 8);
        s[c] += s[d];  s[b] ^= s[c];  s[b] = RotL(s[b], 7);
    }

    private static byte[] Block(byte[] key, uint counter, byte[] nonce)
    {
        //state
        uint[] w = new uint[16];
        //konstanten
        w[0] = 0x61707865;
        w[1] = 0x3320646e;
        w[2] = 0x79622d32;
        w[3] = 0x6b206574;

        //schlüssel
        for (int j = 0; j < 8; j++)
        {
            w[4 + j] = (uint)key[4 * j]
                       | ((uint)key[4 * j + 1] << 8)
                       | ((uint)key[4 * j + 2] << 16)
                       | ((uint)key[4 * j + 3] << 24);
        }
        //counter
        w[12] = counter;

        for (int j = 0; j < 3; j++)
        {
            w[13 + j] = (uint)nonce[4 * j]
                        | ((uint)nonce[4 * j + 1] << 8)
                        | ((uint)nonce[4 * j + 2] << 16)
                        | ((uint)nonce[4 * j + 3] << 24);
        }
        uint[] original = (uint[])w.Clone();
        
        for (int i = 0; i < 10; i++)
        {
            QuarterRound(w, 0, 4,  8, 12);
            QuarterRound(w, 1, 5,  9, 13);
            QuarterRound(w, 2, 6, 10, 14);
            QuarterRound(w, 3, 7, 11, 15);
            QuarterRound(w, 0, 5, 10, 15);
            QuarterRound(w, 1, 6, 11, 12);
            QuarterRound(w, 2, 7,  8, 13);
            QuarterRound(w, 3, 4,  9, 14);
        }
        //original zum w addieren!
        for (int i = 0; i < 16; i++)
            w[i] += original[i];
        //output littleendian deswegen die shifts. anderst als bei sha oder aes, hier ist niederwertigstes zuletzt
        byte[] output = new byte[64];
        for (int i = 0; i < 16; i++)
        {
            output[4 * i] = (byte)(w[i]);
            output[4 * i + 1] = (byte)(w[i] >> 8);
            output[4 * i + 2] = (byte)(w[i] >> 16);
            output[4 * i + 3] = (byte)(w[i] >> 24);
        }
        return output;
    }
    
    
    // entrypoints für DI 
    public byte[] Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext)
    {
        byte[] keyArr = key.ToArray();
        byte[] nonceArr = nonce.ToArray();
        byte[] output = new byte[plaintext.Length];
        uint counter = 0;

        for (int offset = 0; offset < plaintext.Length; offset += 64)
        {
            byte[] keystream = Block(keyArr, counter, nonceArr);
            int len = Math.Min(64, plaintext.Length - offset);
            for (int i = 0; i < len; i++)
                output[offset + i] = (byte)(plaintext[offset + i] ^ keystream[i]);
            counter++;
        }

        return output;
    }
    public byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext)
        => Encrypt(key, nonce, ciphertext);
}