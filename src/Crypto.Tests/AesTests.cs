using System.Security.Cryptography;
using Crypto.Core;
using Xunit;

namespace Crypto.Tests;

public class AesTests
{
    private static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    // Offizieller Testvektor aus FIPS 197, Anhang C.3 (AES-256, ein Block).
    [Fact]
    public void EncryptBlock_MatchesFips197()
    {
        byte[] key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] plaintext = Convert.FromHexString("00112233445566778899aabbccddeeff");
        byte[] expected = Convert.FromHexString("8ea2b7ca516745bfeafc49904b496089");

        byte[] actual = Aes256.EncryptBlock(plaintext, key);

        Assert.Equal(ToHex(expected), ToHex(actual));
    }

    // Quervergleich gegen die .NET-Implementierung im ECB-Modus mit zufaelligen
    // Schluesseln und Bloecken. ECB verschluesselt jeden 16-Byte-Block unabhaengig,
    // ein Block entspricht also genau unserem EncryptBlock.
    [Fact]
    public void EncryptBlock_MatchesDotNet_ForRandomInputs()
    {
        var rng = new Random(7); // fester Seed -> reproduzierbar
        for (int i = 0; i < 100; i++)
        {
            byte[] key = new byte[32];
            byte[] block = new byte[16];
            rng.NextBytes(key);
            rng.NextBytes(block);

            using var aes = Aes.Create();
            aes.Key = key; // 32 Byte -> AES-256
            byte[] expected = aes.EncryptEcb(block, PaddingMode.None);

            byte[] actual = Aes256.EncryptBlock(block, key);

            Assert.Equal(expected, actual);
        }
    }
}
