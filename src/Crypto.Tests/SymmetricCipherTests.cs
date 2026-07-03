using System.Text;
using Crypto.Core;
using Xunit;

namespace Crypto.Tests;

public class SymmetricCipherTests
{
    // ChaCha20 als Chiffre, HMAC-SHA256 als MAC, per Konstruktor injiziert.
    private static ISymmetricCipher Create() => new EncryptThenMacCipher(new ChaCha20(), new HmacSha256());

    private static byte[] RandomKey(int seed)
    {
        byte[] key = new byte[32];
        new Random(seed).NextBytes(key);
        return key;
    }

    // Decrypt macht Encrypt rueckgaengig, ueber verschiedene Laengen (inkl. leer und Teilbloecke).
    [Fact]
    public void Decrypt_UndoesEncrypt_ForVariousLengths()
    {
        var sut = Create();
        byte[] key = RandomKey(1);
        var rng = new Random(2);

        foreach (int len in new[] { 0, 1, 15, 64, 100 })
        {
            byte[] plaintext = new byte[len];
            rng.NextBytes(plaintext);

            byte[] blob = sut.Encrypt(key, plaintext);
            Assert.Equal(plaintext, sut.Decrypt(key, blob));
        }
    }

    // Zweimal derselbe Klartext ergibt verschiedene Blobs, weil jeder Aufruf einen frischen Nonce nimmt.
    [Fact]
    public void Encrypt_ProducesDifferentBlobsForSamePlaintext()
    {
        var sut = Create();
        byte[] key = RandomKey(3);
        byte[] plaintext = Encoding.ASCII.GetBytes("gleicher Klartext");

        Assert.NotEqual(sut.Encrypt(key, plaintext), sut.Encrypt(key, plaintext));
    }

    // Manipulation wird erkannt: ein gekipptes Byte im Blob, und Decrypt bricht ab.
    [Fact]
    public void Decrypt_Throws_WhenBlobTampered()
    {
        var sut = Create();
        byte[] key = RandomKey(4);
        byte[] plaintext = Encoding.ASCII.GetBytes("wichtig und geheim");

        byte[] blob = sut.Encrypt(key, plaintext);
        blob[blob.Length / 2] ^= 0xFF;

        Assert.ThrowsAny<Exception>(() => sut.Decrypt(key, blob));
    }
}
