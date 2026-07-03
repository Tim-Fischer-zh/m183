using System.Text;
using Crypto.Core;
using Xunit;

namespace Crypto.Tests;

public class ChaCha20Tests 
{
    // Known-Answer-Test: RFC-8439-Schluessel, -Nonce und -Klartext, mit Zaehler-Start 0
    // (wie unser Encrypt es macht). Der erwartete Ciphertext stammt aus einer gegen die
    // RFC-8439-Vektoren verifizierten Referenzimplementierung.
    [Fact]
    public void Encrypt_MatchesKnownAnswer()
    {
        var sut = new ChaCha20();
        byte[] key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] nonce = Convert.FromHexString("000000000000004a00000000");
        byte[] plaintext = Encoding.ASCII.GetBytes(
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
        byte[] expected = Convert.FromHexString(
            "e3647a29ded31528ef56bac70f7a7ac3b735c7444da42d99823ef9938c8ebfdc" +
            "f05bb71a822c62981aa1ea608f47933f2ed755b62d9312ae72037674f3e93e24" +
            "4c2328d32f75bcc15bb7574fde0c6fcdf87b7aa25b5972970c2ae6cced86a10b" +
            "e9496fc61c407dfdc01510ed8f4eb35d0d62");

        byte[] actual = sut.Encrypt(key, nonce, plaintext);

        Assert.Equal(Convert.ToHexString(expected), Convert.ToHexString(actual));
    }

    // Round-Trip: Decrypt macht Encrypt rueckgaengig, auch bei Teilbloecken.
    // Die Laengen decken leere Eingabe, Ein-Byte, genau ein Block, knapp darueber und mehrere Bloecke ab.
    [Fact]
    public void Decrypt_UndoesEncrypt_ForVariousLengths()
    {
        var sut = new ChaCha20();
        var rng = new Random(42);
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        rng.NextBytes(key);
        rng.NextBytes(nonce);

        foreach (int len in new[] { 0, 1, 63, 64, 65, 200 })
        {
            byte[] plaintext = new byte[len];
            rng.NextBytes(plaintext);

            byte[] ciphertext = sut.Encrypt(key, nonce, plaintext);
            byte[] roundtrip = sut.Decrypt(key, nonce, ciphertext);

            Assert.Equal(plaintext, roundtrip);
        }
    }
}
