using System.Security.Cryptography;
using System.Text;
using Crypto.Core;
using Xunit;

namespace Crypto.Tests;

public class Sha256Tests
{
    private static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    // Offizielle Testvektoren (FIPS 180-4 / bekannt). Siehe docs/krypto-spec/01-sha256.md, Abschnitt 7.
    [Theory]
    [InlineData("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    [InlineData("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
    [InlineData(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")]
    public void Hash_MatchesOfficialTestVectors(string input, string expectedHex)
    {
        var sut = new Sha256();
        byte[] actual = sut.Hash(Encoding.ASCII.GetBytes(input));
        Assert.Equal(expectedHex, ToHex(actual));
    }

    // Quervergleich gegen die geprüfte .NET-Implementierung mit zufälligen Eingaben.
    [Fact]
    public void Hash_MatchesDotNet_ForRandomInputs()
    {
        var sut = new Sha256();
        var rng = new Random(12345); // fester Seed -> reproduzierbar
        for (int i = 0; i < 100; i++)
        {
            byte[] data = new byte[rng.Next(0, 200)];
            rng.NextBytes(data);
            Assert.Equal(SHA256.HashData(data), sut.Hash(data));
        }
    }
}
