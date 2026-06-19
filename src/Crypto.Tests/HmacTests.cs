using System.Security.Cryptography;
using System.Text;
using Crypto.Core;
using Xunit;

namespace Crypto.Tests;

public class HmacTests
{
    private static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private static byte[] Repeat(byte value, int count)
    {
        byte[] a = new byte[count];
        Array.Fill(a, value);
        return a;
    }

    // Offizielle Testvektoren aus RFC 4231.
    public static IEnumerable<object[]> Rfc4231()
    {
        // TC1: Key = 20x 0x0b, Msg = "Hi There"
        yield return new object[]
        {
            Repeat(0x0b, 20), Encoding.ASCII.GetBytes("Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        };
        // TC2: Key = "Jefe", Msg = "what do ya want for nothing?"
        yield return new object[]
        {
            Encoding.ASCII.GetBytes("Jefe"), Encoding.ASCII.GetBytes("what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        };
        // TC6: Key = 131x 0xaa (laenger als 64 -> wird zuerst gehasht)
        yield return new object[]
        {
            Repeat(0xaa, 131), Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First"),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        };
    }

    [Theory]
    [MemberData(nameof(Rfc4231))]
    public void ComputeMac_MatchesRfc4231(byte[] key, byte[] message, string expectedHex)
    {
        var sut = new HmacSha256();
        Assert.Equal(expectedHex, ToHex(sut.ComputeMac(key, message)));
    }

    // Quervergleich gegen die .NET-Implementierung mit zufaelligen Schluesseln und Nachrichten.
    [Fact]
    public void ComputeMac_MatchesDotNet_ForRandomInputs()
    {
        var sut = new HmacSha256();
        var rng = new Random(99); // fester Seed
        for (int i = 0; i < 100; i++)
        {
            byte[] key = new byte[rng.Next(1, 100)];   // teils ueber 64 -> testet den Hash-Pfad
            byte[] msg = new byte[rng.Next(0, 200)];
            rng.NextBytes(key);
            rng.NextBytes(msg);
            Assert.Equal(HMACSHA256.HashData(key, msg), sut.ComputeMac(key, msg));
        }
    }
}
