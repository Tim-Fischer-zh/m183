using System.Security.Cryptography;
using System.Text;
using Crypto.Core;
using Xunit;

namespace Crypto.Tests;

public class Pbkdf2Tests
{
    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    // Der Hash-String hat die Form: pbkdf2-sha256$<iterations>$<salt_b64>$<hash_b64>.
    // Wir zerlegen ihn, leiten den Hash mit der geprueften .NET-Implementierung aus
    // demselben Salt und derselben Iterationszahl neu ab und vergleichen.
    // Das prueft Mathematik und Format in einem.
    [Fact]
    public void Hash_MatchesReferencePbkdf2()
    {
        var sut = new Pbkdf2();
        const string password = "correct horse battery staple";

        string stored = sut.Hash(password);
        string[] parts = stored.Split('$');

        Assert.Equal(4, parts.Length);
        Assert.Equal("pbkdf2-sha256", parts[0]);

        int iterations = int.Parse(parts[1]);
        byte[] salt = Convert.FromBase64String(parts[2]);
        byte[] hash = Convert.FromBase64String(parts[3]);

        byte[] expected = Rfc2898DeriveBytes.Pbkdf2(
            Utf8(password), salt, iterations, HashAlgorithmName.SHA256, 32);

        Assert.Equal(expected, hash);
    }

    // Zwei Aufrufe mit demselben Passwort muessen verschiedene Hashes liefern,
    // weil jeder einen frischen zufaelligen Salt bekommt.
    [Fact]
    public void Hash_UsesFreshSaltEachTime()
    {
        var sut = new Pbkdf2();
        Assert.NotEqual(sut.Hash("same"), sut.Hash("same"));
    }

    [Fact]
    public void Verify_AcceptsCorrectPassword()
    {
        var sut = new Pbkdf2();
        string stored = sut.Hash("hunter2");
        Assert.True(sut.Verify("hunter2", stored));
    }

    [Fact]
    public void Verify_RejectsWrongPassword()
    {
        var sut = new Pbkdf2();
        string stored = sut.Hash("hunter2");
        Assert.False(sut.Verify("hunter3", stored));
    }
}
