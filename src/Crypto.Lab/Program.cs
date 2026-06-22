using System.ComponentModel;
using Crypto.Core;
// Crypto.Lab — Angriffs-Labor (Erweiterung).
// Wird später umgesetzt (siehe docs/design.md, Abschnitt 7). Darf KI-generiert sein.

namespace Crypto.Lab;
class Program
{
    private readonly IHashFunction _hashFunction;
    private readonly IMac _mac;
    private readonly IPasswordHasher _pbkdf2;

    public Program(IHashFunction hashFunction, IMac mac, IPasswordHasher pbkdf2)
    {
        _hashFunction = hashFunction;
        _mac = mac;
        _pbkdf2 = pbkdf2;
    }
 
    static void Main()
    {
        var p = new Program(new Sha256(), new HmacSha256(), new Pbkdf2());   
        // p.CallMac();
        // p.CallHash();
        p.CallPbkdf2();
    }

    public void CallHash()
    {
        byte[] hash = _hashFunction.Hash("abc"u8);
        Console.WriteLine(Convert.ToHexString(hash).ToLowerInvariant());
    }

    public void CallMac()
    {
        byte[] mac = _mac.ComputeMac(new byte[20], "Hi There"u8);
        Console.WriteLine(Convert.ToHexString(mac).ToLowerInvariant());
    }

    public void CallPbkdf2()
    {
        var sut = new Pbkdf2();
        byte[] salt = System.Text.Encoding.ASCII.GetBytes("salt");
        byte[] dk = sut.Do("password", salt, 4096, 32, 1);
        Console.WriteLine(Convert.ToHexString(dk).ToLowerInvariant());
    }
}