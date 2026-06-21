using System.ComponentModel;
using Crypto.Core;
// Crypto.Lab — Angriffs-Labor (Erweiterung).
// Wird später umgesetzt (siehe docs/design.md, Abschnitt 7). Darf KI-generiert sein.

namespace Crypto.Lab;
class Program
{
    private readonly IHashFunction _hashFunction;
    private readonly IMac _mac;

    public Program(IHashFunction hashFunction, IMac mac)
    {
        _hashFunction = hashFunction;
        _mac = mac;
    }
 
    static void Main()
    {
        var p = new Program(new Sha256(), new HmacSha256());   
        p.CallMac();
        p.CallHash();
        uint iterations = 0b0001;
        Console.WriteLine($"Iterations : {iterations}");
        byte beIterations = (byte)(iterations << 4);
        Console.WriteLine($"Bei iteration : {beIterations}");
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
}