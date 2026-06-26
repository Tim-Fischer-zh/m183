using System.Security.Cryptography;
using System.Text;

namespace Crypto.Core;

public sealed class Pbkdf2 : IPasswordHasher
{
    private readonly IMac _mac= new HmacSha256();

    private byte[] Do(string password, byte[] salt, uint iterations, int dkLen, uint index)
    {
        byte[] bytePassword = Encoding.UTF8.GetBytes(password);
        // Salt || 00 00 00 01.
        // index ist der block den der Hash ist. zb 2 oder 100
        byte[] blockIndex = new byte[4];
        blockIndex[0] = (byte)(index >> 24);
        blockIndex[1] = (byte)(index >> 16);
        blockIndex[2] = (byte)(index >> 8);
        blockIndex[3] = (byte)(index);
        
        
        var saltPlusCounter = salt.Concat(blockIndex).ToArray();
        
        var u1 = _mac.ComputeMac(bytePassword, saltPlusCounter);

        byte[] u = u1;
        byte[] t = (byte[])u1.Clone();

        for (uint j = 2; j <= iterations; j++)
        {
            u = _mac.ComputeMac(bytePassword, u);
            for (int k = 0; k < t.Length; k++)
            {
                // oder? t[k] ^= u[k];
                t[k] = (byte)(t[k] ^ u[k]);
            }
        }
        
        return t;
    }
    
    public string Hash(string password)
    {
        // Random Number Generator mache ich nicht von Hand.
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        uint iterations = 60000;
        int dkLen = 32;
        var hash = Do(password, salt, iterations, dkLen, 1);
        return $"pbkdf2-sha256${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public bool Verify(string password, string storedHash)
    {
        string[] parts = storedHash.Split('$');
        uint iterations = uint.Parse(parts[1]);
        byte[] salt = Convert.FromBase64String(parts[2]);
        byte[] hash = Convert.FromBase64String(parts[3]);
        var hashToVerify = Do(password, salt, iterations, 32, 1);
        
        
        if (hashToVerify.Length != hash.Length) return false;

        int diff = 0;
        for (int i = 0; i < hash.Length; i++)
            diff |= hashToVerify[i] ^ hash[i];

        return diff == 0;
    }
    
}