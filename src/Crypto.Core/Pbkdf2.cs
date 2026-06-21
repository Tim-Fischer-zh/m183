using System.Security.Cryptography;

namespace Crypto.Core;

public sealed class Pbkdf2 : IPasswordHasher
{
    private readonly IMac _mac= new HmacSha256();

    private byte[] Do(string password, byte[] salt, uint iterations, int dkLen)
    {
        // Salt || 00 00 00 01.
        byte beIterations = (byte)(iterations >> 4);
        salt[0] += beIterations;
        return salt;
    }
    
    public string Hash(string password)
    {
        // Random Number Generator mache ich nicht von Hand.
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        uint iterations = 1;
        int dkLen = 32;
        Do(password, salt, iterations, dkLen);
        return BitConverter.ToString(Do(password, salt, iterations, dkLen));
    }

    public bool Verify(string password, string storedHash)
    {
        return true;
    }
    
}