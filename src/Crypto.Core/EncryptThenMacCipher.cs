using System.Security.Cryptography;

namespace Crypto.Core;

public class EncryptThenMacCipher : ISymmetricCipher
{
    private readonly IStreamCipher _cipher;
    private readonly IMac _mac;

    public EncryptThenMacCipher(IStreamCipher cipher, IMac mac)
    {
        _cipher = cipher;
        _mac = mac;
    }
    /*
     * HMAC und ChaCha20
     */
    public byte[] Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext)
    {
        var encKey = _mac.ComputeMac(key, "enc"u8);
        var macKey = _mac.ComputeMac(key, "mac"u8);
        var nonce = RandomNumberGenerator.GetBytes(_cipher.NonceSizeInBytes);
        var ct = _cipher.Encrypt(encKey, nonce, plaintext);
        var tag = _mac.ComputeMac(macKey, nonce.Concat(ct).ToArray());
        return nonce.Concat(ct).Concat(tag).ToArray();
    }

    public byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> blob)
    {
        byte[] encKey = _mac.ComputeMac(key, "enc"u8);
        byte[] macKey = _mac.ComputeMac(key, "mac"u8);
        int nonceLen = _cipher.NonceSizeInBytes;   // 12
        int macLen   = _mac.MacSizeInBytes;         // 32
        byte[] nonce = blob.Slice(0, nonceLen).ToArray();
        byte[] tag   = blob.Slice(blob.Length - macLen, macLen).ToArray();
        byte[] ct    = blob.Slice(nonceLen, blob.Length - nonceLen - macLen).ToArray();
        if (!_mac.Verify(macKey, nonce.Concat(ct).ToArray(), tag))
        {
            throw new CryptographicException("Entschluesselung fehlgeschlagen.");
        }
        
        return _cipher.Decrypt(encKey, nonce, ct);
    }
}