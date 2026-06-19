
namespace Crypto.Core;

public class HmacSha256 : IMac
{
    private readonly IHashFunction _hashFunction = new Sha256();
    public int MacSizeInBytes { get; } = 32;
    
    public byte[] ComputeMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
    {
        List<byte> block;
        
        byte[] ipad = new byte[64];
        byte[] opad = new byte[64];
        for (int i = 0; i < 64; i++)
        {
            ipad[i] = 0x36;
            opad[i] = 0x5C;
            
        }

        if (key.Length > 64)
        {
            block = new List<byte>(_hashFunction.Hash(key));
        }
        else
        {
            block = new List<byte>(key.ToArray());
        }
        
        while (block.Count < 64)
        {
            block.Add(0x00);
        }
        
        //ipadKey = K' XOR ipad,
        //opadKey = K' XOR opad
        byte[] ipadkey = new byte[64];
        byte[] opadkey = new byte[64];
        for (int i = 0; i < 64; i++)
        {
            ipadkey[i] = (byte)(block[i] ^ ipad[i]);
            opadkey[i] = (byte)(block[i] ^ opad[i]);
        }
        var inner = _hashFunction.Hash(ipadkey.Concat(message.ToArray()).ToArray());
        var outer = _hashFunction.Hash(opadkey.Concat(inner.ToArray()).ToArray());
        /*
         * inner  = SHA-256( (K' XOR ipad) || message )
         * result = SHA-256( (K' XOR opad) || inner )
         */
        return outer.ToArray();
    }

    public bool Verify(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> expectedMac)
    {
        int diff =0;
        var computed = ComputeMac(key, message);
        if (expectedMac.Length != computed.Length)
        {
            return false;
        }
        
        for (int i = 0; i < computed.Length; i++)
        { 
            diff |= computed[i] ^ expectedMac[i];
            
            if (expectedMac[i] != computed[i])
            {
                return false;
            }
        }
        return diff == 0;
    }
    
    
}