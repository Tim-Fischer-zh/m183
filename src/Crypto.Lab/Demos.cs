using System.Security.Cryptography;
using System.Text;
using Crypto.Core;
using static Crypto.Lab.LabHelpers;

namespace Crypto.Lab;

// Die einfachen Demos: jede Primitive einmal mit Eingabe und konkreter Ausgabe.
internal static class Demos
{
    public static void Sha256Demo()
    {
        byte[] hash = new Sha256().Hash(Utf8(Ask("Text: ")));
        Console.WriteLine("SHA-256: " + Hex(hash));
    }

    public static void HmacDemo()
    {
        byte[] key = Utf8(Ask("Schlüssel: "));
        byte[] msg = Utf8(Ask("Nachricht: "));
        Console.WriteLine("HMAC-SHA256: " + Hex(new HmacSha256().ComputeMac(key, msg)));
    }

    public static void Pbkdf2Demo()
    {
        var hasher = new Pbkdf2();
        string stored = hasher.Hash(Ask("Passwort: "));
        Console.WriteLine("Gespeicherter Hash: " + stored);
        bool ok = hasher.Verify(Ask("Passwort zum Prüfen: "), stored);
        Console.WriteLine("Passwort stimmt: " + ok);
    }

    public static void AesDemo()
    {
        byte[] block = new byte[16];
        byte[] text = Utf8(Ask("Text (die ersten 16 Bytes werden genutzt): "));
        Array.Copy(text, block, Math.Min(16, text.Length));
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] ct = new Aes256().EncryptBlock(key, block);
        Console.WriteLine("Schlüssel (hex):   " + Hex(key));
        Console.WriteLine("Block (hex):       " + Hex(block));
        Console.WriteLine("Ciphertext (hex):  " + Hex(ct));
    }

    public static void ChaChaDemo()
    {
        byte[] pt = Utf8(Ask("Text: "));
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        var cipher = new ChaCha20();
        byte[] ct = cipher.Encrypt(key, nonce, pt);
        Console.WriteLine("Schlüssel (hex):   " + Hex(key));
        Console.WriteLine("Nonce (hex):       " + Hex(nonce));
        Console.WriteLine("Ciphertext (hex):  " + Hex(ct));
        Console.WriteLine("Entschlüsselt:     " + Encoding.UTF8.GetString(cipher.Decrypt(key, nonce, ct)));
    }

    public static void AuthDemo()
    {
        byte[] pt = Utf8(Ask("Text: "));
        byte[] key = Utf8(Ask("Schlüssel/Passwort: "));
        var cipher = new EncryptThenMacCipher(new ChaCha20(), new HmacSha256());
        byte[] blob = cipher.Encrypt(key, pt);
        Console.WriteLine("Blob (base64): " + Convert.ToBase64String(blob));
        Console.WriteLine("Entschlüsselt: " + Encoding.UTF8.GetString(cipher.Decrypt(key, blob)));
    }
}
