using System.Security.Cryptography;
using System.Text;
using Crypto.Core;

// Interaktive Demo der Krypto-Library.
// Menü wählen, Eingaben machen, konkrete Ausgaben prüfen.
// SHA-256 und HMAC sind deterministisch und lassen sich gegen Online-Tools prüfen.
// AES und ChaCha20 nehmen pro Aufruf einen zufälligen Schlüssel, darum wird er mit ausgegeben.

Console.OutputEncoding = Encoding.UTF8;

while (true)
{
    Console.WriteLine();
    Console.WriteLine("=== Krypto-Library Demo ===");
    Console.WriteLine("1  SHA-256 Hash");
    Console.WriteLine("2  HMAC-SHA256");
    Console.WriteLine("3  PBKDF2 (Passwort-Hash und Prüfung)");
    Console.WriteLine("4  AES-256 (ein 16-Byte-Block)");
    Console.WriteLine("5  ChaCha20 (Verschlüsselung und Round-Trip)");
    Console.WriteLine("6  Authentifizierte Verschlüsselung (Encrypt-then-MAC)");
    Console.WriteLine("0  Beenden");
    Console.Write("Auswahl: ");

    switch (Console.ReadLine())
    {
        case "1": Sha256Demo(); break;
        case "2": HmacDemo(); break;
        case "3": Pbkdf2Demo(); break;
        case "4": AesDemo(); break;
        case "5": ChaChaDemo(); break;
        case "6": AuthDemo(); break;
        case "0": return;
        default: Console.WriteLine("Ungültige Auswahl."); break;
    }
}

static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
static string Ask(string label) { Console.Write(label); return Console.ReadLine() ?? ""; }

static void Sha256Demo()
{
    byte[] hash = new Sha256().Hash(Utf8(Ask("Text: ")));
    Console.WriteLine("SHA-256: " + Hex(hash));
}

static void HmacDemo()
{
    byte[] key = Utf8(Ask("Schlüssel: "));
    byte[] msg = Utf8(Ask("Nachricht: "));
    Console.WriteLine("HMAC-SHA256: " + Hex(new HmacSha256().ComputeMac(key, msg)));
}

static void Pbkdf2Demo()
{
    var hasher = new Pbkdf2();
    string stored = hasher.Hash(Ask("Passwort: "));
    Console.WriteLine("Gespeicherter Hash: " + stored);
    bool ok = hasher.Verify(Ask("Passwort zum Prüfen: "), stored);
    Console.WriteLine("Passwort stimmt: " + ok);
}

static void AesDemo()
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

static void ChaChaDemo()
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

static void AuthDemo()
{
    byte[] pt = Utf8(Ask("Text: "));
    byte[] key = Utf8(Ask("Schlüssel/Passwort: "));
    var cipher = new EncryptThenMacCipher(new ChaCha20(), new HmacSha256());
    byte[] blob = cipher.Encrypt(key, pt);
    Console.WriteLine("Blob (base64): " + Convert.ToBase64String(blob));
    Console.WriteLine("Entschlüsselt: " + Encoding.UTF8.GetString(cipher.Decrypt(key, blob)));
}
