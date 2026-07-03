using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Crypto.Core;
using static Crypto.Lab.LabHelpers;

namespace Crypto.Lab;

// Angriffs-Labor (Erweiterung, KI-generiert). Jeder Angriff führt eine echte Attacke aus
// und zeigt danach die Gegenmassnahme, die die Library umsetzt.
internal static class AttackLab
{
    public static void Run()
    {
        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("=== Angriffs-Labor ===");
            Console.WriteLine("1  AES-ECB verrät Muster (der ECB-Pinguin)");
            Console.WriteLine("2  Nonce-Wiederverwendung bei ChaCha20");
            Console.WriteLine("3  Brute-Force gegen einen SHA-256-Passwort-Hash");
            Console.WriteLine("0  Zurück");
            Console.Write("Auswahl: ");

            switch (Console.ReadLine())
            {
                case "1": Ecb(); break;
                case "2": NonceReuse(); break;
                case "3": BruteForce(); break;
                case "0": return;
                default: Console.WriteLine("Ungültige Auswahl."); break;
            }
        }
    }

    // ECB verschlüsselt jeden Block einzeln und gleich. Gleiche Klartext-Blöcke
    // ergeben gleiche Ciphertext-Blöcke, die Struktur leakt.
    private static void Ecb()
    {
        Console.WriteLine();
        Console.WriteLine("--- AES-ECB verrät Muster ---");

        var aes = new Aes256();
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] blockA = Utf8("GEHEIM_GEHEIM_16");          // genau 16 Bytes
        byte[] plaintext = blockA.Concat(blockA).ToArray(); // Block 1 == Block 2

        byte[] c1 = aes.EncryptBlock(key, plaintext.AsSpan(0, 16));
        byte[] c2 = aes.EncryptBlock(key, plaintext.AsSpan(16, 16));

        Console.WriteLine("Klartext-Block 1:   " + Hex(plaintext[..16]));
        Console.WriteLine("Klartext-Block 2:   " + Hex(plaintext[16..]));
        Console.WriteLine("Ciphertext-Block 1: " + Hex(c1));
        Console.WriteLine("Ciphertext-Block 2: " + Hex(c2));
        Console.WriteLine("Beide Ciphertext-Blöcke identisch? " + (Hex(c1) == Hex(c2)));
        Console.WriteLine();
        Console.WriteLine("Der Angreifer sieht die Struktur ohne den Schlüssel. So entsteht der ECB-Pinguin.");
        Console.WriteLine();

        var safe = new EncryptThenMacCipher(new ChaCha20(), new HmacSha256());
        Console.WriteLine("Gegenmassnahme (authentifizierte Verschlüsselung mit frischer Nonce):");
        Console.WriteLine("  " + Convert.ToBase64String(safe.Encrypt(key, plaintext)));
        Console.WriteLine("  Dieselben Klartext-Blöcke, keine erkennbaren Muster mehr.");
    }

    // Dieselbe Nonce zweimal mit demselben Schlüssel heisst derselbe Keystream.
    // Dann gilt c1 XOR c2 = p1 XOR p2, und der Schlüssel fällt raus.
    private static void NonceReuse()
    {
        Console.WriteLine();
        Console.WriteLine("--- Nonce-Wiederverwendung bei ChaCha20 ---");

        var cipher = new ChaCha20();
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);   // DIESELBE Nonce für beide, der Fehler

        byte[] p1 = Utf8("Treffen um Mitternacht!!!!");
        byte[] p2 = Utf8("Das Passwort lautet: 1234!");       // gleich lang wie p1

        byte[] c1 = cipher.Encrypt(key, nonce, p1);
        byte[] c2 = cipher.Encrypt(key, nonce, p2);

        // Angreifer kennt p1 und rekonstruiert p2 ohne Schlüssel: p2 = c1 XOR c2 XOR p1
        byte[] recovered = new byte[p2.Length];
        for (int i = 0; i < p2.Length; i++)
            recovered[i] = (byte)(c1[i] ^ c2[i] ^ p1[i]);

        Console.WriteLine("Bekannter Klartext p1: " + Encoding.ASCII.GetString(p1));
        Console.WriteLine("Geheimer Klartext p2:  " + Encoding.ASCII.GetString(p2));
        Console.WriteLine("Rekonstruiertes p2:    " + Encoding.ASCII.GetString(recovered));
        Console.WriteLine();
        Console.WriteLine("Der geheime Text wurde ohne Schlüssel wiederhergestellt.");
        Console.WriteLine("Gegenmassnahme: pro Nachricht eine frische Nonce. Genau das macht die");
        Console.WriteLine("authentifizierte Verschlüsselung automatisch.");
    }

    // Echter Brute-Force: alle Kleinbuchstaben-Passwörter der Länge 4 durchprobieren,
    // bis der gestohlene SHA-256-Hash matcht.
    private static void BruteForce()
    {
        Console.WriteLine();
        Console.WriteLine("--- Brute-Force gegen einen SHA-256-Passwort-Hash ---");
        Console.WriteLine("SHA-256 ist schnell. Wir probieren alle Kleinbuchstaben-Passwörter der");
        Console.WriteLine("Länge 4 durch, bis der Hash passt. Das ist ein echter Angriff, kein Hinweis.");
        Console.WriteLine();

        var sha = new Sha256();
        const string secret = "code";
        string targetHex = Hex(sha.Hash(Utf8(secret)));
        Console.WriteLine("Gestohlener Hash: " + targetHex);
        Console.WriteLine("Brute-Force läuft...");

        const string charset = "abcdefghijklmnopqrstuvwxyz";
        const int length = 4;
        long total = 1;
        for (int i = 0; i < length; i++) total *= charset.Length;

        var sw = Stopwatch.StartNew();
        string? found = null;
        long tries = 0;
        char[] candidate = new char[length];
        for (long n = 0; n < total; n++)
        {
            long x = n;
            for (int i = length - 1; i >= 0; i--)
            {
                candidate[i] = charset[(int)(x % charset.Length)];
                x /= charset.Length;
            }
            tries++;
            if (Hex(sha.Hash(Utf8(new string(candidate)))) == targetHex)
            {
                found = new string(candidate);
                break;
            }
        }
        sw.Stop();

        double seconds = sw.Elapsed.TotalSeconds;
        double perHashMs = sw.Elapsed.TotalMilliseconds / tries;
        Console.WriteLine();
        Console.WriteLine($"Geknackt: \"{found}\"");
        Console.WriteLine($"Versuche: {tries:N0}   Dauer: {seconds:F2} s   Rate: {tries / Math.Max(seconds, 0.001):N0} Hashes/s");
        Console.WriteLine();

        // Gegenmassnahme: PBKDF2. Jeder einzelne Versuch wird absichtlich teuer.
        var pbkdf2 = new Pbkdf2();
        var sw2 = Stopwatch.StartNew();
        pbkdf2.Hash(secret);
        sw2.Stop();
        double pbkdf2Ms = sw2.Elapsed.TotalMilliseconds;
        double projectedSeconds = tries * pbkdf2Ms / 1000.0;

        Console.WriteLine("Gegenmassnahme PBKDF2 (gesalzen, viele Iterationen):");
        Console.WriteLine($"  Ein PBKDF2-Hash dauert {pbkdf2Ms:F1} ms statt {perHashMs:F4} ms bei SHA-256.");
        Console.WriteLine($"  Das ist rund {pbkdf2Ms / Math.Max(perHashMs, 0.0001):N0} mal langsamer pro Versuch.");
        Console.WriteLine($"  Derselbe Brute-Force würde mit PBKDF2 etwa {FormatDuration(projectedSeconds)} dauern.");
        Console.WriteLine("  Und der Salt macht vorberechnete Tabellen wertlos.");
    }

    private static string FormatDuration(double seconds)
    {
        if (seconds < 60) return $"{seconds:F0} Sekunden";
        if (seconds < 3600) return $"{seconds / 60:F0} Minuten";
        if (seconds < 86400) return $"{seconds / 3600:F1} Stunden";
        return $"{seconds / 86400:F1} Tage";
    }
}
