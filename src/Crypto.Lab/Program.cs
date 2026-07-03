using System.Text;

namespace Crypto.Lab;

// Interaktive Demo der Krypto-Library. Nur das Menü, die Logik steckt in Demos und AttackLab.
internal static class Program
{
    private static void Main()
    {
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
            Console.WriteLine("7  Angriffs-Labor (warum man Krypto nicht selbst rollt)");
            Console.WriteLine("0  Beenden");
            Console.Write("Auswahl: ");

            switch (Console.ReadLine())
            {
                case "1": Demos.Sha256Demo(); break;
                case "2": Demos.HmacDemo(); break;
                case "3": Demos.Pbkdf2Demo(); break;
                case "4": Demos.AesDemo(); break;
                case "5": Demos.ChaChaDemo(); break;
                case "6": Demos.AuthDemo(); break;
                case "7": AttackLab.Run(); break;
                case "0": return;
                default: Console.WriteLine("Ungültige Auswahl."); break;
            }
        }
    }
}
