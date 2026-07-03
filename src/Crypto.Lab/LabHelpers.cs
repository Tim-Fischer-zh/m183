using System.Text;

namespace Crypto.Lab;

// Kleine Konsolen-Helfer, die Demos und AttackLab gemeinsam nutzen.
internal static class LabHelpers
{
    public static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    public static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    public static string Ask(string label)
    {
        Console.Write(label);
        return Console.ReadLine() ?? "";
    }
}
