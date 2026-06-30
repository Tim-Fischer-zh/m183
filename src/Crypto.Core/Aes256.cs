namespace Crypto.Core;

public class Aes256
{
    // S-Box (FIPS 197), Substitutions-Tabelle für SubBytes. Verifizierte Normwerte.
    private static readonly byte[] Sbox =
    {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    };

    // Rundenkonstanten für die Schluesselexpansion: RC[1..7], jeweils das erste Byte des Rcon-Worts.
    private static readonly byte[] Rcon = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40 };

    private static byte XTime(byte a)
    {
        //a = 1001_0000 = (7tes bit gesetzt (1 ...)) 
        // 0x80 = 1000_0000 = auch 7 bit gesetzt = 128
        /*
         *  shift a um 1 nach links dann geht 7 bit weg, das muss man prüfen
         */
        int result = a << 1;
        if ((a & 0x80) != 0)   //prüft, ob nach dem shift das bit weg ist 
            result ^= 0x1b; 
        return (byte)result; 
    }

    private static void SubBytes(byte[,] state)
    {
        /*
         * Ersetzt jedes Byte des States durch seinen S-Box-Wert (Substitution)
         */
        // 2 Dimensional Array deswegen 2 For Schleifen
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                state[i, j] = Sbox[state[i,j]];
            }
        }
    }

    private static void ShiftRows(byte[,] state)
    {
        /*
         * Rotiert jede Zeile zyklisch nach links um ihre Zeilennummer (verteilt die Bytes über die Spalten)
         */
        for (int i = 1; i < 4; i++)
        {
            byte[] temp = new byte[4];
            for (int j = 0; j < 4; j++)
            {
                temp[j] = state[i, j];
            }
            for (int j = 0; j < 4; j++)
            {
                state[i, j] = temp[(j + i) % 4];
            }
            
        }
    }

    private static void AddRoundKey(byte[,] state, byte[][] schedule, int round)
    {
        /*
         * Der Rundenschlüssel kommt aus der Schlüsselexpansion. Die liefert 60 Wörter zu 4 Byte (byte[][]).
         * Pro Runde nutzt man vier Wörter, darum übergibt man den ganzen Schedule plus die Rundennummer
         */

        for (int c = 0; c < 4; c++)
        {
            for (int r = 0; r < 4; r++)
            {
                state[r, c ] ^= schedule[4 * round + c][r];
            }
        }
    }

    private static void MixColumns(byte[,] state)
    {
        /*
         * Mischt jede Spalte im Galois-Feld GF(2^8) (verteilt jedes Byte über die ganze Spalte).
         */
        for (int c = 0; c < 4; c++)
        {
            /*
             * a0          (1·a0)
             * XTime(a1)   (2·a1)
             * XTime(a2)^a2 (3·a2)
             * a3          (1·a3)
             */
            /*
             *  b0 = 2·a0 ^ 3·a1 ^   a2 ^   a3
             *  b1 =   a0 ^ 2·a1 ^ 3·a2 ^   a3
             *  b2 =   a0 ^   a1 ^ 2·a2 ^ 3·a3
             *  b3 = 3·a0 ^   a1 ^   a2 ^ 2·a3
             */
            byte a0 = state[0,c], a1 = state[1, c], a2 = state[2, c],  a3 = state[3, c];
            /*b0*/state[0, c] = (byte)(XTime(a0) ^ (XTime(a1) ^ a1) ^ a2 ^ a3);
            /*b1*/state[1, c] = (byte)(a0 ^ XTime(a1) ^ (XTime(a2) ^ a2) ^ a3);
            /*b2*/state[2, c] = (byte)(a0 ^ a1 ^ XTime(a2) ^ XTime(a3) ^ a3);
            /*b3*/state[3, c] = (byte)((XTime(a0) ^ a0) ^ a1 ^ a2 ^ XTime(a3));
        }
    }

    private static byte[] SubWord(byte[] w)
    {
        return [Sbox[w[0]], Sbox[w[1]], Sbox[w[2]], Sbox[w[3]]];
    }
    private static byte[] RotWord(byte[] w)
    {
        return [w[1], w[2], w[3], w[0]];
    }

    private static byte[][] KeyExpansion(byte[] key)
    {
        byte[][] w = new byte[60][];
        for (int i = 0; i < 8; i++)
        {
            w[i] = new byte[] {key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]};
        }

        for (int i = 8; i < 60; i++)
        {
            byte[] temp = w[i - 1];

            if (i % 8 == 0)
            {
                temp = SubWord(RotWord(temp));
                temp[0] ^= Rcon[i / 8 - 1];
            }
            else if (i % 8 == 4)
            {
                temp = SubWord(temp);
            }

            byte[] next = new byte[4];
            for (int k = 0; k < 4; k++)
                next[k] = (byte)(w[i - 8][k] ^ temp[k]);
            w[i] = next;
        }
        return w;
    }
    
    public static byte[] EncryptBlock(byte[] input, byte[] key)
    {
        byte[][] schedule = KeyExpansion(key);

        // State spaltenweise laden: state[zeile, spalte] = input[4*spalte + zeile]
        byte[,] state = new byte[4, 4];
        for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            state[r, c] = input[4 * c + r];

        AddRoundKey(state, schedule, 0); // Runde 0

        for (int round = 1; round <= 13; round++) // Runden 1 bis 13
        {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, schedule, round);
        }

        SubBytes(state); // letzte Runde (14)
        ShiftRows(state);
        AddRoundKey(state, schedule, 14); // OHNE MixColumns

        // State spaltenweise ausgeben
        byte[] output = new byte[16];
        for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            output[4 * c + r] = state[r, c];

        return output;
    }
}