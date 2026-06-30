# Mathe-Spec 04 — AES-256

Quelle/Norm: **FIPS 197**. AES ist eine Block-Chiffre. Sie verschlüsselt einen festen **16-Byte-Block** mit einem Schlüssel. Bei AES-256 ist der Schlüssel **32 Byte** und es gibt **14 Runden**.

Den C#-Code schreibst du selbst. Hier stehen die Mathematik, der Ablauf und die geprüften Tabellen.

> **Umfang:** Wir bauen vorerst nur die **Verschlüsselung** eines Blocks. Das reicht für die Library (sie nutzt später den CTR-Modus, der nur die Vorwärtsrichtung braucht) und für die ECB- und CBC-Demos im Labor. Die Entschlüsselung (inverse S-Box, InvMixColumns) bauen wir nur, falls wir sie fürs Labor brauchen.

---

## 1. Der State

AES arbeitet auf einem **4×4-Byte-Raster**, dem State. Die 16 Eingabe-Bytes werden **spaltenweise** eingefüllt:

```
state[zeile][spalte] = input[4*spalte + zeile]
```
Also gehen `input[0..3]` in die erste Spalte (von oben nach unten), `input[4..7]` in die zweite, und so weiter. Beim Ausgeben dieselbe Reihenfolge rückwärts: `output[4*spalte + zeile] = state[zeile][spalte]`.

Diese spaltenweise Anordnung ist eine häufige Fehlerquelle. Präg sie dir ein.

## 2. Die Mathematik: GF(2^8)

AES rechnet mit Bytes als Elementen des endlichen Körpers GF(2^8). Addition ist einfach **XOR**. Die Multiplikation ist der interessante Teil, aber für die Verschlüsselung brauchst du nur die Multiplikation mit **2** und **3**.

**Mal 2 (`xtime`):** Ein Linksshift um 1. Wenn dabei oben ein Bit rausfällt (das alte Bit 7 war gesetzt), XOR mit `0x1b`. Das `0x1b` ist das AES-Reduktionspolynom.
```
xtime(a) = (a << 1) , und wenn (a & 0x80) != 0 dann XOR 0x1b , alles auf 8 Bit (& 0xFF)
```
Prüfwerte: `xtime(0x57) = 0xae`, `xtime(0x80) = 0x1b`.

**Mal 3:** `3·a = (2·a) XOR a`, also `xtime(a) ^ a`.

Mehr brauchst du für die Verschlüsselung nicht.

## 3. Die vier Operationen

**SubBytes:** jedes Byte des State durch die S-Box ersetzen, `state[r][c] = SBOX[state[r][c]]`. Die S-Box steht in Abschnitt 6.

**ShiftRows:** jede Zeile zyklisch nach links rotieren, um ihre Zeilennummer. Zeile 0 bleibt, Zeile 1 um 1, Zeile 2 um 2, Zeile 3 um 3.
```
Zeile 1: [a,b,c,d] -> [b,c,d,a]
Zeile 2: [a,b,c,d] -> [c,d,a,b]
Zeile 3: [a,b,c,d] -> [d,a,b,c]
```

**MixColumns:** jede Spalte `[a0,a1,a2,a3]` einzeln neu berechnen (alle `·` sind GF-Multiplikation, alle `+` sind XOR):
```
b0 = 2·a0 ^ 3·a1 ^   a2 ^   a3
b1 =   a0 ^ 2·a1 ^ 3·a2 ^   a3
b2 =   a0 ^   a1 ^ 2·a2 ^ 3·a3
b3 = 3·a0 ^   a1 ^   a2 ^ 2·a3
```
Mit `xtime` für `2·` und `xtime(x) ^ x` für `3·`.

**AddRoundKey:** den State mit dem Rundenschlüssel XOR-en. Rundenschlüssel `r` sind die Wörter `W[4*r]` bis `W[4*r+3]` aus der Schlüsselexpansion. Spalte `c` wird mit Wort `W[4*r + c]` ge-XOR-t: `state[zeile][c] ^= W[4*r + c][zeile]`.

## 4. Schlüsselexpansion (AES-256)

Aus dem 32-Byte-Schlüssel werden **60 Wörter** zu je 4 Byte erzeugt (`W[0..59]`). Daraus ergeben sich 15 Rundenschlüssel zu je 16 Byte.

- `W[0..7]` sind direkt der Schlüssel (8 Wörter zu 4 Byte).
- Für `i = 8` bis `59`:
  ```
  temp = W[i-1]
  wenn i mod 8 == 0:   temp = SubWord(RotWord(temp)) XOR Rcon[i/8]
  sonst wenn i mod 8 == 4:   temp = SubWord(temp)
  W[i] = W[i-8] XOR temp
  ```
- `RotWord([a,b,c,d]) = [b,c,d,a]`.
- `SubWord([a,b,c,d]) = [SBOX[a], SBOX[b], SBOX[c], SBOX[d]]`.
- `Rcon[j]` ist `[RC[j], 0, 0, 0]`, du XOR-st also nur das erste Byte. Die `RC`-Werte stehen in Abschnitt 6.

Achtung, AES-256-spezifisch: der zweite Fall `i mod 8 == 4` (ein zusätzliches SubWord ohne RotWord). AES-128 hat den nicht. Leicht zu vergessen.

## 5. Ablauf der Verschlüsselung

```
state = input
AddRoundKey(state, Runde 0)

für Runde = 1 bis 13:
    SubBytes(state)
    ShiftRows(state)
    MixColumns(state)
    AddRoundKey(state, Runde)

SubBytes(state)
ShiftRows(state)
AddRoundKey(state, Runde 14)     // letzte Runde OHNE MixColumns

output = state
```

Die letzte Runde hat **kein** MixColumns. Das ist Absicht, nicht vergessen.

## 6. Tabellen (verifiziert)

### S-Box
```
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
```
Das ist ein flaches 256-Byte-Array, `SBOX[byte]` gibt das ersetzte Byte. Du kannst es auch selbst berechnen (multiplikatives Inverses in GF(2^8) plus affine Transformation), aber die Tabelle direkt zu nehmen ist üblich und fehlerfrei.

### Rcon (RC-Bytes für die Schlüsselexpansion)
```
0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40
```
Das ist `RC[1]` bis `RC[7]`. Bei `i/8 = 1` nimmst du den ersten, und so weiter.

## 7. Testvektor (FIPS 197, Anhang C.3)

```
Schlüssel:   000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f   (32 Byte)
Klartext:    00112233445566778899aabbccddeeff                                   (16 Byte)
Ciphertext:  8ea2b7ca516745bfeafc49904b496089
```

Zusätzlich Quervergleich gegen `System.Security.Cryptography.Aes` im ECB-Modus mit zufälligen Schlüsseln und Blöcken.

## 8. Empfohlene Reihenfolge

1. `xtime` und die GF-Mal-3-Hilfe. Prüfen: `xtime(0x57) == 0xae`.
2. State laden und ausgeben (spaltenweise). Lade einen Block, gib ihn unverändert wieder aus, vergleich mit dem Original.
3. Die vier Operationen einzeln: SubBytes, ShiftRows, MixColumns, AddRoundKey.
4. Schlüsselexpansion (mit dem `i mod 8 == 4`-Fall).
5. Den Rundenablauf zusammensetzen.
6. Gegen den FIPS-197-Vektor testen, dann der Quervergleich.

Stolperfallen: State spaltenweise laden, nicht zeilenweise. Letzte Runde ohne MixColumns. Den `i mod 8 == 4`-Fall in der Schlüsselexpansion. ShiftRows nach links, nicht rechts.

## 9. Schnittstelle

AES selbst ist erstmal nur die Block-Funktion (16 Byte rein, 16 Byte raus). Die öffentliche `ISymmetricCipher`-API kommt später, wenn wir AES im CTR-Modus mit Encrypt-then-MAC zusammenbauen.
