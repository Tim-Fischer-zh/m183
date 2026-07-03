# Mathe-Spec 05 — ChaCha20

Quelle/Norm: **RFC 8439**. ChaCha20 ist eine Stream-Cipher. Aus Schlüssel, Nonce und einem Zähler erzeugt sie einen 64-Byte-Keystream-Block. Verschlüsseln heisst dann einfach: Klartext XOR Keystream. Es gibt nur drei Operationen auf 32-Bit-Wörtern: Addition (mod 2^32), Rotation und XOR. Daher der Name ARX (Add, Rotate, XOR). Kein Galois-Feld, keine Tabellen.

Den C#-Code schreibst du selbst. Hier stehen Mathematik, Ablauf und Testvektoren.

> **Wichtig, anders als SHA-256:** ChaCha20 ist durchgehend **little-endian**. Beim Einlesen von Schlüssel und Nonce und beim Ausgeben der Wörter. SHA-256 war big-endian. Das ist die häufigste Fehlerquelle hier.

---

## 1. Der State: 16 Wörter (4×4)

Der State sind 16 `uint`-Wörter, angeordnet als 4×4-Raster, aber am einfachsten als flaches `uint[16]`:

```
 0: konst   1: konst   2: konst   3: konst
 4: key     5: key     6: key     7: key
 8: key     9: key    10: key    11: key
12: zähler 13: nonce  14: nonce  15: nonce
```

- **Wörter 0-3:** feste Konstanten (das ist der ASCII-Text „expand 32-byte k" als vier little-endian Wörter):
  ```
  0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
  ```
- **Wörter 4-11:** der 32-Byte-Schlüssel als 8 Wörter, **little-endian** gelesen.
- **Wort 12:** der 32-Bit-Blockzähler.
- **Wörter 13-15:** die 12-Byte-Nonce als 3 Wörter, **little-endian**.

## 2. Little-endian lesen und schreiben

Vier Bytes zu einem Wort (niederwertigstes Byte zuerst):
```
wort = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
```
Ein Wort zu vier Bytes:
```
b0 = wort & 0xFF,  b1 = (wort >> 8) & 0xFF,  b2 = (wort >> 16) & 0xFF,  b3 = (wort >> 24) & 0xFF
```
Das ist genau die umgekehrte Byte-Reihenfolge zu SHA-256.

## 3. Die Quarter-Round

Der Kern. Sie nimmt vier Wörter des States (über Indizes `a, b, c, d`) und mischt sie. Alle `+` sind mod 2^32, `<<<` ist Rotation nach **links**:

```
a += b;   d ^= a;   d = RotL(d, 16);
c += d;   b ^= c;   b = RotL(b, 12);
a += b;   d ^= a;   d = RotL(d, 8);
c += d;   b ^= c;   b = RotL(b, 7);
```

`RotL(x, n) = (x << n) | (x >> (32 - n))`. Das ist dein `RotR` gespiegelt, nur die Richtung ist andersrum.

## 4. Die 20 Runden

Es sind 20 Runden, aufgeteilt in 10 Durchgänge zu je zwei Runden. Ein Durchgang ist eine **Spalten-Runde** gefolgt von einer **Diagonal-Runde**. Also 10-mal folgendes:

```
// Spalten
QuarterRound(0, 4,  8, 12)
QuarterRound(1, 5,  9, 13)
QuarterRound(2, 6, 10, 14)
QuarterRound(3, 7, 11, 15)
// Diagonalen
QuarterRound(0, 5, 10, 15)
QuarterRound(1, 6, 11, 12)
QuarterRound(2, 7,  8, 13)
QuarterRound(3, 4,  9, 14)
```

Die Quarter-Round verändert den State direkt an den vier Indizes.

## 5. Abschluss des Blocks

Vor den Runden machst du eine **Kopie** des initialen States. Nach den 20 Runden addierst du diese Kopie wieder dazu, wortweise mod 2^32:
```
für i = 0..15:  out[i] = working[i] + initial[i]
```
Dann serialisierst du die 16 Wörter little-endian zu **64 Byte**. Das ist der Keystream-Block.

## 6. Verschlüsselung

Für jeden 64-Byte-Abschnitt des Klartexts:
```
keystream = Block(key, zähler, nonce)
ciphertext_block = klartext_block XOR keystream
zähler = zähler + 1
```
Der Zähler zählt pro Block hoch. Beim letzten, evtl. kürzeren Abschnitt XOR-st du nur so viele Keystream-Bytes wie Klartext da ist. Entschlüsseln ist identisch, weil XOR seine eigene Umkehrung ist.

## 7. Testvektoren (RFC 8439, verifiziert)

**Block-Funktion (§2.3.2):**
```
Schlüssel: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Zähler:    1
Nonce:     000000090000004a00000000
Keystream: 10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e
           d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e
```

**Verschlüsselung (§2.4.2):**
```
Schlüssel: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Zähler:    1 (Startwert)
Nonce:     000000000000004a00000000
Klartext:  "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
Cipher:    6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b ... (volle 114 Byte in der RFC)
```

Zusätzlich Quervergleich gegen `System.Security.Cryptography.ChaCha20Poly1305` ist nicht direkt möglich (das ist AEAD, nicht die reine Chiffre). Der RFC-Block-Vektor ist der zuverlässigste Test.

## 8. Empfohlene Reihenfolge

1. `RotL` (dein `RotR` gespiegelt). Test: `RotL(0x00000001, 8) == 0x00000100`.
2. `QuarterRound` auf einem `uint[16]` über vier Indizes.
3. Die Block-Funktion: State aufbauen, Kopie sichern, 10 Durchgänge, dazu-addieren, little-endian serialisieren. Gegen den Keystream aus §2.3.2 testen.
4. Die Verschlüsselung: über die Blöcke laufen, XOR, Zähler hochzählen. Gegen §2.4.2 testen.

Stolperfallen: little-endian statt big-endian. RotL statt RotR. Die Kopie des States vor den Runden vergessen (dann kannst du am Schluss nichts dazu-addieren). Die Index-Tupel der Diagonal-Runde.

## 9. Schnittstelle

ChaCha20 selbst ist die Block- und die Verschlüsselungs-Funktion. Die öffentliche `ISymmetricCipher`-API kommt später, wenn du ChaCha20 (oder AES) mit Encrypt-then-MAC zur authentifizierten Verschlüsselung zusammenbaust.
