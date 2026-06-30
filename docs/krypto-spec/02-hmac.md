# Mathe-Spec 02 — HMAC-SHA256

Quelle/Norm: **RFC 2104** und **FIPS 198-1**. HMAC ist ein Message Authentication Code. Er nimmt einen Schlüssel und eine Nachricht und liefert einen 32-Byte-Tag, mit dem sich Integrität und Echtheit prüfen lassen. Baut direkt auf deinem SHA-256 auf.

Den C#-Code schreibst du selbst. Hier stehen Mathematik, Ablauf und Testvektoren.

---

## 1. Die Idee

HMAC hasht die Nachricht zweimal, jeweils mit dem Schlüssel vermischt. Die Formel:

```
HMAC(K, m) = H( (K' XOR opad) || H( (K' XOR ipad) || m ) )
```

- `H` ist SHA-256.
- `||` heisst aneinanderhängen (Konkatenation).
- `K'` ist der auf Blockgrösse gebrachte Schlüssel (siehe unten).
- `ipad` und `opad` sind feste Füllmuster.

Das doppelte Hashen (innen und aussen) ist kein Zufall. Es schützt vor Angriffen, die bei einem einfachen `H(K || m)` möglich wären (Length-Extension).

## 2. Konstanten

- **B = 64** Byte. Das ist die Blockgrösse von SHA-256, nicht die Ausgabelänge.
- **ipad** = das Byte `0x36`, 64-mal.
- **opad** = das Byte `0x5c`, 64-mal.
- Ausgabe = 32 Byte.

## 3. Schlüssel auf Blockgrösse bringen (K')

Der Schlüssel muss am Ende genau **64 Byte** lang sein:

1. Ist der Schlüssel **länger** als 64 Byte: zuerst `SHA-256(key)` rechnen. Das ergibt 32 Byte.
2. Ist der Schlüssel **64 Byte oder kürzer**: so lassen.
3. Danach rechts mit Nullen auf genau 64 Byte auffüllen.

Das Ergebnis ist `K'` (64 Byte).

## 4. Berechnung

```
ipadKey = K' XOR ipad        // 64 Byte, jedes Byte mit 0x36 ge-XOR-t
opadKey = K' XOR opad        // 64 Byte, jedes Byte mit 0x5c ge-XOR-t

inner  = SHA-256( ipadKey || message )      // erst Schlüssel-Block, dann Nachricht
result = SHA-256( opadKey || inner )        // erst Schlüssel-Block, dann der innere Hash
```

`result` ist der 32-Byte-Tag.

## 5. Verify (constant-time)

Beim Prüfen rechnest du den Tag neu und vergleichst ihn mit dem erwarteten.

Wichtig: der Vergleich muss **constant-time** sein. Nicht beim ersten unterschiedlichen Byte abbrechen, sonst verrät die Laufzeit, wie viele Bytes gestimmt haben. Stattdessen alle Bytes durchgehen und die Unterschiede mit OR aufsammeln:

```
diff = 0
für jedes Byte-Paar (a, b):
    diff = diff | (a XOR b)
gleich, wenn diff == 0 am Ende
```

Vorher die Längen vergleichen. Sind sie verschieden, ist es sowieso ungleich.

## 6. Testvektoren (RFC 4231, zum Selbstprüfen)

| Schlüssel | Nachricht | HMAC-SHA256 (hex) |
|---|---|---|
| `0x0b` × 20 | `"Hi There"` | `b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7` |
| `"Jefe"` | `"what do ya want for nothing?"` | `5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843` |
| `0xaa` × 131 | `"Test Using Larger Than Block-Size Key - Hash Key First"` | `60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54` |

Der dritte Fall ist wichtig. Der Schlüssel ist länger als 64 Byte und muss zuerst gehasht werden. So prüfst du den Pfad aus Abschnitt 3.

Zusätzlich: Quervergleich gegen `System.Security.Cryptography.HMACSHA256` mit zufälligen Schlüsseln und Nachrichten.

## 7. Empfohlene Reihenfolge

1. Schlüssel auf `K'` bringen (mit dem langen Schlüssel separat testen).
2. Zwei kleine Helfer: zwei Byte-Arrays aneinanderhängen, und ein Array byteweise mit einem festen Wert XOR-en.
3. Inner-Hash, dann Outer-Hash.
4. Testvektoren in dieser Reihenfolge: TC1, TC2, dann TC6 (langer Schlüssel).
5. Verify mit dem constant-time Vergleich.

Stolperfallen: `K'` nicht genau 64 Byte. Reihenfolge bei der Konkatenation verdreht (erst Schlüssel-Block, dann Nachricht). XOR mit dem falschen Pad.

## 8. Schnittstelle

Aus dem Design: `IMac` mit `ComputeMac(key, message)` und `Verify(key, message, expectedMac)`. `MacSizeInBytes` ist 32. `Verify` nutzt den constant-time Vergleich aus Abschnitt 5.
