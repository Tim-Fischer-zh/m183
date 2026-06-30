# Mathe-Spec 03 — PBKDF2

Quelle/Norm: **RFC 8018** (PKCS #5 v2.1). PBKDF2 macht aus einem Passwort einen abgeleiteten Schlüssel. Wir nutzen es als Passwort-Hash. Es baut direkt auf deinem HMAC auf.

Den C#-Code schreibst du selbst. Hier stehen Mathematik, Ablauf und Testvektoren.

---

## 1. Wozu

Passwörter darf man nicht einfach mit SHA-256 hashen. SHA-256 ist schnell, also lässt sich ein gestohlener Hash per Brute-Force mit Milliarden Versuchen pro Sekunde knacken. PBKDF2 dreht das um:

- **Langsam mit Absicht.** Es wendet HMAC sehr oft an (Iterationszahl `c`). Das bremst den Angreifer.
- **Gesalzen.** Ein zufälliger Salt pro Passwort verhindert Rainbow Tables und macht gleiche Passwörter unterscheidbar.

## 2. Bausteine

- PRF (die Mischfunktion) = **HMAC-SHA256**, also dein `HmacSha256`.
- `hLen` = 32 Byte, die Ausgabelänge von HMAC-SHA256.
- Eingaben: Passwort `P`, Salt `S`, Iterationszahl `c`, gewünschte Länge `dkLen`.

## 3. Der Kern: ein Block

Für `dkLen <= 32` (ein Block) ist es überschaubar:

```
U1 = HMAC(P, S || INT(1))        // INT(1) = die Zahl 1 als 4-Byte big-endian, an den Salt gehängt
U2 = HMAC(P, U1)
U3 = HMAC(P, U2)
...
Uc = HMAC(P, U(c-1))

T1 = U1 XOR U2 XOR U3 XOR ... XOR Uc
```

Drei Dinge, die man leicht verdreht:
- Das **Passwort ist immer der HMAC-Schlüssel**, in jeder Iteration.
- Die **Nachricht** ist beim ersten Mal `Salt + Zähler`, danach das **vorige `U`**.
- Du XOR-st **alle** `c` Ergebnisse zusammen, nicht nur das letzte.

`T1`, auf `dkLen` Byte gekürzt, ist das Resultat.

## 4. Mehrere Blöcke (für dkLen > 32)

Brauchst du mehr als 32 Byte, machst du mehrere Blöcke. `l = aufrunden(dkLen / 32)`. Jeder Block `i` (1-basiert) läuft wie oben, nur mit `INT(i)` statt `INT(1)`:

```
Ti = U1 XOR ... XOR Uc       mit   U1 = HMAC(P, S || INT(i))

DK = T1 || T2 || ... || Tl   auf dkLen Byte gekürzt
```

`INT(i)` ist der Blockindex als **4-Byte big-endian**. Der Zähler startet bei **1**, nicht bei 0.

## 5. Als Passwort-Hash verwenden

Fürs Passwort-Hashing reicht `dkLen = 32`, also ein Block.

- **Hash:** zufälligen Salt erzeugen (z. B. 16 Byte aus `RandomNumberGenerator`), PBKDF2 mit einer hohen Iterationszahl rechnen, dann Algorithmus, Iterationszahl, Salt und Hash in einen String packen.
- **Verify:** den String zerlegen, mit demselben Salt und derselben Iterationszahl neu rechnen, das Resultat **constant-time** mit dem gespeicherten vergleichen (gleicher Vergleich wie bei HMAC).

Ausgabeformat (Vorschlag, selbstbeschreibend):
```
pbkdf2-sha256$<iterations>$<salt_base64>$<hash_base64>
```
So stecken Algorithmus, Iterationszahl und Salt im Ergebnis. Du kannst die Iterationszahl später erhöhen, ohne alte Hashes zu brechen.

Iterationszahl: OWASP empfiehlt für PBKDF2-HMAC-SHA256 aktuell rund **600000**. Mach sie konfigurierbar mit einem hohen Default.

## 6. Testvektoren (verifiziert über Pythons `hashlib`)

PBKDF2-HMAC-SHA256, Passwort und Salt sind ASCII:

| Passwort | Salt | c | dkLen | Ergebnis (hex) |
|---|---|---|---|---|
| `password` | `salt` | 1 | 32 | `120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b` |
| `password` | `salt` | 2 | 32 | `ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43` |
| `password` | `salt` | 4096 | 32 | `c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a` |
| `passwd` | `salt` | 1 | 64 | `55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783` |
| `Password` | `NaCl` | 80000 | 64 | `4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d` |

Die ersten drei sind ein Block (`dkLen = 32`), die letzten zwei testen Multi-Block (`dkLen = 64`, also zwei Blöcke). Zusätzlich Quervergleich gegen `System.Security.Cryptography.Rfc2898DeriveBytes` mit zufälligen Eingaben.

## 7. Empfohlene Reihenfolge

1. `INT(i)`: den Zähler als 4-Byte big-endian an den Salt hängen.
2. Die `U`-Iteration: `U1` aus `Salt + Zähler`, dann `Uj = HMAC(P, U(j-1))`.
3. XOR über alle `c` Iterationen aufsammeln → `Ti`.
4. Erst `dkLen = 32` mit kleinem `c` testen (`c = 1`, dann `c = 2`), danach `c = 4096`.
5. Multi-Block (`dkLen = 64`) zuletzt.
6. Dann `Hash` und `Verify` mit Salt-Erzeugung und Ausgabeformat.

Stolperfallen: `INT(i)` nicht big-endian oder nicht 4 Byte. Zähler bei 0 gestartet statt bei 1. Passwort und Nachricht vertauscht. Nur das letzte `U` genommen statt alle ge-XOR-t.

## 8. Schnittstelle

Aus dem Design: `IPasswordHasher` mit `Hash(string password)` und `Verify(string password, string storedHash)`. Intern PBKDF2 mit deinem `HmacSha256`. Der constant-time Vergleich beim Verify ist derselbe wie in der HMAC-Spec.
