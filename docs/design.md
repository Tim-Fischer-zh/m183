# Design — Krypto-Library (M183)

**Stand:** 2026-06-05
**Stack:** C# / .NET (aktuelles LTS)
**Arbeitstitel der Solution:** `Crypto.*` (Name frei änderbar)

> Arbeitsteilung: Die mathematischen Spezifikationen, Testvektoren und dieses Design stammen als Vorgabe von der KI. Den **Code der Library-Primitiven (`Crypto.Core`) schreibt der Student selbst** (kein generierter Code). Der **Code des Angriffs-Labors (`Crypto.Lab`, Erweiterung) darf KI-generiert sein** (offen deklariert). Siehe Projektantrag, Abschnitt 6.

## 1. Ziele

- Eine kleine, verständliche Security-Library mit **selbst implementierten** Krypto-Primitiven.
- **Sichere Defaults**: Wer die öffentliche API benutzt, soll nichts kryptografisch falsch machen können.
- **Belegbare Korrektheit** über offizielle Testvektoren.
- Ein **Angriffs-Labor** (Erweiterung), das die Notwendigkeit der Defaults praktisch zeigt.

## 2. Solution-Struktur

| Projekt | Typ | Zweck |
|---|---|---|
| `Crypto.Core` | Klassenbibliothek | Die Primitiven und die öffentliche API |
| `Crypto.Tests` | xUnit-Testprojekt | Verifikation gegen offizielle Testvektoren + Round-Trip-Tests |
| `Crypto.Lab` | Konsolen-App | Angriffs-Labor (Erweiterung) |

## 3. Öffentliche API (im Stil von ASP.NET Core Security)

Die interne Mathematik bleibt gekapselt; nach aussen werden klare, schwer-falsch-zu-bedienende Schnittstellen angeboten. Vorschlag (Signaturen vom Studenten zu implementieren):

- `IHashFunction` — `byte[] Hash(ReadOnlySpan<byte> data)` (für SHA-256)
- `IMac` — `byte[] ComputeMac(key, message)` und `bool Verify(key, message, mac)` (HMAC; Verify constant-time)
- `IPasswordHasher` — `string Hash(string password)` und `bool Verify(string password, string stored)` (PBKDF2; speichert Algorithmus-Parameter + Salt im Ergebnis)
- `ISymmetricCipher` — `byte[] Encrypt(key, plaintext)` und `byte[] Decrypt(key, blob)`; intern **Encrypt-then-MAC**, Nonce/IV wird selbst erzeugt und im Blob abgelegt

**Design-Regeln:**
- Verschlüsselung gibt immer ein **authentifiziertes** Ergebnis zurück (kein „nur AES-CBC").
- Nonce/IV nie vom Aufrufer verlangen — intern zufällig erzeugen, im Ausgabeformat mitführen.
- Vergleiche von MACs/Hashes immer **constant-time**.
- Fehler beim Entschlüsseln/Verifizieren: eine generische Exception, keine Detail-Leaks (Padding-Oracle vermeiden).

## 4. Komponenten und Abhängigkeiten

```
SHA-256  ──►  HMAC-SHA256  ──►  PBKDF2
                   │
                   └──►  Encrypt-then-MAC  ◄── AES-256 / ChaCha20
```

- **SHA-256**: Merkle-Damgård, 32-Bit-Arithmetik. Basis für HMAC.
- **HMAC-SHA256**: Standard-Konstruktion auf SHA-256. Basis für PBKDF2 und für die Integritätssicherung.
- **PBKDF2**: Iterierte HMAC-Anwendung als Passwort-Hash.
- **AES-256**: Block-Cipher; rechnet im endlichen Körper GF(2^8). Betriebsmodus: CBC oder CTR (Entscheid in der Mathe-Spec).
- **ChaCha20**: Stream-Cipher; ARX (Add-Rotate-XOR) auf 32-Bit-Wörtern.

## 5. Ausgabeformate (selbst zu definieren, Vorschlag)

- **Passwort-Hash:** `algo$iterations$salt_b64$hash_b64` (parametrisiert, damit später migrierbar).
- **Verschlüsselter Blob:** `version || algo-id || nonce || ciphertext || mac` (Bytes, base64 nach aussen).

Diese Formate sind bewusst selbst-beschreibend, damit Parameter nicht „verloren gehen".

## 6. Test-Strategie

- **Testvektoren** je Primitive aus der Norm (Pflicht): bekannte Eingabe → bekannte Ausgabe.
- **Quervergleich** gegen `System.Security.Cryptography` (zusätzliche Sicherheit).
- **Round-Trip**: `Decrypt(Encrypt(x)) == x` für zufällige Eingaben.
- **Negativtests**: manipulierter Ciphertext/MAC muss zuverlässig abgelehnt werden.

## 7. Angriffs-Labor (`Crypto.Lab`) — Erweiterung

Mindestens drei davon umsetzen. Jede Demonstration nach dem Muster: **Angriff zeigen → erklären → mit der Library fixen → erneut prüfen.**

| # | Angriff | Kernaussage | Gegenmassnahme |
|---|---|---|---|
| 1 | Unser SHA-256 als ungesalzener Passwort-Hash, per hashcat/Brute-Force geknackt | ein schneller, kryptografisch starker Hash ist trotzdem kein sicherer Passwort-Speicher | PBKDF2 (gesalzen, viele Iterationen) |
| 2 | Naiver `==`-Vergleich, Timing gemessen | Vergleichszeit verrät Information | constant-time Vergleich |
| 3 | AES-ECB auf einem Bild (Pinguin) | ECB erhält Muster | CBC/CTR + Authentifizierung |
| 4 | AES-CBC ohne MAC: Padding-Oracle | unauthentifizierte Verschlüsselung ist angreifbar | Encrypt-then-MAC |
| 5 | Nonce-Reuse bei Stream-Cipher | Wiederverwendung leakt Klartext | interne, einmalige Nonce-Erzeugung |

## 8. Sicherheits-Defaults (Zusammenfassung)

- Authentifizierte Verschlüsselung als einziger öffentlicher Weg.
- Zufällige, einmalige Nonces/IVs intern.
- Constant-time Vergleiche.
- Generische Fehler ohne Seitenkanal.
- Sinnvolle PBKDF2-Iterationszahl als Default.

## 9. Scope

**In Scope (Kern, Ziel Note 5):** SHA-256, HMAC, PBKDF2, AES-256, ChaCha20, Encrypt-then-MAC, Tests gegen offizielle Testvektoren.

**Erweiterung (über Note 5):** Angriffs-Labor mit mindestens drei Angriffen inkl. Gegenmassnahme.

**Out of Scope** (bewusst weggelassen — zu grosser Handschreib-Aufwand): SHA-3/Keccak, Argon2id, AES-GCM, Poly1305, Demo-Web-App, produktiver Einsatz, asymmetrische Kryptografie.

