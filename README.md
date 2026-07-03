# M183 — Eigene Krypto-Library

Modul 183, Applikationssicherheit. Eigenständiges Projekt anstelle der einzelnen Kompetenznachweise: eine kleine Krypto-Library in C#/.NET, bei der die kryptografischen Algorithmen **von Grund auf selbst implementiert** sind, dazu ein interaktives Angriffs-Labor.

**Antragsteller:** Tim Fischer
**Projekt-Board (offene und erledigte Issues):** https://github.com/users/Tim-Fischer-zh/projects/9

---

## Wichtiger Hinweis

Das ist ein **Lern- und Demonstrationsprojekt**, nicht für den produktiven Einsatz gedacht. Eigene Kryptografie zu schreiben ist in der Praxis ein Anti-Pattern („don't roll your own crypto"). Genau das wird im Projekt aktiv thematisiert. Die **Korrektheit** jeder Primitive ist gegen die **offiziellen Testvektoren** der jeweiligen Norm belegt (FIPS, RFC) und zusätzlich gegen `System.Security.Cryptography` quergeprüft.

## Was implementiert ist

Alles from-scratch und gegen offizielle Testvektoren getestet:

| Baustein | Norm | Zweck |
|---|---|---|
| SHA-256 | FIPS 180-4 | kryptografische Hash-Funktion |
| HMAC-SHA256 | RFC 2104 / 4231 | Message Authentication Code |
| PBKDF2 | RFC 8018 | Passwort-Hashing (langsam, gesalzen) |
| AES-256 | FIPS 197 | Block-Chiffre (Galois-Feld GF(2^8)) |
| ChaCha20 | RFC 8439 | Stream-Chiffre (ARX) |
| Encrypt-then-MAC | — | authentifizierte Verschlüsselung (ChaCha20 + HMAC) |

Die Chiffren sind über Interfaces (`IBlockCipher`, `IStreamCipher`, `IMac`, `IHashFunction`, `IPasswordHasher`, `ISymmetricCipher`) per Dependency Injection austauschbar.

## Eigenleistung und KI-Nutzung

Der gesamte **Code der kryptografischen Primitiven** (`Crypto.Core`) ist selbst geschrieben. KI wurde als Tutor für die **mathematischen Grundlagen**, für die **offiziellen Testvektoren** und für **Code-Review** eingesetzt. **KI-generiert und offen deklariert** sind das **Angriffs-Labor** (`Crypto.Lab`) und ein kleiner Wrapper der ChaCha20-Verschlüsselung. Vollständige Offenlegung in **`docs/ki-deklaration.md`**, ergänzt durch `docs/projektantrag.md` (Abschnitt 6) und `docs/arbeitsjournal.md`.

## Projektstruktur

```
src/
  Crypto.Core/    die Library: Primitiven und Interfaces
  Crypto.Tests/   Tests gegen die offiziellen Testvektoren
  Crypto.Lab/     interaktive Demo und Angriffs-Labor
docs/
  projektantrag.md       der Antrag
  design.md              Architektur und Design-Entscheide
  arbeitsjournal.md      Arbeitsjournal (5. Juni bis 3. Juli)
  ki-deklaration.md      Deklaration der KI-Nutzung
  zeitaufwand.csv        Zeitaufwand pro Phase
  krypto-spec/           die Mathe-Spezifikation je Algorithmus (01 bis 06)
  aes-ablauf.md          Ablauf-Diagramme AES (Mermaid)
  chacha20-ablauf.md     Ablauf-Diagramme ChaCha20 (Mermaid)
```

## Voraussetzungen

.NET 10 SDK. Prüfen mit `dotnet --version`.

## Bauen und Testen

```
dotnet build src/Crypto.sln
dotnet test  src/Crypto.sln
```

Die Test-Suite prüft jede Primitive gegen die offiziellen Testvektoren der Norm und vergleicht zusätzlich mit der .NET-Referenzimplementierung. Grüne Tests sind der Korrektheitsnachweis.

## Demo starten (zum Ausprobieren)

```
dotnet run --project src/Crypto.Lab
```

Ein Menü führt durch die Bausteine. Jede Option fragt Eingaben ab und zeigt die konkrete Ausgabe:

```
1  SHA-256 Hash
2  HMAC-SHA256
3  PBKDF2 (Passwort-Hash und Prüfung)
4  AES-256 (ein 16-Byte-Block)
5  ChaCha20 (Verschlüsselung und Round-Trip)
6  Authentifizierte Verschlüsselung (Encrypt-then-MAC)
7  Angriffs-Labor
0  Beenden
```

**SHA-256 und HMAC sind deterministisch** und lassen sich mit einem beliebigen Online-Tool gegenprüfen. AES und ChaCha20 nehmen pro Aufruf einen zufälligen Schlüssel, der mit ausgegeben wird.

## Angriffs-Labor (Erweiterung)

Menüpunkt 7. Drei **echte** Angriffe, jeder mit Gegenmassnahme, die die Library umsetzt:

1. **AES-ECB verrät Muster** — zwei gleiche Klartext-Blöcke ergeben zwei gleiche Ciphertext-Blöcke (der ECB-Pinguin). Gegenmassnahme: authentifizierte Verschlüsselung mit frischer Nonce.
2. **Nonce-Wiederverwendung** — dieselbe Nonce zweimal, und der geheime Klartext wird ohne Schlüssel rekonstruiert. Gegenmassnahme: frische Nonce pro Nachricht.
3. **Brute-Force gegen einen SHA-256-Passwort-Hash** — probiert live alle Kleinbuchstaben-Passwörter der Länge 4 durch, bis der Hash matcht, und misst die Geschwindigkeit. Gegenmassnahme: PBKDF2, gesalzen und um Grössenordnungen langsamer pro Versuch.

Die Botschaft: naive oder falsch benutzte Kryptografie ist angreifbar, sichere Defaults verhindern es.
