# Projektantrag M183 — Eigene Krypto-Library (statt Kompetenznachweise)

[Projekt-Board (offene Issues)](https://github.com/users/Tim-Fischer-zh/projects/9)

**Modul:** 183 — Applikationssicherheit implementieren
**Antragsteller:** Tim Fischer
**Datum:** 2026-06-05
**Modulverantwortung:** Jonas van Essen
**Variante:** Eigenständiges Projekt anstelle der einzelnen Kompetenznachweise (KN)

---

## 1. Ausgangslage und Idee

Anstelle der einzelnen Kompetenznachweise möchte ich im Modul 183 ein eigenständiges Projekt umsetzen: eine **kleine Krypto-/Security-Library in C#/.NET**, bei der die kryptografischen Algorithmen **von Grund auf selbst implementiert** werden (nicht aus einer bestehenden Bibliothek übernommen). Vorbild für die Struktur und API ist **ASP.NET Core Security** (`IPasswordHasher`, Data Protection).

Das Projekt verbindet zwei Ebenen:

1. **Konstruktiv:** eine saubere Library mit sicheren Standardeinstellungen (so wie man Kryptografie in der Praxis kapselt).
2. **Offensiv/didaktisch (als Erweiterung):** ein **Angriffs-Labor**, das zeigt, *warum* die sicheren Defaults nötig sind — durch echte Angriffe auf naive Implementierungen.

## 2. Wichtige Einordnung: „Don't roll your own crypto"

Mir ist bewusst, dass eigene Kryptografie im produktiven Einsatz ein Anti-Pattern ist. Das Projekt ist deshalb ausdrücklich ein **Lern- und Demonstrationsprojekt**, nicht für den produktiven Einsatz gedacht. Genau dieser Punkt wird im Projekt aktiv thematisiert: Die selbst gebauten Algorithmen werden gegen die offiziellen Standard-Implementierungen und gegen Seitenkanal-Angriffe gestellt, um zu zeigen, weshalb man in der Praxis geprüfte Bibliotheken verwendet.

## 3. Korrektheitsnachweis

Jede selbst implementierte Primitive wird gegen die **offiziellen Testvektoren** der jeweiligen Norm geprüft (FIPS 180-4 für SHA-256, FIPS 197 für AES, RFC 8439 für ChaCha20, RFC 2104/8018 für HMAC/PBKDF2). Die Implementierung gilt erst als korrekt, wenn sie bitgenau dieselben Resultate liefert wie die Norm und wie `System.Security.Cryptography`.

## 4. Umfang

### 4.1 Grundanforderungen (Ziel: Note 5)

- **Zwei Hash-Verfahren:** SHA-256 (kryptografische Hash-Primitive) und PBKDF2 (Passwort-Hashing, aufbauend auf HMAC-SHA256).
- **Zwei Verschlüsselungsverfahren:** AES-256 (Block-Cipher) und ChaCha20 (Stream-Cipher).
- **Integritätssicherung:** HMAC-SHA256, Verschlüsselung als Encrypt-then-MAC (authentifiziert).
- **Test-Suite** gegen offizielle Testvektoren.
- **Dokumentation** inkl. Prozessdokumentation und Deklaration der KI-Nutzung.

### 4.2 Erweiterung (Ziel: über Note 5 — „Rahmen sprengen")

- **Angriffs-Labor** mit mindestens drei demonstrierten Angriffen inkl. Gegenmassnahme (z. B. Brute-Force/hashcat gegen unser ungesalzenes SHA-256 als Passwort-Hash, Timing-Attack, AES-ECB-Muster, Padding-Oracle, Nonce-Reuse). Jede Demonstration nach dem Muster: Angriff zeigen → erklären → mit der Library schliessen.

## 5. Nachweis der Modulkompetenzen

| Modulthema / Kompetenz | Nachweis im Projekt |
|---|---|
| Schutzziele — Vertraulichkeit & Integrität | Vertraulichkeit (AES-256/ChaCha20), Integrität (HMAC / Encrypt-then-MAC) |
| Verschlüsselung (Vertiefung) | AES-256 und ChaCha20 inkl. zugrunde liegender Mathematik (endliche Körper, ARX) |
| Authentifizierung / Umgang mit Zugangsdaten | PBKDF2-Passwort-Hashing, sichere Passwortspeicherung; Key-/Salt-Handling ohne Hardcoding |
| Secure Design | Fail-safe API, sichere Defaults, constant-time Vergleich, authentifizierte Verschlüsselung |
| Schwachstellen ausnutzen und fixen | Angriffs-Labor (Erweiterung): jede Schwachstelle wird ausgenutzt und anschliessend mit der Library geschlossen |
| Schwachstellen finden (Tools) | hashcat (Passwort-Cracking), Timing-Messung — im Angriffs-Labor (Erweiterung) |

Der Schwerpunkt liegt auf Kryptografie (Verschlüsselung, Passwort-Hashing, Integrität) und Secure Design. Das Ausnutzen und Schliessen von Schwachstellen wird in der Erweiterung (Angriffs-Labor) demonstriert.

## 6. Eigenleistung und KI-Nutzung (Deklaration)

Klare, transparente Abgrenzung, die während des ganzen Projekts eingehalten wird:

- **Eigenleistung — selbst geschrieben (ich):** Die **kryptografischen Primitiven der Library** (`Crypto.Core`: SHA-256, HMAC, PBKDF2, AES-256, ChaCha20, Encrypt-then-MAC). Das ist der bewertete Kern und entsteht ohne generierten Code.
- **KI als Tutor/Review für den Kern:** mathematische Grundlagen, Erklärungen, offizielle Testvektoren und Code-Review (Suche nach Fehlern/Schwachstellen in meinem Code).
- **KI-generiert — offen deklariert:** der Code des **Angriffs-Labors** (`Crypto.Lab`, Erweiterung). Die Angriffe (z. B. Padding-Oracle, Timing-Messung) sind anspruchsvoll; dieser Demonstrations-Code wird mit KI erstellt. Ich stelle sicher, dass ich ihn fachlich verstehe und erklären kann.

## 7. Zeitplan (24 Lektionen + Freizeit)

| Phase | Inhalt | Lektionen | Freizeit (ca.) |
|---|---|---|---|
| 0 | Setup Solution, API-Interfaces, dieser Antrag | ~2 | ~5 h |
| 1 | SHA-256 → HMAC → PBKDF2 (+ Tests) | ~5 | ~5 h |
| 2 | AES-256 und ChaCha20 (+ Tests) | ~7 | ~5 h |
| 3 | Angriffs-Labor (Erweiterung) | ~5 | ~5 h |
| 4 | Dokumentation, Prozessdoku, Demo/Präsentation | ~4 | ~5 h |

## 8. Liefergegenstände

- Lauffähige Library inkl. Quellcode (Git-Repository)
- Test-Suite mit offiziellen Testvektoren
- Projektdokumentation inkl. Prozessdokumentation und KI-Deklaration
- Präsentation/Demo
- Angriffs-Labor (ausführbar) — Erweiterung
