# Deklaration der KI-Nutzung

Modul 183, Projekt „Eigene Krypto-Library". Dieses Dokument legt offen, wo und wie KI eingesetzt wurde, wo bewusst nicht, und warum diese Aufteilung so gewählt ist.

Als KI-Assistent wurde **Claude (Anthropic)** verwendet.

---

## 1. Grundsatz der Arbeitsteilung

Von Anfang an galt eine klare Linie (siehe auch Projektantrag, Abschnitt 6):

- Der **gesamte Code der kryptografischen Primitiven** wird selbst geschrieben. Kein generierter Code.
- KI dient als **Tutor** für die Mathematik, als **Quelle für die offiziellen Testvektoren** und als **Code-Reviewer**.
- Der **Demonstrations- und Erweiterungsteil** (Angriffs-Labor) sowie reines Gerüst (Tests, Doku) dürfen KI-generiert sein, offen deklariert.

Der Gedanke dahinter: Die bewertete Eigenleistung und der Lerneffekt liegen im Implementieren der Algorithmen. Genau dort wird nichts generiert. Alles darum herum, das nicht die eigentliche Krypto ist, darf KI übernehmen.

## 2. Eigenleistung ohne generierten Code

Selbst geschrieben, Zeile für Zeile, in `Crypto.Core`:

- **SHA-256** (Padding, Message Schedule, Kompression, Multi-Block)
- **HMAC-SHA256**
- **PBKDF2** inklusive Hash und Verify
- **AES-256** (xtime, SubBytes, ShiftRows, MixColumns, AddRoundKey, Schlüsselexpansion, EncryptBlock)
- **ChaCha20** (RotL, QuarterRound, die Block-Funktion)
- die **Encrypt-then-MAC**-Komposition (`EncryptThenMacCipher`)

Diese Teile sind der Kern des Projekts. Der Weg dorthin, inklusive der eigenen Fehler und wie sie gefunden wurden, ist im Arbeitsjournal (`docs/arbeitsjournal.md`) dokumentiert.

## 3. KI als Tutor und Reviewer

Hier wurde KI genutzt, aber ohne Code zu generieren:

- **Mathematische Grundlagen und Ablauf.** Die Spezifikationen in `docs/krypto-spec/` (01 bis 06) erklären die Mathematik und die Schritte jedes Algorithmus. Sie dienten als Vorlage zum Selbst-Implementieren, enthalten aber keinen fertigen C#-Code der Primitiven.
- **Offizielle Testvektoren.** Die Vektoren aus FIPS und RFC wurden von der KI bereitgestellt und vorab gegen die Norm verifiziert, damit beim Selbstprüfen sichere Sollwerte vorliegen.
- **Konstanten.** Die Normwerte (SHA-256 K-Konstanten, AES S-Box und Rcon) wurden von der KI berechnet und gegen die bekannten Werte geprüft. Das sind öffentliche Fakten aus der Norm, keine Implementierung, und das Abtippen von Hand wäre nur fehleranfällig gewesen.
- **Code-Review.** Die KI hat den selbst geschriebenen Code auf Fehler durchgesehen. Einige Beispiele, die das Review gefunden hat:
  - ChaCha20: die 20 Runden fehlten komplett, der State wurde geklont und sofort wieder addiert.
  - AES-Schlüsselexpansion: Bedingung `i % 4 == i` statt `i % 8 == 4`, und das Wort-XOR im falschen Zweig.
  - AES MixColumns: `XTime(a1)` statt `XTime(a2)`.
  - PBKDF2: Passwort und Nachricht im HMAC vertauscht.
  - PBKDF2 Verify: `SequenceEqual` statt eines constant-time Vergleichs.

## 4. KI-generierter Code (offen deklariert)

Folgende Teile sind mit KI entstanden und sind **nicht** als Eigenleistung an der Kryptografie zu werten:

- **Das Angriffs-Labor** (`src/Crypto.Lab/`): das interaktive Menü und die drei Angriffe (AES-ECB-Muster, Nonce-Wiederverwendung, Brute-Force gegen SHA-256). Das ist die Erweiterung und Demonstrationsschicht. Sie nutzt die selbst geschriebenen Primitiven, ist aber selbst keine neue Kryptografie.
- **Der ChaCha20-Encrypt-Wrapper**: die kurze Schleife, die den Keystream mit den Daten XOR-t. Die eigentliche Block-Funktion darunter ist Eigenleistung.
- **Die Test-Dateien** (`src/Crypto.Tests/`): das xUnit-Gerüst mit den Testvektoren. Das ist Testinfrastruktur, kein Krypto-Code.
- **Die Dokumentation**: die Spezifikationen, die Ablauf-Diagramme, das README und diese Deklaration wurden mit KI entworfen.

## 5. Warum diese Aufteilung

Die Trennung folgt einem einfachen Prinzip: KI übernimmt, was Verständnis, Prüfung oder Gerüst ist, aber nicht die eigentliche Denkarbeit ersetzt.

- Die **Primitiven selbst zu schreiben** war das Lernziel. Hätte die KI sie generiert, wäre weder der Lerneffekt noch die Eigenleistung da.
- Die **Mathematik erklären zu lassen** und den Code **reviewen zu lassen** ist genau der sinnvolle Einsatz: Ich verstehe die Algorithmen besser und finde Fehler schneller, schreibe aber selbst.
- Die **Testvektoren und Konstanten** sind feste Normwerte. Sie von der KI verifiziert zu bekommen, spart fehleranfälliges Abtippen, ohne dass eigene Leistung verloren geht.
- Das **Angriffs-Labor** ist die Erweiterung. Die Angriffe (Padding, Timing, Brute-Force) sind anspruchsvoll und gehören nicht zum bewerteten Kern, darum ist KI-Generierung dort vertretbar, solange sie offen deklariert ist und ich den Code verstehe und erklären kann.

## 6. Nachvollziehbarkeit

Der Prozess ist über das Projekt verteilt dokumentiert:

- `docs/arbeitsjournal.md` beschreibt Tag für Tag, woran gearbeitet wurde, inklusive der eigenen Fehler.
- `docs/krypto-spec/` zeigt die Mathematik, die als Vorlage diente.
- Die Git-Historie zeigt die schrittweise Entstehung des Codes.
