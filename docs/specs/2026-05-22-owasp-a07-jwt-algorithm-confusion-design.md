# Design-Spec — OWASP A07:2025: JWT Algorithm Confusion Demo

| | |
|---|---|
| **Status** | Freigegeben (Design), bereit für Umsetzungsplan |
| **Datum** | 2026-05-22 |
| **Modul** | M183 — Applikationssicherheit |
| **Thema** | OWASP Top 10 — A07:2025 Authentication Failures |
| **OWASP-Quelle** | https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/ |
| **Format** | Screencast-Video, 8–10 Minuten |
| **Sprache** | README, Sprecher-Skript, Code-Kommentare und Terminal-Ausgabe durchgehend Deutsch; Bezeichner im Code englisch |

---

## 1. Kontext & Ziel

Es entsteht ein vollständiges, lauffähiges Projekt als Grundlage für ein **Screencast-Video** (8–10 Min) zu **OWASP A07:2025 — Authentication Failures**. Das Video folgt der Gliederung **Intro → Theorie → Schwachstelle (Hands-on) → Massnahme (Hands-on) → Resultate & Zusammenfassung**. Der Hands-on-Teil (Live-Code im Terminal) ist mit ca. 5 Minuten der Hauptteil.

Demonstriert wird ein **JWT Algorithm Confusion**-Angriff (RS256 → HS256): Eine verwundbare Server-Verifikation liest den Signatur-Algorithmus aus dem angreifer-kontrollierten Token-Header. Der Angreifer fälscht damit ein Admin-Token, das per HMAC mit dem **öffentlichen** RSA-Schlüssel als Secret signiert ist — und erhält Admin-Zugriff ohne Passwort und ohne Private Key.

Die Demo läuft komplett im Terminal; kein Browser nötig.

## 2. Lerninhalt: Die Schwachstelle

### 2.1 JWT & die Algorithmus-Verwechslung

Ein JWT besteht aus drei Base64URL-Teilen: **Header** (u. a. `alg`), **Payload** (Claims), **Signatur**.

- **RS256** (asymmetrisch): Der Server signiert mit dem **Private Key**, verifiziert mit dem **Public Key**. Der Public Key ist per Definition öffentlich.
- **HS256** (symmetrisch): Signieren und Verifizieren nutzen **dasselbe Secret** (HMAC).

Der Fehler: Eine Verifikationsfunktion vertraut dem `alg`-Feld aus dem Token-Header. Der Header ist Teil der unsignierten Eingabe und damit **angreifer-kontrolliert**. Setzt der Angreifer `alg` auf `HS256`, behandelt eine naive Verifikation den übergebenen Schlüssel als HMAC-Secret. Übergeben wird der **Public Key** — der öffentlich verfügbar ist. Der Angreifer kennt das „Secret" also und kann ein gültiges HS256-Token erzeugen.

**Fix:** Den erlaubten Algorithmus serverseitig fest pinnen (`algorithms: ['RS256']`) und das `alg`-Feld des Headers ignorieren.

### 2.2 CWE-/OWASP-Zuordnung

- **OWASP A07:2025** — Authentication Failures.
- **CWE-303** — *Incorrect Implementation of Authentication Algorithm* — **Hauptzuordnung** für diesen Angriff.
- **CWE-287** — *Improper Authentication* — **Oberbegriff**.
- **Nicht** CWE-347 (*Improper Verification of Cryptographic Signature*) verwenden — diese ist nicht unter A07 gemappt.

### 2.3 Verifiziertes technisches Fundament (jsonwebtoken 8.5.1)

Der Quellcode von `jsonwebtoken@8.5.1` (`verify.js`) wurde vor dem Design geprüft. Ergebnis:

- **Ohne** `algorithms`-Option erkennt die Library ein PEM mit `BEGIN PUBLIC KEY` und schränkt **selbst** auf RS/ES-Algorithmen ein. Ein blankes `jwt.verify(token, publicKey)` ist damit **nicht** angreifbar — ein gefälschtes HS256-Token wird mit `invalid algorithm` abgewiesen.
- Verwundbar wird die Verifikation erst, wenn der Code die erlaubten Algorithmen **aus dem Token-Header ableitet** (`algorithms: [header.alg]`). Version 8.5.1 enthält **keine** Prüfung des Schlüsseltyps gegen den Algorithmus; sie ruft anschliessend `jws.verify(token, 'HS256', publicKeyPem)` auf und bildet den HMAC mit dem öffentlichen Schlüssel.
- Dies entspricht **CVE-2022-23541**, behoben in `jsonwebtoken@9.0.0`. Ab v9 verhindert eine zusätzliche Schlüsseltyp-Prüfung den Angriff. Deshalb ist für die Demo die Version **8.5.1 exakt** erforderlich.

**Konsequenz für das Design:** Die verwundbare Funktion liest `alg` aus dem Header und übergibt es an `algorithms`. Das ist realistisch (ein verbreiteter Anti-Pattern: „den Algorithmus des Tokens unterstützen"), funktioniert unabhängig von Library-Interna und ist die stärkere Lehrgeschichte — die Library *bietet* einen Schutz, der Entwickler hebelt ihn aus.

## 3. Scope — Deliverables

1. **Verwundbare Demo-App** (Node.js / Express): Login-Route mit RS256-JWT-Ausstellung, geschützte Admin-Route, Verifikationsfunktion mit `VULNERABLE`-Schalter.
2. **Exploit-Skript** (Node.js): führt den Angriff in nachvollziehbaren, im Terminal ausgegebenen Schritten aus.
3. **README.md**: Sprecher-Skript pro Videoabschnitt (wörtlich vorlesbar) mit Regie-Hinweisen und Zeitbudget für 8–10 Minuten.
4. **`demo.sh`**: startet Server und Exploit in der richtigen Reihenfolge, damit die Aufnahme nicht durch Tippen unterbrochen wird.

## 4. Design-Entscheidungen

| # | Entscheidung | Gewählt |
|---|---|---|
| A | `VULNERABLE`-Schalter | Konstante in `auth.js`, per Env-Variable `VULNERABLE` überschreibbar. Default = verwundbar. Sichtbar im Editor (Lehrmoment), per `demo.sh` ohne Editieren umschaltbar. |
| B | Public-Key-Kanal | `public.pem` auf Platte **und** `GET /public-key`-Endpoint. Der Exploit liest `public.pem` (byte-identisch, robust); der Endpoint unterstreicht: der Public Key ist bewusst öffentlich. |
| C | Exploit-Form | Node.js-Skript. Forge per `jwt.sign(...)`; HTTP per eingebautem `fetch`. Keine Zusatz-Pakete, terminal-only. |

## 5. Projektstruktur

```
m183/
├── .gitignore                node_modules/, *.pem, Logs, .DS_Store
├── package.json              jsonwebtoken "8.5.1" (exakt), express ^4
├── package-lock.json         (generiert)
├── README.md                 Intro · Setup · Drehbuch/Sprecher-Skript · Zeitbudget
├── demo.sh                   orchestriert Aufnahme: Phase 1 (verwundbar) → Phase 2 (Fix)
├── public.pem                (zur Laufzeit erzeugt, NICHT versioniert)
├── docs/specs/               diese Spec
├── src/
│   ├── keys.js               RSA-2048 erzeugen, public.pem schreiben
│   ├── users.js              In-Memory-Store: 1 Normaluser, kein Admin
│   ├── auth.js               issueToken() + verifyToken() mit VULNERABLE-Schalter  ← Kern
│   └── server.js             Express: POST /login · GET /admin · GET /public-key
└── exploit/
    └── exploit.js            der Angriff in 6 nummerierten Schritten
```

Dateien klein und fokussiert (< 200 Zeilen je Datei). Das Lehr-Herzstück `auth.js` ist isoliert, damit es im Video als einzelne, klare Kameraeinstellung gezeigt werden kann.

## 6. Komponenten-Spezifikation

### 6.1 `src/keys.js`

- `generateKeyPair()` → erzeugt ein RSA-Schlüsselpaar via `crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } })`. Rückgabe `{ publicKey, privateKey }` als PEM-Strings.
- `PUBLIC_KEY_PATH` → Konstante, `path.join(__dirname, '..', 'public.pem')` (Projekt-Root).
- `writePublicKeyFile(publicKey)` → schreibt `public.pem` mit Encoding `utf8`, gibt den Pfad zurück, loggt eine Zeile.
- Der **Private Key wird niemals auf Platte geschrieben** (bleibt nur im Server-Prozess-Speicher).

### 6.2 `src/users.js`

- Eingefrorener In-Memory-Store mit **einem** Normaluser: `{ username: 'alice', password: 'passwort123', role: 'user' }`. Bewusst **kein** Admin-Konto.
- `findUser(username, password)` → gibt das User-Objekt zurück oder `null`.
- Passwort im Klartext; Code-Kommentar weist hin: „Demo-Store; produktiv gehörte hier ein Passwort-Hash (bcrypt/argon2) — nicht das Thema dieser Demo."

### 6.3 `src/auth.js` — Kern

- `VULNERABLE` → `const VULNERABLE = process.env.VULNERABLE !== 'false';` (Default `true`). Prominenter Kommentarblock erklärt den Schalter.
- `issueToken(user, privateKey)` → `jwt.sign({ sub: user.username, role: user.role }, privateKey, { algorithm: 'RS256', expiresIn: '15m' })`. Der Server stellt **immer** RS256 aus.
- `verifyToken(token, publicKey)`:

  ```js
  function verifyToken(token, publicKey) {
    if (VULNERABLE) {
      // ⚠ FEHLER: Der Header stammt vom Angreifer — und wir vertrauen ihm.
      const decoded = jwt.decode(token, { complete: true });
      const alg = decoded && decoded.header && decoded.header.alg;
      return jwt.verify(token, publicKey, { algorithms: [alg] });
    }
    // ✓ FIX: Algorithmus fest vorgegeben, der Header wird ignoriert.
    return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
  }
  ```

- Exporte: `issueToken`, `verifyToken`, `VULNERABLE`.
- `auth.js` bleibt bewusst minimal („fahrlässiger" Code); die robuste Fehlerbehandlung sitzt in `server.js`.

### 6.4 `src/server.js`

Express-App. Beim Start: `generateKeyPair()`, `writePublicKeyFile()`, Schlüssel im Modul-Speicher halten, Startup-Banner ausgeben (aktiver Modus, Port, Pfad zu `public.pem`).

| Route | Verhalten | Statuscodes |
|---|---|---|
| `POST /login` | Body `{username, password}`. Fehlende Felder → 400. `findUser` → bei `null` 401. Sonst `issueToken` → `{ token }`. | 200 / 400 / 401 |
| `GET /admin` | `Authorization: Bearer <token>` lesen. Fehlt/fehlerhaft → 401. `verifyToken` in `try/catch`; Exception → 401. Bei Erfolg `payload.role === 'admin'` prüfen → sonst 403. Admin → `{ message, geheim }`. | 200 / 401 / 403 |
| `GET /public-key` | Liefert den Public Key als `text/plain`. | 200 |

- `express.json()` als Body-Parser.
- Pro `/admin`-Anfrage eine Log-Zeile: vorgelegter `alg` und Verdikt (gewährt/abgewiesen).
- Port: `process.env.PORT || 3000`.
- Fehlerantworten als JSON `{ error: '<deutsche Meldung>' }`, keine Stacktraces nach aussen.

### 6.5 `exploit/exploit.js`

Node-Skript, farbige (ANSI) nummerierte Ausgabe, konfigurierbare Pause zwischen Schritten (`STEP_DELAY_MS`, Default 1200 ms). `BASE_URL` aus `PORT` (Default 3000). HTTP via eingebautem `fetch`.

Sechs Schritte (Details siehe §7). Bei nicht erreichbarem Server: klare Meldung („Server nicht erreichbar — läuft er?") und Exit-Code 1. Sonst Exit-Code 0; das Ergebnis wird über ein eindeutiges Banner ausgegeben (`ERGEBNIS: ANGRIFF ERFOLGREICH` bzw. `ERGEBNIS: ANGRIFF ABGEWEHRT`), das `demo.sh` für den Selbstcheck auswertet.

### 6.6 `package.json`

- `name: "owasp-a07-jwt-algorithm-confusion"`, `private: true`, `version: "1.0.0"`.
- `dependencies`: `"jsonwebtoken": "8.5.1"` (**exakt**, kein Caret), `"express": "^4.21.2"`.
- `scripts`: `start` (`node src/server.js`), `exploit` (`node exploit/exploit.js`), `demo` (`./demo.sh`).
- `engines`: `node >= 18` (informativ).

### 6.7 `.gitignore`

```
node_modules/
*.pem
npm-debug.log*
.DS_Store
```

`*.pem` schliesst `public.pem` aus. Der Private Key wird ohnehin nicht auf Platte geschrieben.

### 6.8 `demo.sh`

- `#!/usr/bin/env bash`, `set -euo pipefail`, `export NODE_NO_WARNINGS=1` (saubere Aufnahme).
- Argumente: kein Argument → beide Phasen; `vuln` → nur Phase 1; `fixed` → nur Phase 2.
- Pro Phase: Server im Hintergrund starten (`VULNERABLE=true|false`), Server-Ausgabe in eine Logdatei unter `/tmp` umleiten, auf Bereitschaft warten (Poll auf `GET /public-key`, Timeout ~10 s), `exploit.js` im Vordergrund ausführen, danach Server beenden.
- `trap` beendet einen gestarteten Server bei jedem Exit (Cleanup).
- Banner trennen die Phasen optisch.
- Abschliessender **Selbstcheck**: prüft, dass Phase 1 „ANGRIFF ERFOLGREICH" und Phase 2 „ANGRIFF ABGEWEHRT" ergab, und gibt eine Zusammenfassung aus.

### 6.9 `README.md`

Abschnitte: Titel & Kurzbeschreibung · ⚠️ Sicherheitshinweis (absichtlich verwundbar, nur lokal, `npm audit`-Warnungen sind gewollt) · Voraussetzungen · Setup (`npm install`) · Schnellstart (`./demo.sh`) · Manueller Betrieb · Hintergrund (A07:2025, CWE-303/287, OWASP-Link) · „Die Schwachstelle in einer Zeile" · **🎬 Drehbuch / Sprecher-Skript** (siehe §8) · Zeitbudget-Tabelle · Projektstruktur · Aufräumen.

## 7. Datenfluss — Angriffsablauf

| Schritt | Aktion | Erwartetes Ergebnis |
|---|---|---|
| 1 | Exploit → `POST /login {alice, passwort123}` | Echter RS256-Token (`alg:RS256`, `role:user`) |
| 2 | Exploit → `GET /admin` mit alice' Token | **403** — Normaluser ist kein Admin (Autorisierung greift korrekt) |
| 3 | Exploit liest `public.pem` | Public Key als String `K` — kein Geheimnis |
| 4 | Exploit forge: `jwt.sign({sub:'mallory',role:'admin'}, K, {algorithm:'HS256'})` | Gefälschtes HS256-Token, HMAC-signiert mit `K` |
| 5 | Exploit → `GET /admin` mit gefälschtem Token | siehe Schritt 6 |
| 6a | **Verwundbar:** `verifyToken` liest `alg:HS256` → `jwt.verify(token, K, {algorithms:['HS256']})` → HMAC mit `K` stimmt überein → `role:admin` | **200 + Admin-Daten — Angriff erfolgreich** |
| 6b | **Gepinnt:** `verifyToken` → `{algorithms:['RS256']}` → `HS256 ∉ ['RS256']` → `invalid algorithm` | **401 — Angriff abgewehrt** |

**Invariante (Determinismus):** Der Server hält den Public Key als String, schreibt exakt diesen String mit `utf8` nach `public.pem`; der Exploit liest `public.pem` mit `utf8`. Der UTF-8-Roundtrip ist verlustfrei → das HMAC-Secret ist auf beiden Seiten byte-identisch → die gefälschte Signatur stimmt im verwundbaren Modus garantiert.

Der legitime RS256-Token funktioniert in **beiden** Modi (`alg:RS256` ist in beiden Algorithmen-Listen erlaubt) — der Fix bricht den normalen Login nicht.

## 8. Sprecher-Skript & Zeitbudget

Das README enthält pro Abschnitt eine **Zeitmarke**, einen **`[Regie: …]`**-Hinweis (was am Bildschirm zu sehen ist) und den **wörtlich vorlesbaren** deutschen Sprechertext.

| Marke | Abschnitt | Dauer | Pflicht-Inhalt |
|---|---|---|---|
| 0:00 | Intro | 1:00 | Begrüssung; OWASP A07:2025 Authentication Failures vorstellen; ankündigen, dass ein JWT Algorithm-Confusion-Angriff live gezeigt und anschliessend behoben wird. |
| 1:00 | Theorie | 1:30 | JWT-Aufbau (Header/Payload/Signatur); RS256 (asymmetrisch, Private signiert / Public verifiziert) vs. HS256 (symmetrisch, ein Secret); der Angriff: `alg` aus dem Header ist angreifer-kontrolliert; warum der öffentliche Schlüssel als HMAC-Secret genügt. |
| 2:30 | Schwachstelle (Hands-on) | 3:00 | Server verwundbar starten (Banner zeigt Modus); `verifyToken` in `auth.js` zeigen; Exploit starten; Schritte 1–6 mitlesen; Admin-Zugriff mit gefälschtem Token. |
| 5:30 | Massnahme (Hands-on) | 2:00 | Die eine Zeile in `auth.js` zeigen (`[header.alg]` → `['RS256']`), Fix erklären; Server gepinnt neu starten; denselben Exploit erneut → `invalid algorithm`, 401. |
| 7:30 | Resultate & Zusammenfassung | 1:30 | Vorher/Nachher gegenüberstellen; Kernbotschaft „Algorithmus serverseitig pinnen, dem Token-Header nie vertrauen"; CWE-303 (primär) und CWE-287 nennen; auf die OWASP-A07:2025-Quelle verweisen. |

Summe ~9:00 (im Zielfenster 8–10). Hands-on-Teil = 3:00 + 2:00 = 5:00 (Hauptteil).

## 9. Fehlerbehandlung & Edge Cases

- **server.js**: fehlende Login-Felder → 400; fehlender/fehlerhafter `Authorization`-Header → 401; `verifyToken`-Exception in `try/catch` → 401; keine Stacktraces in Antworten.
- **auth.js (verwundbarer Zweig)**: `jwt.decode` kann `null` liefern → defensiv prüfen; ein ungültiges Token läuft regulär in den `jwt.verify`-Fehler (von `server.js` als 401 behandelt).
- **exploit.js**: `fetch`-Fehler (z. B. `ECONNREFUSED`) → klare Meldung, Exit 1; jede Server-Antwort wird mit Status und Body angezeigt.
- **demo.sh**: `set -euo pipefail`; `trap` beendet den Server; Readiness-Poll mit Timeout, sonst klarer Abbruch.

## 10. Umgebung & Sicherheit

- **Node 25 / npm 11**: `jsonwebtoken@8.5.1` ist reines JavaScript (`engines: node>=4`, keine Obergrenze, keine nativen Abhängigkeiten) → installiert und läuft auf Node 25. `NODE_NO_WARNINGS=1` in `demo.sh` hält die Aufnahme ruhig.
- **Absichtlich verwundbar**: `npm install` / `npm audit` melden bekannte CVEs für `jsonwebtoken@8.5.1` — das ist beabsichtigt und Teil des Lerninhalts. Das README weist deutlich darauf hin. Die App ist nur für den lokalen Demo-Einsatz; **nicht deployen**.
- **Schlüssel**: Schlüsselpaar bei jedem Serverstart neu; Private Key nur im Speicher; `public.pem` auf Platte und über `.gitignore` ausgeschlossen. Keine Schlüssel im Repo.

## 11. Nicht im Scope (YAGNI)

- Kein Browser / kein Frontend — Demo ist terminal-only.
- Kein Docker, kein Deployment.
- **Kein Test-Framework** — der Exploit gegen beide Modi *ist* der Funktionsnachweis; `demo.sh` wertet ihn als Selbstcheck aus. (Optionale Jest-Unit-Tests nur auf ausdrücklichen Wunsch.)
- Keine persistente Datenbank, keine Passwort-Hashes (Demo-Store), keine echte Benutzerverwaltung.

## 12. Abnahmekriterien

1. `npm install` installiert exakt `jsonwebtoken@8.5.1`.
2. `./demo.sh` läuft fehlerfrei durch und meldet im Selbstcheck: Phase 1 = „ANGRIFF ERFOLGREICH", Phase 2 = „ANGRIFF ABGEWEHRT".
3. Verwundbarer Modus: gefälschtes HS256-Token erhält **200** auf `GET /admin` mit Admin-Daten.
4. Gepinnter Modus: dasselbe Token erhält **401** (`invalid algorithm`); der legitime RS256-Login funktioniert weiterhin.
5. Der Exploit gibt alle 6 Schritte nachvollziehbar im Terminal aus.
6. Das README enthält ein wörtlich vorlesbares Sprecher-Skript mit Zeitmarken für 8–10 Minuten und Regie-Hinweisen.
7. Es werden keine Schlüssel versioniert; `public.pem` ist in `.gitignore`.
8. Code-Kommentare und Terminal-Ausgaben sind auf Deutsch.
