# Spec — JWT Algorithm Confusion Demo: verwundbares Mitarbeiter-Portal

**Datum:** 2026-05-31
**Modul:** Applikationssicherheit (Screencast-Begleitprojekt)
**Rahmen:** OWASP A07:2025 — Authentication Failures · CWE-287 (Improper Authentication) / CWE-303 · CVE-2022-23541 (`jsonwebtoken` ≤ 8.5.1)

## Ziel

Ein **kleines, realistisches, absichtlich verwundbares** Web-Portal, an dem die JWT-Algorithm-Confusion (RS256 → HS256) **live von Hand** vorgeführt wird: Token im Cookie, Manipulation über **jwt.io**, Tausch via Browser-DevTools, Neuladen → Admin-Panel.

Die Theorie (CVE, JWT-Aufbau, RS256/HS256, realer Vorfall) kommt aus einer separaten **Pages-Präsentation** des Users — **nicht** Teil dieses Projekts.

## Scope

**In Scope**
- Eine Node/Express-App, serverseitig gerendert, zwei sichtbare Seiten (Login + Panel).
- Echtes RS256-JWT im Cookie, **absichtlich verwundbare** Verifikation (`jsonwebtoken@8.5.1`).
- Endpunkt, der den öffentlichen Schlüssel ausliefert (für jwt.io als HMAC-Secret).
- Der Fix als **Code-Kommentar/Snippet** dokumentiert (eine Zeile).

**Out of Scope (bewusst)**
- **Kein** Safe/Unsafe-Laufzeit-Toggle.
- **Keine** HTML-Slides (macht der User in Pages).
- **Kein** Exploit-Skript, **kein** separates Frontend-Build, **keine** DB (alles in-memory).

## Architektur

- **Stack:** Node ≥ 18, Express, `jsonwebtoken@8.5.1` (exakt — das ist die CVE-Version), `cookie-parser`.
- **Rendering:** serverseitig, schlichtes HTML via Template-Strings (kein Template-Engine, keine Build-Pipeline).
- **Schlüssel:** RSA-2048-Paar beim Start im Speicher erzeugt; Public Key zusätzlich über `/public-key` abrufbar.
- **Benutzer:** ein normaler User, in-memory:
  - `anna@firma.ch` / `passwort123`, `role: "user"`, Name „Anna Beispiel".
  - **Kein Admin-Konto** — Kernaussage: man wird Admin, ohne dass ein Admin-Passwort existiert.

### Routen

| Route | Verhalten |
|---|---|
| `GET /` | Redirect → `/panel` (bzw. `/login`, wenn kein Cookie) |
| `GET /login` | Login-Formular (E-Mail + Passwort) |
| `POST /login` | Credentials prüfen → RS256-JWT `{ sub, email, name, role:"user" }` ausstellen → als **Cookie `token`** setzen → Redirect `/panel`. Bei Fehler: Formular mit Fehlermeldung. |
| `GET /panel` | Cookie `token` lesen, **verifizieren**, je nach `role` **User-Panel** oder **Admin-Panel** rendern. Kein/ungültiges Token → Redirect `/login`. |
| `GET /public-key` | Public Key als `text/plain` (kein Geheimnis). |
| `GET /logout` | Cookie löschen → `/login`. |

### Cookie

- Name `token`, Wert = JWT.
- **`httpOnly: false`** (Demo: muss in DevTools sicht-/editierbar sein), `sameSite: 'lax'`, `path: '/'`.
- Hinweis in der Doku: produktiv wäre `httpOnly` üblich — schützt aber **nicht** vor diesem Angriff, da der Angreifer sein *eigenes* Token fälscht.

### Die Schwachstelle (Kern)

In der Panel-Verifikation wird der erlaubte Algorithmus **nicht serverseitig gepinnt**, sondern aus dem (angreifer-kontrollierten) Token-Header übernommen — die zu CVE-2022-23541 gehörende Algorithm-Confusion-Klasse:

```js
// VERWUNDBAR — alg stammt aus dem Header; HS256 mit dem Public Key als HMAC-Secret wird akzeptiert
const { header } = jwt.decode(token, { complete: true });
const payload = jwt.verify(token, publicKey, { algorithms: [header.alg] });
```

**Fix (nur als Snippet/Kommentar dokumentiert, kein Toggle):**

```js
// FIX — Algorithmus serverseitig fest vorgeben
const payload = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

## Domäne

Internes **Mitarbeiter-Portal**:
- **User-Panel:** „Meine Daten" — Name, E-Mail, Rolle.
- **Admin-Panel:** „Alle Mitarbeitenden / Gehaltsliste" — sichtbar sensible Beispiel-Daten (fiktiv), als greifbare Konsequenz der Rechte-Eskalation.

## Angriffsablauf (live, von Hand)

1. Login als `anna@firma.ch` → Cookie `token` enthält RS256-JWT (`role:user`), `/panel` zeigt **User-Panel**.
2. DevTools → Application → Cookies → Wert von `token` kopieren.
3. Auf **jwt.io** einfügen; Public Key von `GET /public-key` holen.
4. Header `alg: RS256 → HS256`, Payload `role: "user" → "admin"` ändern; mit dem **Public Key als Secret** signieren — **„base64 encoded" NICHT ankreuzen**, PEM **byte-identisch** (inkl. abschließendem Zeilenumbruch).
5. Gefälschtes Token → DevTools → Cookie-Wert überschreiben → **Neuladen**.
6. `/panel` zeigt jetzt das **Admin-Panel** mit den internen Daten. Angriff gelungen — ohne Admin-Passwort, ohne privaten Schlüssel.

**Fallback-Werkzeug:** falls die jwt.io-UI das HS256-Signieren mit eigenem Secret nicht sauber zulässt → `token.dev` (gleicher Ablauf).

## Projektstruktur

```
m183/
├── README.md              Rahmen + Kurzanleitung (Start, Angriffsschritte, Fix)
├── package.json           express, jsonwebtoken@8.5.1, cookie-parser
├── src/
│   ├── server.js          Express-App + Routen
│   ├── auth.js            Token ausstellen + (verwundbare) Verifikation
│   ├── keys.js            RSA-Schlüsselpaar
│   ├── users.js           In-Memory-User (nur ein normaler User)
│   └── views.js           HTML-Rendering (Login, User-Panel, Admin-Panel)
```

## Verifikation (beim Bauen)

End-to-End empirisch absichern:
1. Server starten, als `anna` einloggen → User-Panel erscheint, Cookie gesetzt.
2. Token aus dem Cookie nehmen, per Tool (HMAC mit PEM) ein `HS256/role:admin`-Token fälschen.
3. Cookie tauschen, neuladen → **Admin-Panel** wird ausgeliefert (HTTP 200).
4. Gegenprobe: Mit dem `['RS256']`-Fix wird dasselbe Token abgewiesen (→ Redirect/401).
5. Die exakten jwt.io-Schritte in der README festhalten (inkl. PEM-/base64-Stolperstein).

## Risiken / offene Punkte

- **jwt.io-UI** kann sich geändert haben → token.dev als Fallback, beim Bauen verifizieren.
- **PEM-Byte-Gleichheit** ist die häufigste Fehlerquelle → `/public-key` liefert exakt den PEM, den der Server nutzt; in der Anleitung betonen.
