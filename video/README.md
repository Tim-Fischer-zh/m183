# OWASP A07:2025 — JWT Algorithm Confusion (verwundbares Portal)

Begleitprojekt zum Screencast „Modul Applikationssicherheit". Ein **absichtlich
verwundbares** internes Mitarbeiter-Portal, an dem die JWT-Algorithm-Confusion
(RS256 → HS256) **live von Hand** über [jwt.io](https://jwt.io) vorgeführt wird.

> ⚠ **Absichtlich verwundbar.** Nur lokal verwenden, niemals deployen.
> Nutzt `jsonwebtoken@8.5.1` (CVE-2022-23541) bewusst ohne Schutzmassnahmen.

## Rahmen

| | |
|---|---|
| OWASP | A07:2025 — Authentication Failures |
| CWE | CWE-287 — Improper Authentication (mit CWE-303) |
| CVE | CVE-2022-23541 — `jsonwebtoken` ≤ 8.5.1 |
| Quelle | https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/ |

## Start

```bash
npm install      # express + jsonwebtoken@8.5.1
npm start        # http://localhost:3000/
```

Login: **anna@firma.ch** / **passwort123** (role `user`). Es gibt **kein**
Admin-Konto — der Angriff verschafft trotzdem Admin-Rechte.

## Der Angriff (live, über jwt.io)

1. **Einloggen** als `anna@firma.ch`. Es erscheint **„Mein Bereich"** (User-Panel).
   Der Server hat ein RS256-JWT im **Cookie `token`** gesetzt.
2. **DevTools → Application → Cookies** → Wert von `token` kopieren.
3. Auf **jwt.io** einfügen. Öffentlichen Schlüssel von
   <http://localhost:3000/public-key> holen.
4. **Manipulieren & neu signieren:**
   - Header: `alg` von `RS256` auf **`HS256`** ändern
   - Payload: `role` von `user` auf **`admin`** ändern
   - Als HMAC-**Secret den öffentlichen Schlüssel** einfügen — genau so, wie er
     unter `/public-key` steht (keine zusätzliche Leerzeile am Ende)
   - ⚠ **„secret base64 encoded" NICHT ankreuzen** — sonst stimmt die Signatur nicht.
5. Das **gefälschte Token** kopieren → DevTools → Cookie-Wert `token` überschreiben.
6. **Neu laden** → es erscheint der **Admin-Bereich** mit der Gehaltsliste.
   Angriff gelungen — ohne Admin-Passwort, ohne den privaten Schlüssel des Servers.

> **Falls jwt.io zickt** (meist wegen Leerzeichen/Zeilenumbruch im Secret):
> [token.dev](https://token.dev) funktioniert gleich. Garantiert klappt dieser
> Einzeiler — er erzeugt ein fertiges Admin-Token zum direkten Einfügen in den Cookie:
>
> ```bash
> node -e 'const c=require("crypto"),b=x=>Buffer.from(x).toString("base64url");fetch("http://localhost:3000/public-key").then(r=>r.text()).then(k=>{const h=b(JSON.stringify({alg:"HS256",typ:"JWT"})),p=b(JSON.stringify({email:"anna@firma.ch",name:"Anna Beispiel",role:"admin"}));console.log(h+"."+p+"."+b(c.createHmac("sha256",k.trim()).update(h+"."+p).digest()))})'
> ```

## Die Schwachstelle (`src/auth.js`)

```js
// VERWUNDBAR — Algorithmus aus dem (angreifer-kontrollierten) Header:
const { header } = jwt.decode(token, { complete: true });
return jwt.verify(token, publicKey, { algorithms: [header.alg] });

// FIX — Algorithmus serverseitig fest vorgeben, Header ignorieren:
return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

**Kernaussage:** Vertraue beim Prüfen einer Signatur nie dem Algorithmus, den die
Eingabe selbst angibt. Bei JWT heisst das: `algorithms` immer explizit setzen.

## Projektstruktur

```
src/
├── server.js   Express-App + Routen (/login, /panel, /public-key, /logout)
├── auth.js     Token ausstellen + (verwundbare) Verifikation
├── keys.js     RSA-Schlüsselpaar
├── users.js    ein normaler User + fiktive Gehaltsliste fürs Admin-Panel
└── views.js    HTML (Login, User-Panel, Admin-Panel)
```
