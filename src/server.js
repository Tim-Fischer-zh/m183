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
