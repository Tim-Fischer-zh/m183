'use strict';

// Demo-Server für die JWT-Algorithm-Confusion (OWASP A07:2025, CVE-2022-23541).

const express = require('express');
const { generateKeyPair } = require('./keys');
const { findUser, EMPLOYEES } = require('./users');
const { issueToken, verifyToken } = require('./auth');
const { renderLogin, renderUserPanel, renderAdminPanel } = require('./views');

const PORT = process.env.PORT || 3000;

// Frisches Schlüsselpaar beim Start; privater Schlüssel bleibt im Speicher.
// Den Public Key OHNE abschliessenden Zeilenumbruch verwenden: Er dient im
// verwundbaren Pfad als HMAC-Secret. So stimmt er byte-genau mit dem überein,
// was beim Kopieren nach jwt.io/token.dev entsteht (sonst scheitert die
// Signatur am fehlenden "\n" und das Token wird verworfen).
const { publicKey: rawPublicKey, privateKey } = generateKeyPair();
const publicKey = rawPublicKey.trim();

const app = express();
app.use(express.urlencoded({ extended: false })); // Login-Formular parsen

// Liest ein Cookie aus dem Request-Header (kein cookie-parser nötig).
function getCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) {
      return decodeURIComponent(part.slice(idx + 1).trim());
    }
  }
  return null;
}

app.get('/', (req, res) => res.redirect('/panel'));

app.get('/login', (req, res) => res.send(renderLogin()));

app.post('/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = findUser(email, password);
  if (!user) {
    return res.status(401).send(renderLogin('Ungültige Anmeldedaten.'));
  }
  const token = issueToken(user, privateKey);
  res.cookie('token', token, { httpOnly: false, sameSite: 'lax', path: '/' });
  res.redirect('/panel');
});

app.get('/panel', (req, res) => {
  const token = getCookie(req, 'token');
  if (!token) return res.redirect('/login');

  let payload;
  try {
    payload = verifyToken(token, publicKey);
  } catch (err) {
    console.log(`[/panel] Token abgelehnt: ${err.message}`);
    res.clearCookie('token', { path: '/' });
    return res.redirect('/login');
  }

  console.log(`[/panel] Zugriff: ${payload.email || payload.sub} (role=${payload.role})`);
  if (payload.role === 'admin') {
    return res.send(renderAdminPanel(payload, EMPLOYEES));
  }
  return res.send(renderUserPanel(payload));
});

// Öffentlicher Schlüssel 
app.get('/public-key', (req, res) => res.type('text/plain').send(publicKey));

app.get('/logout', (req, res) => {
  res.clearCookie('token', { path: '/' });
  res.redirect('/login');
});

app.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log('  OWASP A07:2025 — Mitarbeiter-Portal (⚠ VERWUNDBAR)');
  console.log(`  URL:         http://localhost:${PORT}/`);
  console.log('  Login:       anna@firma.ch / passwort123');
  console.log(`  Public Key:  http://localhost:${PORT}/public-key`);
  console.log('='.repeat(60));
});
