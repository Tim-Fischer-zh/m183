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
