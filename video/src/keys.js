'use strict';

// Erzeugt das RSA-Schlüsselpaar des Servers. Der private Schlüssel bleibt
// nur im Arbeitsspeicher; der öffentliche ist über /public-key abrufbar
// (er ist kein Geheimnis — das ist gerade der Kern des Angriffs).

const crypto = require('crypto');

function generateKeyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

module.exports = { generateKeyPair };
