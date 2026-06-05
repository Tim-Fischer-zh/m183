'use strict';

const jwt = require('jsonwebtoken');

// Stellt ein echtes RS256-Token aus, signiert mit dem privaten Schlüssel.
function issueToken(user, privateKey) {
  return jwt.sign(
    { sub: user.email, email: user.email, name: user.name, role: user.role },
    privateKey,
    { algorithm: 'RS256', expiresIn: '1h' }
  );
}

// Verifiziert das Token aus dem Cookie.
//
// VERWUNDBAR — JWT Algorithm Confusion (CVE-2022-23541, OWASP A07:2025).
// Der erlaubte Algorithmus wird aus dem Token-Header gelesen. Der Header ist
// nicht signiert und stammt vollständig vom Aufrufer. Setzt ein Angreifer
// alg=HS256, verwendet jsonwebtoken den ÖFFENTLICHEN Schlüssel als
// HMAC-Secret — und akzeptiert ein selbst signiertes, gefälschtes Token.
function verifyToken(token, publicKey) {
  const decoded = jwt.decode(token, { complete: true });
  const alg = decoded && decoded.header && decoded.header.alg;
  return jwt.verify(token, publicKey, { algorithms: ['RS256'] });

  // ✓ FIX (eine Zeile) — Algorithmus serverseitig fest vorgeben, Header ignorieren:
  //     return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
}

module.exports = { issueToken, verifyToken };
