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
