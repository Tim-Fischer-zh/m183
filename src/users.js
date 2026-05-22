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
