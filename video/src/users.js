'use strict';

// Genau EIN normaler Benutzer. Es gibt bewusst KEIN Admin-Konto:
// Der Angriff verschafft Admin-Rechte, obwohl gar kein Admin-Passwort
// existiert. (Klartext-Passwort nur zu Demozwecken.)
const USERS = [
  { email: 'anna@firma.ch', password: 'passwort123', name: 'Anna Beispiel', role: 'user' },
];

function findUser(email, password) {
  const u = USERS.find((x) => x.email === email);
  return u && u.password === password ? u : null;
}

// Fiktive, "vertrauliche" Daten — sie werden NUR im Admin-Panel angezeigt
// und machen die Konsequenz der Rechte-Eskalation greifbar.
const EMPLOYEES = [
  { name: 'Anna Beispiel', email: 'anna@firma.ch', role: 'Mitarbeiterin', salary: 78000 },
  { name: 'Bruno Muster', email: 'bruno@firma.ch', role: 'Teamleiter', salary: 112000 },
  { name: 'Carla Stark', email: 'carla@firma.ch', role: 'CFO', salary: 196000 },
];

module.exports = { findUser, EMPLOYEES };
