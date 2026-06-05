# Präsentation — Folien-Inhalt (zum Reinkopieren in Pages)

JWT Algorithm Confusion · OWASP A07:2025 · CVE-2022-23541
Nur Stichpunkte, kein Sprechertext. ~12 Folien, ca. 8–10 Min.

---

## Folie 1 — Titel

- **JWT Algorithm Confusion**
- RS256 → HS256: vom normalen User zum Admin — ohne Passwort
- OWASP Top 10 — A07:2025: Authentication Failures
- Modul Applikationssicherheit · [Name] · [Datum]

---

## Folie 2 — Was ist ein JWT?

- JSON Web Token: drei Base64url-Teile, durch Punkte getrennt
- **Header** (alg, typ) · **Payload** (Claims, z. B. `role`) · **Signatur**
- Header und Payload sind nur kodiert — nicht verschlüsselt
- Wichtig: Der **Header ist nicht signiert** → vom Aufrufer frei setzbar
- Im Header steht `alg` — der verwendete Signatur-Algorithmus

---

## Folie 3 — RS256 vs. HS256

- **RS256 (asymmetrisch):** privater Schlüssel signiert, öffentlicher prüft
  - der öffentliche Schlüssel ist bewusst **kein Geheimnis**
- **HS256 (symmetrisch):** ein gemeinsames Geheimnis signiert **und** prüft (HMAC)
- Merke: Bei HS256 kann jeder, der das Secret kennt, auch signieren

---

## Folie 4 — Der Trick: Algorithm Confusion

- Der Server erwartet RS256 und hat nur den **öffentlichen** Schlüssel
- Vertraut er dem `alg` aus dem Header? → Angreifer setzt `alg = HS256`
- Der Server nutzt nun den öffentlichen Schlüssel als **HMAC-Secret**
- Dieser Schlüssel ist öffentlich → der Angreifer kann selbst gültig signieren
- Aus „nur prüfen können" wird „auch fälschen können"

---

## Folie 5 — CVE-2022-23541 (Fakten)

- Bibliothek: **`jsonwebtoken`** (Node.js, gepflegt von Auth0/Okta)
- Betroffen: **≤ 8.5.1** · Fix in **9.0.0**
- Ein RSA-signiertes Token konnte mit HS256 verifiziert werden → Token fälschbar
- **CVSS 5.0** (Moderate) · **CWE-287** (Improper Authentication)
- Offengelegt: 21.12.2022

---

## Folie 6 — Wo es real auftrat

- `jsonwebtoken` ist eine der **meistgenutzten** JWT-Bibliotheken
  - ~9 Mio. Downloads/Woche, 20'000+ abhängige Pakete
- Die Lücke steckte potenziell in **unzähligen Produktionssystemen**
- Auth0/Okta und Downstream-Hersteller (z. B. IBM) gaben Security-Bulletins heraus
- Ursprung dieser Angriffsklasse: bereits **2015** (Auth0, Tim McLean)

---

## Folie 7 — Unser Szenario: Mitarbeiter-Portal

- Kleine Web-App: Login → JWT im Cookie → Panel
- Normaler User („Anna", `role: user`) sieht „Meine Daten"
- Admin sähe „alle Mitarbeitenden + Gehaltsliste"
- Es existiert **kein Admin-Konto** — und wir kommen trotzdem rein
- → jetzt live

---

## Folie 8 — Der Angriff in 4 Schritten

1. Als User einloggen → RS256-Token landet im **Cookie**
2. Token kopieren → auf **jwt.io**: `alg → HS256`, `role → admin`
3. Mit dem **öffentlichen Schlüssel als Secret** neu signieren
4. Token zurück in den Cookie → **neu laden** → Admin-Panel
- Ergebnis: Admin-Zugriff ohne Passwort, ohne privaten Schlüssel

---

## Folie 9 — Die verwundbare Zeile (src/auth.js)

```js
// Algorithmus aus dem (angreifer-kontrollierten) Header:
const alg = jwt.decode(token, { complete: true }).header.alg;
return jwt.verify(token, publicKey, { algorithms: [alg] });
```

- Der erlaubte Algorithmus kommt aus dem Token — also vom Angreifer

---

## Folie 10 — Der Fix (eine Zeile)

```js
// Algorithmus serverseitig fest vorgeben, Header ignorieren:
return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

- Ein HS256-Token fliegt jetzt mit „invalid algorithm" raus

---

## Folie 11 — Einordnung & Merksatz

- **OWASP A07:2025** — Authentication Failures
- **CWE-303** (fehlerhafte Implementierung des Auth-Algorithmus), Oberbegriff **CWE-287**
- **Merksatz:** Vertraue beim Prüfen einer Signatur nie dem Algorithmus aus der
  Eingabe — `algorithms` immer explizit setzen
- Abhängigkeiten aktuell halten — neuere Versionen verhindern den Angriff

---

## Folie 12 — Quellen / Danke

- owasp.org/Top10/2025/A07_2025-Authentication_Failures/
- GitHub Advisory GHSA-hjrf-2m68-5959 (CVE-2022-23541)
- Auth0/Okta Security Bulletin, 21.12.2022
- PortSwigger Web Security Academy — „Algorithm confusion"
- Danke · Fragen?
