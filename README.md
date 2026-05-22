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
