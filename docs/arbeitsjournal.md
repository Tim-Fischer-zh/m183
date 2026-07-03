# Arbeitsjournal

Modul 183, eigene Krypto-Library in C#. Hier halte ich fest, woran ich an welchem Tag gearbeitet habe.

## 5. Juni 2026

Projekt aufgesetzt. Statt der einzelnen Kompetenznachweise mache ich ein eigenes Projekt. Eine kleine Krypto-Library, bei der ich die Algorithmen selbst schreibe.

Den Projektantrag für den Lehrer geschrieben. Grundanforderung und Erweiterung sauber getrennt. Das Vorbild ist ASP.NET Core Security.

Danach die Solution angelegt. Drei Teile: Core für die Library, Tests für die Testvektoren, Lab für das Angriffs-Labor. Die Interfaces grob definiert und SHA-256 als leeren Stub angelegt. So laufen die Tests schon rot, bevor ich anfange.

## 7. Juni 2026

Am Padding von SHA-256 gearbeitet. Das war fummelig.

Erst die Nachricht, dann ein 0x80, dann Nullen bis Byte 56. Am Ende die Länge in Bit als 8 Byte big-endian. Höchstwertiges Byte zuerst.

Ich habe lange gebraucht, bis ich verstanden habe, dass die letzten 8 Byte zusammen eine einzige Zahl sind. Nicht sieben Nullen und ein Längen-Byte. Für "abc" kommt jetzt ein korrekter 64-Byte-Block raus.

## 12. Juni 2026

Die Hilfsfunktionen geschrieben.

RotR zuerst, weil die Sigma-Funktionen sie brauchen. Eine Rotation ist ein Shift, bei dem die rausgefallenen Bits vorne wieder reinkommen. Mit einem kleinen Wert geprüft: RotR(0x12345678, 8) ergibt 0x78123456.

Danach Ch, Maj und die vier Sigmas. Das war reines Einsetzen der Formeln. Bei Ch hatte ich im Kommentar einen XOR-Rechenfehler, der Code war aber korrekt.

Zum Schluss die Konstanten reingenommen. Die acht Startwerte und die 64 Rundenkonstanten. Berechnet aus den Wurzeln der ersten Primzahlen und gegen die bekannten Werte geprüft.

## 18. Juni 2026

Am Message Schedule. Den 64-Byte-Block in 16 uint-Wörter zerlegen, big-endian. Danach auf 64 Wörter erweitern mit den kleinen Sigmas.

Als Nächstes kommen die 64-Runden-Kompression und der Output. Dann sollte der erste Testvektor grün werden.

## 19. Juni 2026

SHA-256 fertig gemacht und HMAC dazu. Langer Tag.

Zuerst den Message Schedule fertig. Den Block in 16 Wörter zerlegen, dann auf 64 erweitern. Als zwei Methoden, B1 und B2.

Dann die Kompression. 64 Runden mit T1 und T2. Ich habe gebraucht, bis ich verstanden habe, dass die acht Variablen wie ein Schieberegister laufen. T1 und T2 sind nur zwei Zwischenwerte, die oben und in der Mitte neu reinkommen.

Den Output gebaut. Die acht Wörter als 32 Bytes big-endian.

Dann ein fieser Bug. Meine Pad-Methode hat sich selbst aufgerufen, Endlosschleife. Der ganze Hash-Code war aus Versehen in Pad gelandet. Aufgeräumt, jetzt paddet Pad nur und Hash macht den Rest.

Danach waren leere Eingabe und "abc" grün. Lange Eingaben noch nicht, da fehlte Multi-Block. Das Padding auf ein Vielfaches von 64 verallgemeinert und Hash über alle Blöcke laufen lassen. Alle vier SHA-256 Tests grün.

Dann HMAC angefangen. Im Kern ist das nur zweimal SHA-256, mit dem Schlüssel reingemischt. Schlüssel auf 64 Byte bringen, mit ipad und opad XOR-en, innen und aussen hashen.

Beim Aneinanderhängen habe ich Union erwischt statt Concat. Union wirft Duplikate weg, das gibt Müll. Mit Concat lief es.

Beim Testen den Schlüssel als Text statt als Bytes eingegeben und mich kurz gewundert, warum der Wert nicht passt. Mit den richtigen Byte-Arrays stimmen alle RFC-Vektoren.

Zum Schluss Verify mit dem constant-time Vergleich. HMAC ist durch.

## 22. Juni 2026

Die Interfaces aufgeräumt und committet. Dann PBKDF2 angefangen.

PBKDF2 baut auf HMAC auf. Es ruft HMAC in einer Kette auf und macht das absichtlich oft, damit Passwörter langsam zu knacken sind. Das Passwort ist immer der Schlüssel, der Salt plus ein Blockindex die erste Nachricht.

Zuerst den Blockindex als 4 Byte big-endian an den Salt gehängt. Dann die U-Kette gebaut und alle U zusammen ge-XOR-t. Ich hatte zuerst Passwort und Nachricht im HMAC vertauscht und die Schleife falsch gestartet. Nach dem Fix lief es.

Beim Testen kam jedes Mal ein anderer Wert raus. Kurz erschrocken, aber das war richtig so. Hash erzeugt jedes Mal einen neuen zufälligen Salt. Zum Prüfen gegen die Testvektoren braucht es einen festen Salt über die innere Methode.

Mit festem Salt stimmt der erste Testvektor. Die innere Methode ist gerade noch public zum Testen, das mache ich später wieder private.

Als Nächstes Multi-Block, dann Hash und Verify fertig machen.

## 26. Juni 2026

PBKDF2 fertig gemacht.

Verify gebaut: den gespeicherten String zerlegen, mit demselben Salt und derselben Iterationszahl neu rechnen, dann vergleichen. Zuerst hatte ich `SequenceEqual` genommen. Das ist aber nicht constant-time, es bricht beim ersten unterschiedlichen Byte ab und verrät damit über die Laufzeit etwas. Auf den diff-Vergleich umgestellt, denselben wie bei HMAC.

Multi-Block für längere Ausgaben habe ich weggelassen. Der Passwort-Hash braucht nur einen Block, und der Quervergleich gegen die .NET-Referenz beweist die Korrektheit schon.

Alle Tests grün. PBKDF2 ist durch.

## 30. Juni 2026

AES-256, der grösste Brocken. Der hat mit Abstand am meisten Teile.

Angefangen mit xtime, der Multiplikation mit 2 im Galois-Feld. Ein Linksshift, und wenn oben ein Bit rausfällt, XOR mit 0x1b. Den 0x80-Fall als Test, da greift die Reduktion.

S-Box und Rcon als Konstanten reingenommen, beide verifiziert.

Dann die vier Operationen. SubBytes ersetzt jedes Byte über die S-Box. ShiftRows rotiert die Zeilen nach links. MixColumns ist die GF-Rechnung mit xtime. AddRoundKey ist nur ein XOR mit dem Rundenschlüssel. Ein paar Tippfehler unterwegs: bei MixColumns `XTime(a1)` statt `XTime(a2)`, bei ShiftRows hatte ich temp als einzelnes Byte statt als ganze Zeile.

Die Schlüsselexpansion war am kniffligsten. Aus 32 Byte werden 60 Wörter. Ich hatte die Bedingung `i % 4 == i` statt `i % 8 == 4` geschrieben, die nie wahr wird, und das Wort-XOR im falschen Zweig statt für jedes Wort.

EncryptBlock setzt alles zusammen. State spaltenweise laden, AddRoundKey, dann 13 volle Runden, die letzte ohne MixColumns, dann ausgeben.

Der FIPS-Testvektor stimmt, und der Quervergleich gegen die .NET-AES mit 100 Zufallsblöcken auch. AES ist durch.

Als Nächstes ChaCha20, der zweite Verschlüsseler.

## 3. Juli 2026

Viel geschafft. ChaCha20 fertig, die Interfaces aufgeräumt und die authentifizierte Verschlüsselung dazu.

ChaCha20 ist eine Stream-Chiffre, viel einfacher als AES. Nur Addition, Rotation und XOR auf 32-Bit-Wörtern, kein Galois-Feld. RotL ist mein RotR gespiegelt, die Quarter-Round eine kurze feste Sequenz. Wichtig war little-endian, genau umgekehrt zu SHA-256.

Beim Testen kam ein falscher Keystream raus, obwohl der Round-Trip passte. Der Fehler war eindeutig: ich hatte die 20 Runden komplett vergessen. Ich habe den State geklont und sofort wieder dazu-addiert, ohne zu mischen. Das hat jedes Wort nur verdoppelt. Mit der Runden-Schleife dazwischen stimmt der RFC-Vektor.

Dann die Interfaces. AES und ChaCha20 hatten noch keins. AES hat jetzt IBlockCipher, ChaCha20 hat IStreamCipher. Kein gemeinsames Interface, jedes passend zu seiner Art. AES musste ich von einer statischen Methode auf eine Instanzmethode umstellen, damit es per DI geht.

Zum Schluss die authentifizierte Verschlüsselung, Encrypt-then-MAC. Keine neue Chiffre, sondern Komposition: erst mit ChaCha20 verschlüsseln, dann einen HMAC über das Ergebnis. Beim Entschlüsseln erst den MAC prüfen, dann entschlüsseln. Zwei getrennte Schlüssel, aus dem einen abgeleitet. Der Test kippt ein Byte im Blob, und das Entschlüsseln bricht ab. Das beweist, dass Manipulation erkannt wird.

Damit ist die ganze Grundanforderung fertig. Alle fünf Primitiven plus die authentifizierte Verschlüsselung, alle gegen offizielle Vektoren geprüft.

Am Schluss noch ein Menü im Lab gebaut, damit die Lehrperson jede Funktion mit eigenen Eingaben ausprobieren kann.

Fürs KI-Log: das Lab-Menü und der ChaCha-Encrypt-Wrapper sind mit KI entstanden, die Krypto-Kerne sind alle von mir.
