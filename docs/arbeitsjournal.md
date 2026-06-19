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
