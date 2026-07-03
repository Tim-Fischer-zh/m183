# Spec 06 — Encrypt-then-MAC (ISymmetricCipher)

Das ist keine neue Chiffre, sondern die sichere **Komposition** aus einer Stream-Chiffre und einem MAC. Sie liefert **authentifizierte Verschlüsselung**: Vertraulichkeit (die Daten sind verschlüsselt) und Integrität (jede Manipulation wird erkannt).

Anders als die Primitiven ist das reiner Zusammenbau. Trotzdem gibt es Regeln, die man einhalten muss, damit es sicher ist.

---

## 1. Warum überhaupt

Verschlüsselung allein schützt **nicht** vor Manipulation. Ein Angreifer kann Bytes im Ciphertext kippen, und beim Entschlüsseln kommt veränderter Klartext raus, ohne dass es jemand merkt. Bei einer Stream-Chiffre ist das besonders einfach: ein gekipptes Ciphertext-Bit kippt genau das gleiche Klartext-Bit.

Ein **MAC über den Ciphertext** fängt das ab. Stimmt der MAC beim Entschlüsseln nicht, wird abgebrochen.

## 2. Die richtige Reihenfolge: Encrypt-then-MAC

Es gibt drei mögliche Reihenfolgen, nur eine ist allgemein sicher:
- **Encrypt-then-MAC** (richtig): erst verschlüsseln, dann den MAC über den Ciphertext.
- Encrypt-and-MAC / MAC-then-Encrypt: haben bekannte Schwächen.

Der grosse Vorteil: beim Entschlüsseln prüfst du **zuerst den MAC** und entschlüsselst nur, wenn er stimmt. Du fasst also nie manipulierte Daten mit der Chiffre an. Genau das verhindert Angriffe wie das Padding-Oracle.

## 3. Zwei Schlüssel (Schlüsseltrennung)

Denselben Schlüssel für Verschlüsselung **und** MAC zu nehmen ist unsicher. Aus dem einen übergebenen Schlüssel leitest du darum zwei ab, mit deinem HMAC als kleine KDF:
```
encKey = HMAC(masterKey, "enc")     // Schlüssel für die Chiffre
macKey = HMAC(masterKey, "mac")     // Schlüssel für den MAC
```
Beide sind 32 Byte, passt für ChaCha20 und HMAC-SHA256.

## 4. Aufbau

Die Chiffre ist eine **Stream-Chiffre** (ChaCha20), weil sie beliebig lange Daten kann. Die Klasse bekommt Chiffre und MAC per DI:
```
EncryptThenMacCipher(IStreamCipher cipher, IMac mac) : ISymmetricCipher
```
(AES ist eine Block-Chiffre und bräuchte erst einen Modus wie CTR, den wir bewusst weggelassen haben. AES bleibt eigenständig für die Labor-Demos.)

## 5. Ausgabeformat (der Blob)

```
blob = nonce || ciphertext || mac
```
- **nonce**: `cipher.NonceSizeInBytes` Byte (ChaCha20: 12), zufällig pro Aufruf.
- **ciphertext**: gleich lang wie der Klartext.
- **mac**: `mac.MacSizeInBytes` Byte (HMAC-SHA256: 32).

Nonce und MAC-Länge sind fest, darum kann `Decrypt` den Blob eindeutig zerlegen.

## 6. Encrypt

```
encKey = HMAC(key, "enc")
macKey = HMAC(key, "mac")
nonce  = zufällige NonceSizeInBytes Byte   (aus RandomNumberGenerator)
ct     = cipher.Encrypt(encKey, nonce, plaintext)
tag    = mac.ComputeMac(macKey, nonce || ct)
return nonce || ct || tag
```

## 7. Decrypt

```
encKey = HMAC(key, "enc")
macKey = HMAC(key, "mac")

nonce = die ersten NonceSizeInBytes Byte des Blobs
tag   = die letzten MacSizeInBytes Byte des Blobs
ct    = alles dazwischen

wenn NICHT mac.Verify(macKey, nonce || ct, tag):   // constant-time
    wirf eine generische Exception ab   // KEINE Details, kein Entschlüsseln

return cipher.Decrypt(encKey, nonce, ct)
```

Wichtig: **erst prüfen, dann entschlüsseln**. Und bei Fehlern eine generische Exception, keine Meldung, die verrät was genau falsch war.

## 8. Schnittstelle und Tests

`ISymmetricCipher` mit `Encrypt(key, plaintext)` und `Decrypt(key, blob)`. Der Nonce ist intern, der Aufrufer sieht ihn nie.

Tests:
- **Round-Trip**: `Decrypt(Encrypt(x)) == x`.
- **Zwei Verschlüsselungen desselben Klartexts sind verschieden** (frischer Nonce).
- **Manipulation wird erkannt**: ein Byte im Blob kippen, dann muss `Decrypt` abbrechen (Exception).
