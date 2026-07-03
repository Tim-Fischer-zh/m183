# ChaCha20 — Ablauf (visuell)

Diese Diagramme zeigen den Ablauf von ChaCha20, so wie er im Code umgesetzt ist. Gedacht für die Präsentation.

## Gesamtablauf

```mermaid
flowchart TD
    C["Konstanten<br/>4 Wörter"]
    K["Schlüssel<br/>8 Wörter, little-endian"]
    CTR["Zähler<br/>1 Wort"]
    N["Nonce<br/>3 Wörter, little-endian"]

    C --> STATE["State aufbauen<br/>16 Wörter, 4x4"]
    K --> STATE
    CTR --> STATE
    N --> STATE

    STATE --> COPY["Kopie des States sichern"]
    COPY --> ROUNDS["10 Doppelrunden<br/>= 20 Runden"]
    ROUNDS --> ADD["Kopie wortweise dazu-addieren"]
    ADD --> SER["little-endian serialisieren<br/>64 Byte Keystream"]

    PT["Klartext"] --> XOR["Klartext XOR Keystream"]
    SER --> XOR
    XOR --> OUT["Ciphertext"]
```

## Eine Doppelrunde

```mermaid
flowchart TB
    subgraph SP["Spalten-Runde"]
        direction TB
        S1["QuarterRound(0, 4, 8, 12)"]
        S2["QuarterRound(1, 5, 9, 13)"]
        S3["QuarterRound(2, 6, 10, 14)"]
        S4["QuarterRound(3, 7, 11, 15)"]
        S1 --> S2 --> S3 --> S4
    end
    subgraph DI["Diagonal-Runde"]
        direction TB
        D1["QuarterRound(0, 5, 10, 15)"]
        D2["QuarterRound(1, 6, 11, 12)"]
        D3["QuarterRound(2, 7, 8, 13)"]
        D4["QuarterRound(3, 4, 9, 14)"]
        D1 --> D2 --> D3 --> D4
    end
    SP --> DI
```

Diese Doppelrunde wird 10-mal wiederholt, das ergibt die 20 Runden.

## Die Quarter-Round (ARX)

```mermaid
flowchart TD
    Q1["a += b   d ^= a   d = RotL(d, 16)"]
    Q2["c += d   b ^= c   b = RotL(b, 12)"]
    Q3["a += b   d ^= a   d = RotL(d, 8)"]
    Q4["c += d   b ^= c   b = RotL(b, 7)"]
    Q1 --> Q2 --> Q3 --> Q4
```

Nur Addition mod 2^32, XOR und Rotation nach links. Kein Galois-Feld, keine Tabellen. Das ist der ganze Trick von ChaCha20.
