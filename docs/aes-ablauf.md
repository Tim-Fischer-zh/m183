# AES-256 — Ablauf (visuell)

Diese Diagramme zeigen den Ablauf der AES-256-Verschlüsselung eines 16-Byte-Blocks, genau so wie er im Code in `Aes256.EncryptBlock` umgesetzt ist. Gedacht für die Präsentation.

## Gesamtablauf

```mermaid
flowchart TD
    IN["Klartext-Block<br/>16 Byte"]
    KEY["Schlüssel<br/>32 Byte"]

    KEY --> KEXP["KeyExpansion<br/>60 Wörter = 15 Rundenschlüssel"]
    IN --> LOAD["State laden<br/>spaltenweise, 4x4"]

    LOAD --> ARK0["AddRoundKey<br/>Runde 0"]
    KEXP --> ARK0

    ARK0 --> LOOP["13 Hauptrunden<br/>Runde 1 bis 13"]
    LOOP --> FIN["Schlussrunde<br/>Runde 14"]
    FIN --> STORE["State ausgeben<br/>spaltenweise"]
    STORE --> OUT["Ciphertext-Block<br/>16 Byte"]
```

## Hauptrunde und Schlussrunde im Vergleich

```mermaid
flowchart LR
    subgraph H["Hauptrunde, Runde 1 bis 13"]
        direction LR
        H1["SubBytes"] --> H2["ShiftRows"] --> H3["MixColumns"] --> H4["AddRoundKey"]
    end
    subgraph S["Schlussrunde, Runde 14"]
        direction LR
        S1["SubBytes"] --> S2["ShiftRows"] --> S3["AddRoundKey"]
    end
```

Der einzige Unterschied: die Schlussrunde hat **kein MixColumns**.

## Was die vier Operationen tun

```mermaid
flowchart TD
    SB["SubBytes<br/>jedes Byte durch die S-Box ersetzen"]
    SR["ShiftRows<br/>jede Zeile nach links rotieren"]
    MC["MixColumns<br/>jede Spalte im Galois-Feld GF(2^8) mischen"]
    AK["AddRoundKey<br/>State mit dem Rundenschlüssel XOR-en"]
    SB --> SR --> MC --> AK
```

## Schlüsselexpansion

```mermaid
flowchart TD
    K["Schlüssel 32 Byte<br/>= Wörter 0 bis 7"] --> LOOP{"für i = 8 bis 59"}
    LOOP --> T["temp = Wort i-1"]
    T --> C0{"i mod 8 == 0?"}
    C0 -->|ja| RS["RotWord, dann SubWord,<br/>dann erstes Byte XOR Rcon"]
    C0 -->|nein| C4{"i mod 8 == 4?"}
    C4 -->|ja| SW["SubWord"]
    C4 -->|nein| SKIP["temp bleibt gleich"]
    RS --> X["Wort i = Wort i-8 XOR temp"]
    SW --> X
    SKIP --> X
    X --> LOOP
```
