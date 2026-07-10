---
tags: [secops, cryptography, privacy, paranoia]
---
# Anti-Forensik & Privacy (SecOps)

Als isolierter KI-Buddy muss NEOTH extrem defensive OPSEC-Praktiken anwenden.

## Zeroizing & Memory Protection
- **`zeroize` Crate:** Alle ephemeren Prompts, unverschlüsselten Datenbank-Queries und Krypto-Keys müssen `ZeroizeOnDrop` implementieren.
- **Paging verhindern:** Schlüssel im RAM müssen via OS-Level-Locks (`mlock` auf Linux) vor dem Auslagern ins Pagefile/Swap geschützt werden.

## Plausible Deniability
- NEOTH implementiert Hidden Volumes. 
- Bei der Passworteingabe kann ein Dummy-Passwort verwendet werden, welches nur harmlose Programmier-Projekte anzeigt.
- Ein kombiniertes Duress-Passwort + YubiKey HMAC Challenge-Response schaltet den wahren SecOps-Vault frei.

## SQLite WAL & Secure Delete
- **Secure Delete:** `PRAGMA secure_delete=FAST` ist zwingend aktiv, um Fragmente auf dem Laufwerk zu überschreiben.
- Der Master-Key liegt nicht auf der Festplatte, sondern wird an TPM 2.0 PCRs (Platform Configuration Registers) gebunden.
