---
tags: [profile, ground_truth, memory]
---
# Ground Truth

Dieses Verzeichnis repräsentiert unumstößliche Fakten, die vom Hebbian Decay (dem automatischen Vergessen über Zeit) ausgeschlossen sind.

## Core Directives
1. **Local-First & Fail-Closed:** Wenn ein lokales Modell fehlt, wird NIE stillschweigend auf eine Cloud-API ausgewichen.
2. **No npm install:** Plugins müssen als WASM (WebAssembly) oder Rust-Binaries bereitgestellt werden.
3. **Audit Trail:** Jede sicherheitsrelevante Aktion MUSS im WAL (`neoth wal`) mit einem Intent/Result Event-Pairing geloggt werden.

## Operator Baseline
*(Hier werden Fakten über den User gespeichert, die dieser explizit gepinnt hat, z.B. kryptografische Public Keys, bevorzugte Identitäten, No-Go-Themen.)*
