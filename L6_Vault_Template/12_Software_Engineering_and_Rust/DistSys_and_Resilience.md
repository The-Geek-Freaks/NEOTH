---
tags: [distsys, resilience, offline, crdt]
---
# Distributed Systems & Offline Resilience

NEOTH läuft primär offline und muss Netzwerkausfälle sowie Systemabstürze elegant überleben.

## CRDTs für Code-Generierung
- Wir nutzen **Sequence/Text CRDTs** (ähnlich Yjs/Fugue) für den Abstract Syntax Tree (AST) beim Code-Schreiben.
- Dadurch lassen sich Änderungen konfliktfrei mergen, selbst wenn NEOTH und der Operator gleichzeitig im selben File arbeiten.

## OOM-Survival (Out-Of-Memory)
- **Cgroup Monitoring:** NEOTH liest `memory.pressure` (cgroups v2). Bevor der Linux OOM-Killer zuschlägt, werden präemptiv VRAM/KV-Caches und unwichtige Agenten ("Shedding") gedroppt.
- **Emergency Memory Pools:** Vorab allokierter Speicher für sichere Shutdown-Routinen (WAL Flushing).

## WAL Recovery
- Nach Kernel-Panics kann der SQLite-Index beschädigt sein. NEOTH implementiert **B-Tree Scraping** (Magic Number Recovery), um rohe LLM-Kontexte und Zielsetzungen direkt aus den Fragmenten zu kratzen.
