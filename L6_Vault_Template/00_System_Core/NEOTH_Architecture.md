---
tags: [core, architecture, memory, brain]
---
# NEOTH Architektur

NEOTH arbeitet mit einem **Hemisphären-Modell**:
- **Left Hemisphere (Analytisch):** Standard-Provider. Einziger Kanal mit User-Egress.
- **Right Hemisphere (Kreativ):** Zweiter Provider. Zuständig für Pattern-Matching.
- **Corpus Callosum (Arbiter):** Drittes Modell, welches bei Diskrepanzen zwischen Left und Right entscheidet (Council).

## Die 6 Memory Tiers
1. **L1 Hot Working Set:** Active Chat, Current Task (Canvas).
2. **L2 Warm Cache:** Recent Recall, Active Project Facts.
3. **L3 Episodic Memory:** Conversations, Events, Timelines (`idx_episode`).
4. **L4 Semantic Memory:** Vector-Embeddings (`idx_embedding`).
5. **L5 Skills & Habits:** Routines, Trigger Patterns (`idx_habit`).
6. **L6 Vault Mirror:** Dieses Obsidian-Wiki. Langzeit-Archiv, human-readable.

## Babel-Index (Collapse Prediction)
NEOTH überwacht 7 Variablen im WAL-Stream (z.B. Coupling Density, Convergence Pressure, Resource Pressure), um Endlos-Schleifen oder Agent-Kollapse vorherzusagen, *bevor* sie eintreten.
