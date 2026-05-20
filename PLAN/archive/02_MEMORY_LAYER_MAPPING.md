# Memory Layer Mapping — alt (Jarvis) → neu (NEOTH)

> **Reference document.** Captures analysis or synthesis at a specific point in time.
> The normative current state lives in `00_DESIGN_v1.1_FINAL.md` plus the `SPEC_*.md`
> files. Use this for context; not build instructions.

Ziel: jeder Datentyp aus dem 12-Store-Chaos hat einen klaren Pfad in das neue 1-WAL-12-Views-Modell.

| Jarvis-Quelle | Pfad alt | NEOTH-Sicht | Migration |
|--------------|----------|---------------|-----------|
| Obsidian Vault | `/mnt/obsidian/Jarvis/**/*.md` | L4 (mirror) — bidirektional | walk → 1 event/Datei + 1 event/Chunk |
| Smart-Connections `.smart-env/multi` | `.../multi/*.ajson` (1014 files) | L7 (vector-index) | parse ajson → re-embed bei dim-mismatch, sonst direkt nach `vectors.bin` |
| Hippocampus Core MD | `~/.openclaw/workspace/HIPPOCAMPUS_CORE.md` | L5 (hippocampus) | importance ≥ threshold → flag im Event |
| Hippocampus index.json | `~/.openclaw/workspace/memory/index.json` | L1 + L2 + L5 | row → event mit importance + scope-Tag |
| Hippo-turbo vectors | `~/.openclaw/workspace/memory/hippo-turbo-vectors.json` | L7 | re-pack als binary in `vectors.bin` |
| LanceDB-Pro | `~/.openclaw/memory/lancedb-pro` | L1 + L7 + L8 (metadata→graph) | row → event, vector → vectors.bin |
| LanceDB-Pro Plugin (sekundär) | `~/.openclaw/plugins/memory-lancedb-pro/...` | dedup → L1 + L7 | dedup gegen hash(payload+ts) |
| qmd | `~/.config/qmd/*` | L1 + L7 | re-embed wenn dim ≠ 1536 |
| OpenClaw Session-MD | `~/.openclaw/workspace/memory/*.md` | L9 (session-bucket) | parse session_uuid aus Pfad → events |
| OpenClaw Cache | `~/.openclaw/cache/skill-md-cache.json` etc. | nicht migrieren (volatil) | regeneriert sich |
| context-mode FTS5 | `~/.context-mode/*.db` | L1 + L10 (FTS) | text → event, FTS-Index baut neu |
| cq | `~/.cq/local.db` | L1 + L11 (cross-session) | row → event mit scope=COMMONS |
| github-backup | `~/github-backup/MEMORY.md`, `MEMORY_MATRIX.md` | L1 + L12 (git-mirror) | git history → time-ordered events |
| Claude CLI Session JSONL | `~/.claude/projects/.../*.jsonl` | L9 + L1 | one event per turn |
| `~/memory/RESEARCH_LOG.md` | `~/memory/*` | L1 + L4 | walk → events |

## De-Duplication Strategy

Jede Migration emittiert Event mit `dedup_key = SHA-256(normalized_text + scope + source_origin)`. Beim Append:
1. WAL-writer schaut in `idx_dedup.bin` (8-byte Hash → event_id)
2. Wenn existiert → emit REINFORCE (counter +1) statt new RAW_TEXT
3. Sonst → new event_id + append

Verhindert: 7 LanceDB-Migrationen + 4 Vault-Re-Imports + 2 Hippo-Mirrors = trotzdem nur 1 event pro real-unique payload.

## Importance Reconciliation

Verschiedene Stores haben verschiedene Importance-Skalen:
- LanceDB: 0.0–1.0 float
- Hippocampus: 0.75 cutoff, 0.0–1.0
- Smart-Connections: cosine similarity, nicht importance
- qmd: kein importance-feld

Migration berechnet importance als Max:
```
importance_new = max(
  importance_lance,
  importance_hippo,
  0.5 if in_smart_env else 0,
  0.4 if reinforced_count > 5 else 0,
  0.3 default
)
```

## Vector Dimension Handling

Aktuell mischen sich:
- LanceDB-Pro: 1536-dim (OpenAI text-embedding-3 oder Ada-002 style)
- qmd: 1024-dim (Qwen3-Embedding-0.6B native)
- Smart-Connections: variable (Plugin-spezifisch)

**Entscheidung Phase 1:** Re-embed alles mit Qwen3-Embedding-0.6B-Q8 (1024-dim) als Standard.
**Begründung:** locally-runnable, kein API-Cost, ausreichend für Recall < 10ms p95.
**Fallback Phase 2:** dual-vector pro event (1024-Qwen + optional 1536-OpenAI für Cross-Reference).
