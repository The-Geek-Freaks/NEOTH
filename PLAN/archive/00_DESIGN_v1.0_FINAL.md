# NEOTH — Design v1.0 FINAL

> **Project name locked: NEOTH** (Neo-Thoth, Egyptian god of writing/memory/knowledge, modernized).
> **Status:** Build-ready. Day-1 operator-GO away.
> **Tagline:** *Neoth knows.* (alt: *Dein Kumpel mit Gedächtnis.*)

---

## 0. Naming

| Was | NEOTH |
|-----|-------|
| Project | NEOTH |
| Project dir | `<your-workspace>\NEOTH\` (rename from `AGENTER\` pending operator action) |
| Binary | `neothd` |
| CLI | `neoth` (verb-form: `neoth recall`, `neoth profile`) |
| Config | `~/.neoth/` |
| WAL magic | `b"NEOT"` (4 ASCII bytes) |
| Brand | friendly companion with depth — Kumpel-vibe, not corporate-AI |
| Logo concept | minimalist ibis silhouette (Thoth's sacred bird) + abstract "N" mark — or pure typographic |
| Color palette | open (deferred to design pass) |
| Voice | blunt-direct DE / clean EN code & commits — matches the operator's LOWKEY baseline already in Block-B |
| Etymology | "Neo" (new) + "Thoth" (Egyptian deity of memory, writing, knowledge, judgment, scribe of the gods) = the modern incarnation of the memory-keeper |

**Why Neoth beats the prior candidates:**
- Friendly without being cutesy (vs Buddy/Kumpel literal — too casual for production)
- Mythological depth without name-dropping (vs Munin/Mimir/Hekate — too obvious mythology)
- 5 letters, hard consonants → memorable
- Googleable virgin term (no major AI product collision in my training data)
- Reads as a real proper-noun, not an acronym

---

## 1. Diff vs v0.9

Only rename. Architecture/spec/feature-list identical to v0.9.

| v0.9 (MUNIN) | v1.0 (NEOTH) |
|--------------|--------------|
| `muninnd` | `neothd` |
| `munin` CLI | `neoth` CLI |
| `~/.munin/` | `~/.neoth/` |
| `b"MUNN"` | `b"NEOT"` |
| "Munin remembers" | "Neoth knows" |
| raven iconography | ibis (Thoth's sacred bird) or pure typographic |

All other v0.9 decisions stand. Specifically retained:
- 96-byte WAL EventHeader (SPEC_wire_header_v2_slim.md)
- WAL lifecycle (SPEC_wal_lifecycle.md)
- HLC multi-node clock (SPEC_multinode_clock.md)
- Phase-3 cutover runbook (RUNBOOK_phase3_cutover.md)
- Recall-parity methodology (SPEC_recall_parity_methodology.md)
- Channel adapters (SPEC_channels.md)
- Mirror refusal (SPEC_mirror_refusal.md)
- Skill+Plugin system (SPEC_skill_plugin_system.md)
- Proactive user-profile learning (SPEC_proactive_learning.md) — **the core feature this rename was triggered by**
- Tool-Framework v4.1 foundation (tool_framework_v4_1.md)

---

## 2. Six brain regions (unchanged from v0.9)

| Value | Region | View | Single-writer | Purpose |
|-------|--------|------|---------------|---------|
| 0 | None | — | — | default for events that don't fit a region |
| 1 | Hippocampus | idx_episode | no | episodic memory (Daily/Sessions) |
| 2 | Amygdala | idx_importance | yes | importance scoring, ≥ 0.75 promotion |
| 3 | Insula | idx_council | no | council rounds + verdicts |
| 4 | Cerebellum | idx_motor | yes | provider call stats |
| 5 | BasalGanglia | idx_habit | no | tool-router + skill keyword index |
| 6 | Hypothalamus | idx_profile | yes | **user-profile state (long-term, slow-drift)** |

---

## 3. CLI Surface (renamed throughout)

```
# Health + status
neoth status                          # daemon health, channel-state, queue lengths
neoth metrics --since 24h
neoth doctor                          # diagnostic, WAL integrity check

# Recall + memory
neoth recall "what did the operator say about WiFi last week"
neoth recall --since=2026-05-01 --top-k=10

# Profile (the core feature)
neoth profile show                    # confidence-sorted current state
neoth profile show --raw              # full WAL trace per claim
neoth profile show --injected         # what's in Block-B right now
neoth profile redact identity.location
neoth profile pause --scope=session|forever
neoth profile resume
neoth profile export --format=json|md
neoth profile inspect <event_id>      # extraction-reasoning + window

# Skills + plugins
neoth skill list / enable / disable
neoth plugin install ./needle.wasm
neoth plugin list

# Channels
neoth channel list / pause / resume

# Council
neoth council invoke --task "stress-test design" --rounds=3
neoth council history --since 7d

# WAL admin
neoth wal verify / rotate / compact / export

# Migration (Phase 3)
neoth migrate dry-run
neoth migrate import-jarvis ~/.openclaw
neoth migrate parity-check
neoth cutover authorize                 # YubiKey/TOTP gated
neoth rollback authorize                # same 2FA

# Settings
neoth freedom show / set
neoth settings show
```

---

## 4. Day-1 Command (updated)

```
cd <your-workspace>\NEOTH\SRC      # after dir rename
cargo new neothd
cd neothd
cargo add tokio --features="full"
cargo add serde --features="derive"
cargo add serde_json serde_yaml
cargo add thiserror anyhow
cargo add tracing tracing-subscriber --features="env-filter,json"
cargo add crc32c xxhash-rust --features="xxh3"
cargo add uuid --features="v4 v7"
# 11 deps total — NO ring/rustls/hyper/reqwest/teloxide/candle/wasmtime/memmap2 at Day 1
mkdir -p src/{wal,memory,channels,pipelines,tools,plugins,council,brain,context_engine,profile}
mkdir -p ~/.neoth/{skills,plugins,memory,vectors}
touch ~/.neoth/soul.md ~/.neoth/claude.md ~/.neoth/freedom.yaml
echo 'Neoth v1.0 — Day 1' > src/main.rs
cargo build --release   # target ≤ 30s
```

WAL writer Day 2 emits magic `b"NEOT"` + 96-byte header + CRC32c + HLC + LE wire format.

---

## 5. Operator Actions Pending

1. **Confirm NEOTH** as final name — done if you're reading this and didn't object.
2. **Directory rename** `<your-workspace>\AGENTER\` → `<your-workspace>\NEOTH\` — operator-destructive (renames workspace). Confirm to execute.
3. **Day-30 MVP scope confirmation:** Telegram-only + Left-Claude + recall=Keyword+Top-K-cosine. Profile-learning lands Phase 2 Day 38-42. OK?
4. **GitHub-PAT revocation** (standing since v0.5): `ghp_OVViPfYc6Y...` in `~/.openclaw-git-mirror/.git/config` on Jarvis VM. Revoke + rotate before any push from Neoth.

---

## 6. Brand-Voice Note (the Kumpel-vibe)

User explicitly compared NEOTH to "Buddy, Kumpel". The voice/persona should reflect that — not just architecturally but in every operator-facing string:

- Banner: `Neoth ready. Sup.` (not "Neoth daemon initialized successfully")
- Status: `Neoth → Telegram: online | WAL: 12 segments | Profile: 47 fields tracking` (not corporate-monitoring style)
- Errors: `Neoth: kann grad nicht — provider claude antwortet nicht. Versuche codex?` (not "ERROR: provider unavailable")
- Refusal-Mirror (per SPEC_mirror_refusal.md): tone stays direct + Kumpel-like, not bureaucratic

This is a **brand-voice constraint**, not a hard spec — but every CLI output, log message, channel-egress copy should pass the "would a Kumpel say this?" test.

---

## 7. Status

NEOTH v1.0 = MUNIN v0.9 + rename. All specs in PLAN/ remain authoritative. Architecture frozen. Day-1 awaits operator GO.

`Neoth knows.`
