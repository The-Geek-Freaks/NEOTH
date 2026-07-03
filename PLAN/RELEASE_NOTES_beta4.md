# NEOTH 1.0.0-beta.4 — first public release candidate

**NEOTH is a local-first personal AI daemon in Rust.** One memory, three
role-bound brain paths, five memory tiers plus your vault, and a signed audit
log for every sensitive action. Simple enough for a normal user (GUI wizard,
no YAML), serious enough for an operator (CLI, local models, WAL, plugins,
private mesh).

This is the first public release candidate. Beta.4 supersedes beta.1/beta.2/
beta.3 only to rebuild release artifacts with current GitHub macOS runner
labels, portable macOS checksum generation, and Windows-safe tag output. It is
not on crates.io yet
(`cargo install neoth` lands with 1.0) — install from source or the bootstrap
script.

## Why look at this over the other personal-AI projects

Everything below is a mechanism you can verify on your own machine, not a
slogan. See [the 15-minute skeptic's path](https://github.com/The-Geek-Freaks/NEOTH/blob/main/docs/evaluation.md).

- **It predicts its own collapse.** The Babel-Index scores NEOTH's own event
  stream for degradation (retry storms, agent loops, context death spirals),
  warns before the failure, self-calibrates, and reports a Brier score. Built
  on the open [delta-kosmologie](https://github.com/The-Geek-Freaks/delta-kosmologie)
  research framework. No other assistant ships this.
- **HMAC-chained audit you can verify** — `neoth verify` recomputes the whole
  chain; tamper with a frame and it fails.
- **Fail-closed by default** — cloud calls, profile-to-cloud extraction, and
  channel egress are denied until you grant them once, and both grant and
  refusal are logged.
- **WASM plugin capability sandbox** — a plugin can only use the hostcalls you
  approved; over-level calls are refused at runtime and audited.
- **Bring your history** — `neoth-migrate` imports Claude Code / Codex / Gemini
  sessions as searchable memory.

## Install

```bash
# Linux/macOS
curl -fsSL https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/SRC/install.sh | bash
neoth gui

# From source
git clone https://github.com/The-Geek-Freaks/NEOTH
cd NEOTH/SRC && cargo install --path neothd && neoth doctor
```

## Honest status

NEOTH is pre-1.0 and the README comparison marks unfinished things **Partial**
or **Goal**, not Yes. Live cross-device memory sync is still in progress; the
WASM host is feature-gated on native targets. Everything marked done is
exercised by tests. Full status: [PROGRESS_v1_0.md](https://github.com/The-Geek-Freaks/NEOTH/blob/main/PLAN/PROGRESS_v1_0.md).

Dual-licensed MIT OR Apache-2.0. Issues and discussion welcome — this is the
release where outside eyes matter most.
