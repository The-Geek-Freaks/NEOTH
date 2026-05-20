# Changelog

All notable changes to NEOTH are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Day-1 cargo workspace, `neothd` binary, panic handler, banner
- Day-3 CLI scaffolding via clap 4.5 (`neoth init` wizard skeleton)
- `freedom.yaml` and `policy.yaml` templates (operator-agnostic)
- `umask 0o077` startup hardening (unix)
- Tracing via `tracing-subscriber` with `NEOTH_LOG` env filter
- Rust 2024 edition, MSRV 1.86

### Documentation
- 23 normative specs in `PLAN/` covering wire format, WAL lifecycle, skill plugins, proactive learning, recall parity, local inference, council governance, channels, profile claim guard, mirror refusal
- Adversarial review reports in `PLAN/ADVERSARIAL/` (10 agent reports + summary)
- User-facing docs in `docs/` (getting-started, configuration, channels, profile, council, plugins, local-models, architecture, faq, troubleshooting, cli-reference)
- Install scripts for Linux/macOS (`scripts/install.sh`) and Windows (`scripts/install.ps1`)

### Security
- Initial threat model documented in `SECURITY.md`
- Adversarial findings catalogued (S/H/A class) with status in `PLAN/ADVERSARIAL/00_SUMMARY.md`

## [0.1.0] — Unreleased

First public preview. Not yet feature-complete. Daemon builds green, CLI wizard scaffolded, WAL writer pending.

**What works (Day-1 -> Day-3):**
- `neothd` builds and runs, prints banner
- `neoth init` wizard skeleton (interactive prompts not yet wired to disk writes)
- CLI subcommand structure via clap

**What does not work yet:**
- WAL writer (Day-2 -- pending)
- Telegram channel (Day-7 -- pending)
- WhatsApp, Slack (Day-8, Day-9 -- pending)
- LLM provider adapters (Day-5 onwards -- pending)
- Local Qwen3-4B inference (Day-14 -- pending)
- Council pipeline (Phase 2 -- pending)
- WASM plugin host (Day-23 -- pending)
- Phase-3 migration tooling (Day-63 -- pending, pure-Rust)

See `PLAN/00_DESIGN_v1.1_FINAL.md` Section 10 for the full Day-1 to Day-90 roadmap.

[Unreleased]: https://github.com/owner/neoth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/owner/neoth/releases/tag/v0.1.0
