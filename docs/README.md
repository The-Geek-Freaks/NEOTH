# NEOTH Docs

*Neoth knows.*

NEOTH is a Rust-based personal AI agent — single binary, runs on your machine, connects to
Telegram/WhatsApp/Slack, remembers you, and gets smarter over time. Privacy-first.

---

## Pages

| Page | What it covers |
|------|---------------|
| [getting-started.md](getting-started.md) | Install, first run, first chat — 10 minutes |
| [install.md](install.md) | Platform-specific install notes |
| [configuration.md](configuration.md) | Every config file explained with all fields annotated |
| [channels.md](channels.md) | Connecting Telegram, WhatsApp, Slack, Discord, Keet |
| [providers.md](providers.md) | Claude, OpenAI, Gemini, local model setup |
| [profile.md](profile.md) | How Neoth learns you, privacy controls, GDPR delete |
| [council.md](council.md) | Multi-LLM debate feature — when and how it fires |
| [plugins.md](plugins.md) | Skills and plugins — extending Neoth |
| [local-models.md](local-models.md) | Running Qwen / Ouro / CLIP / Whisper on your GPU |
| [cron-vs-n8n.md](cron-vs-n8n.md) | When to use the built-in cron vs the n8n localhost API |
| [n8n-api.md](n8n-api.md) | Loopback HTTP API endpoints, auth, examples, audit trail |
| [import-format.md](import-format.md) | Bulk-import shape for ground-truth seeding |
| [live-e2e-protocol.md](live-e2e-protocol.md) | End-to-end channel verification protocol |
| [architecture.md](architecture.md) | How it all works — block diagram, WAL, brain regions |
| [faq.md](faq.md) | Common questions answered directly |
| [troubleshooting.md](troubleshooting.md) | Common errors and how to fix them |
| [cli-reference.md](cli-reference.md) | Every `neoth` command documented |

---

## Quick orientation

**v0.2 ship (current main):** Single binary runs the full daily loop —
CLI + GUI + Telegram + WhatsApp + Slack + Discord + Keet channels;
operator-cached multimodal pipeline (PDF / image / audio / video);
three-hemisphere council with smart-trigger budgeting; n8n localhost
HTTP API for workflow automation; WAL-audited everything. Public
release-candidate from commit `83d60a9` — 4240 tests passing, 0 deferred items.

**Developers:** The `PLAN/` directory contains full internal specs — wire format, type design,
anti-pattern tests. The `docs/` you're reading now is for users and operators.

**What changed since v0.1:** see the top of [the root README](../README.md#whats-new-in-v02-session-23-ship)
for the K / D / H / I workstream ship summary.

---

## License

Apache 2.0. See `LICENSE` in the repo root.
