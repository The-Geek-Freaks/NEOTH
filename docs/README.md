# NEOTH Docs

*Neoth knows.*

NEOTH is a Rust-based personal AI agent — single binary, runs on your machine, connects to
Telegram/WhatsApp/Slack, remembers you, and gets smarter over time. Privacy-first.

---

## Pages

| Page | What it covers |
|------|---------------|
| [getting-started.md](getting-started.md) | Install, first run, first chat — 10 minutes |
| [configuration.md](configuration.md) | Every config file explained with all fields annotated |
| [channels.md](channels.md) | Connecting Telegram, WhatsApp, Slack |
| [profile.md](profile.md) | How Neoth learns you, privacy controls, GDPR delete |
| [council.md](council.md) | Multi-LLM debate feature — when and how it fires |
| [plugins.md](plugins.md) | Skills and plugins — extending Neoth |
| [local-models.md](local-models.md) | Running Qwen3-4B on your GPU for privacy |
| [architecture.md](architecture.md) | How it all works — block diagram, WAL, brain regions |
| [faq.md](faq.md) | Common questions answered directly |
| [troubleshooting.md](troubleshooting.md) | Common errors and how to fix them |
| [cli-reference.md](cli-reference.md) | Every `neoth` command documented |

---

## Quick orientation

**Day 1 (v0.1.0 MVP):** Telegram + CLI chat + memory recall. That's what ships first.
Everything tagged **(Phase 2)** or later is on the roadmap but not in v0.1.0.

**Developers:** The `PLAN/` directory contains full internal specs — wire format, type design,
anti-pattern tests. The `docs/` you're reading now is for users and operators.

---

## License

Apache 2.0. See `LICENSE` in the repo root.
