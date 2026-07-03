# NEOTH vs Hermes Agent

Hermes Agent's public pitch is strong for operators: an agent that grows with
you, CLI/TUI workflows, persistent memory, skills, MCP, messaging gateway,
cron, tools, and migration from OpenClaw.

NEOTH should win users who want that self-improving operator energy, but with a
more approachable DAU path, local/fail-closed privacy posture, coding canvas,
and a clearer personal buddy identity.

Baseline sources — Hermes Agent capabilities below were assessed **as of 2026-06-07**
against the project's then-current `main` branch and live docs. No tagged release or pinned
commit was published to anchor against, so treat every competitor claim as a point-in-time
snapshot that may have moved since:

- <https://github.com/NousResearch/hermes-agent>
- <https://hermes-agent.nousresearch.com/docs>

## Short version

| If you want... | Pick |
| :-- | :-- |
| CLI/TUI-first self-improving agent workflow | Hermes Agent |
| A private Jarvis-like buddy for normal users and pros, with coding canvas, five-tier memory + vault, and audit-first privacy | NEOTH |

## Capability comparison

| Area | NEOTH | Hermes Agent (as of 2026-06-07) |
| :-- | :-- | :-- |
| Product center | Private buddy plus operator runtime | Agent workflow that grows with usage |
| Normal-user onboarding | GUI wizard, plain privacy choices, no YAML happy path | CLI/TUI and docs-first |
| Memory | Five-tier memory + vault ingest, profile evidence, redaction semantics, WAL | Persistent memory and profiles |
| Coding workflow | Canvas, Kanban, repo memory, checks, review promotion | Strong CLI agent workflow and tools |
| Privacy posture | Fail-closed profile extraction, explicit provider destinations, local audit | Security docs and command approval, operator setup dependent |
| Skills/plugins | Skills plus WASM capability sandbox and hostcall audit | Skills and toolsets |
| Runtime self-diagnosis | Babel-Index: collapse prediction on NEOTH's own event stream, pre-registered failure labels, self-calibrating early warning ([details](../babel-index.md)) | None documented |
| Automation | Built-in cron plus n8n localhost API | Cron scheduling and platform delivery |
| Messaging | Focused release channels plus private mesh path | Messaging gateway across platforms |
| Private mesh | Tailscale, Hysteria, Keet-style private surfaces, cluster consent | Gateway/platform path |
| Best user | Wants one loyal assistant for daily life, code, memory, and local control | Wants a powerful agent workbench and CLI-first growth loop |

## Migration angle

Hermes users already like agent growth and skills. NEOTH should say:

> Keep the learning loop. Add a real personal buddy, stronger local privacy
> defaults, visual coding planning, and memory you can audit.

