# NEOTH vs Hermes Agent

Hermes Agent's public pitch is strong: an agent that grows with you, a desktop
app (since v0.16) with a coding cockpit (v0.18), persistent memory, skills,
MCP, messaging gateway, cron, tools, and migration from OpenClaw.

NEOTH should win users who want that self-improving operator energy, but with
verifiable trust underneath it: HMAC-chained audit, evidence-linked profile
facts, fail-closed privacy boundaries, a WASM capability sandbox, and
Babel-Index self-diagnosis — none of which Hermes documents.

Baseline sources — Hermes Agent capabilities below were re-verified **as of
2026-07-03** against release **v0.18.0** (2026-07-01). Hermes moves fast: since
v0.16.0 it ships an Electron desktop app with GUI onboarding, and since
v0.18.0 a full coding cockpit (Projects sidebar, git worktrees, multi-terminal,
PR-style diffs). Treat every competitor claim as a point-in-time snapshot:

- <https://github.com/NousResearch/hermes-agent>
- <https://hermes-agent.nousresearch.com/docs>

## Short version

| If you want... | Pick |
| :-- | :-- |
| Self-improving agent workbench (desktop app + CLI/TUI) | Hermes Agent |
| A private Jarvis-like buddy for normal users and pros, with coding canvas, five-tier memory + vault, and audit-first privacy | NEOTH |

## Capability comparison

| Area | NEOTH | Hermes Agent (as of 2026-07-03, v0.18.0) |
| :-- | :-- | :-- |
| Product center | Private buddy plus operator runtime | Agent workflow that grows with usage |
| Normal-user onboarding | GUI wizard, plain privacy choices, no YAML happy path | Desktop app with GUI onboarding since v0.16 (plus CLI/TUI) |
| Memory | Five-tier memory + vault ingest, profile evidence, redaction semantics, WAL | Persistent memory and profiles |
| Coding workflow | Canvas, Kanban, repo memory, checks, review promotion into audited memory | Desktop coding cockpit (Projects, git worktrees, multi-terminal, PR diffs) + Kanban |
| Privacy posture | Fail-closed profile extraction, explicit provider destinations, local audit | Security docs and command approval, operator setup dependent |
| Skills/plugins | Skills plus WASM capability sandbox and hostcall audit | Skills and toolsets |
| Runtime self-diagnosis | Babel-Index: collapse prediction on NEOTH's own event stream, pre-registered failure labels, self-calibrating early warning ([details](../babel-index.md)) | None documented |
| Automation | Built-in cron plus n8n localhost API | Cron scheduling and platform delivery |
| Messaging | Focused release channels plus private mesh path | Messaging gateway across platforms |
| Private mesh | Tailscale, Hysteria, NEOTH peeroxide/Hyperswarm protocol, cluster consent | Gateway/platform path |
| Best user | Wants one loyal assistant for daily life, code, memory, and local control | Wants a powerful agent workbench and CLI-first growth loop |

## Migration angle

Hermes users already like agent growth and skills. NEOTH should say:

> Keep the learning loop. Add a real personal buddy, stronger local privacy
> defaults, visual coding planning, and memory you can audit.
