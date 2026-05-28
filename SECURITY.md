# Security Policy

NEOTH stores private conversations, profile memory, tool credentials, provider
configuration, channel tokens, and automation state. Treat security reports as
high priority.

## Supported versions

| Version | Supported |
| :-- | :-- |
| 1.0.x | Yes |
| Previous public minor | Critical fixes only |
| Pre-1.0 private builds | Best effort |

## Report a vulnerability

Do not open a public issue for security bugs.

Use GitHub Security Advisories:

<https://github.com/The-Geek-Freaks/NEOTH/security/advisories/new>

Include:

- affected version and platform
- exact reproduction steps
- impact and attacker requirements
- logs or screenshots with secrets removed
- suggested fix if you have one

## Response targets

| Time | Target |
| :-- | :-- |
| 72 hours | Acknowledge the report. |
| 7 days | Triage severity and confirm scope. |
| 30 days | Ship a fix for high/critical issues when practical. |
| 90 days | Coordinate public disclosure after a fix is available. |

## In scope

- `neothd` daemon and `neoth` CLI
- GUI setup and local runtime behavior
- profile memory, redaction, recall, evidence, and privacy audit
- provider routing, fail-closed behavior, and destination audit
- WAL integrity and tamper evidence
- channel adapters and outbound approval boundaries
- plugin/skill capability enforcement and WASM hostcalls
- n8n/cron automation boundaries
- cluster discovery, private mesh pairing, and transport policy
- installer integrity and update paths

## Out of scope

- attacks requiring full OS/admin compromise of the operator machine
- vulnerabilities in third-party LLM providers
- vulnerabilities in Telegram, WhatsApp, Slack, Discord, Tailscale, Hysteria,
  or n8n themselves
- social engineering where the operator intentionally exports secrets
- theoretical issues without a plausible exploit path

## Security principles

| Principle | Requirement |
| :-- | :-- |
| Local-first | Durable personal memory stays local unless the operator configures a destination. |
| Fail-closed | Sensitive profile extraction and provider fallback must not silently become less private. |
| Least privilege | Plugins, skills, hooks, and tools need explicit capabilities. |
| Auditability | Sensitive actions must leave WAL-backed evidence. |
| Human control | Outbound channel writes, durable profile changes, and powerful automation remain policy-gated. |
| Clear diagnostics | `neoth doctor` should tell users what is broken and how to fix it. |

## Hardening checklist

```bash
neoth doctor
neoth privacy audit --last 30d
neoth privacy audit --destinations
neoth profile show --evidence
neoth plugin audit
neoth wal verify
```

Recommended operator baseline:

- enable full-disk encryption
- keep `~/.neoth/credentials.yaml` private
- prefer local-only mode for highly sensitive work
- review plugin capabilities before enabling a plugin
- expose channels/webhooks only through the documented secure paths
- rotate provider and channel tokens after suspected compromise

## Disclosure credit

Reporters get credit in release notes unless they request anonymity.
