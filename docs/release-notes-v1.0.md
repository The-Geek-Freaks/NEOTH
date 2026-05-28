# NEOTH 1.0 Release Notes

NEOTH 1.0 is the first public release intended for real personal use: one
operator, one private memory, many approved surfaces, local-first defaults, and
operator-readable proof.

## What works

| Area | Status |
| :-- | :-- |
| GUI first run | Guided setup, privacy defaults, provider/local-model choice, memory consent, channel selection. |
| CLI | Chat, recall, profile, privacy audit, Doctor, providers, channels, plugins, cluster, coding, backup, WAL verification. |
| Memory | Six-layer local memory with profile facts, evidence, confidence, redaction, recall, and consolidation. |
| Privacy | Fail-closed profile extraction, explicit destinations, provider audit, WAL verification, plugin hostcall audit. |
| Local models | Qwen profile path, optional local thinking model path, model cache diagnostics. |
| Providers | Configured cloud providers, provider status, usage caps, circuit breakers, flapping detection. |
| Channels | GUI, CLI, Telegram, WhatsApp Business, Slack Socket Mode, Discord, Keet/private path. |
| Coding buddy | Planning, canvas/Kanban, repo memory, cargo/check loop, review promotion, recall of decisions. |
| Automation | Local cron and localhost n8n API under the same policy/audit surface. |
| Plugins | Skills and WASM plugins with capabilities, signatures, revocation, hostcall WAL events. |
| Private mesh | LAN/mDNS discovery, Tailscale path, Hysteria transport, consent-gated cluster behavior. |
| Doctor | Setup diagnostics for config, secrets, models, channels, plugins, providers, disk, WAL, and cluster discovery. |
| Docs | Quickstart, privacy proof, install, CLI, providers, local models, channels, plugins, compare pages, security policy. |

## What is not yet done

These are deliberate post-1.0 areas, not hidden broken promises.

| Area | 1.0 boundary |
| :-- | :-- |
| Multi-tenant SaaS | NEOTH 1.0 is single-operator/private-cluster first. No hosted account control plane is required or promised. |
| Enterprise admin console | Policy is local and operator-owned; fleet admin UX belongs after the personal product is stable. |
| Public plugin marketplace trust at scale | 1.0 supports capability gates and audits; large ecosystem moderation is later work. |
| Native mobile app parity | Phone use comes through channels/private surfaces first; full native mobile clients are post-1.0. |
| Perfect deletion from third-party providers | NEOTH can redact local memory and stop re-promotion; it cannot erase data already sent to a provider by approved policy. |
| Arbitrary untrusted autonomous control | Autonomy is policy-gated and auditable. NEOTH is not a "give it root and pray" product. |
| Team collaboration | Project/team modes can build on the runtime later; 1.0 optimizes for one loyal assistant. |

## Verification command set

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
neoth doctor
neoth privacy audit --last 30d
```

Release artifacts should include checksums, signatures, and a matching
`neoth doctor` output from a clean install.
