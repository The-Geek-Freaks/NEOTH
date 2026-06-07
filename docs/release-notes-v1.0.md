# NEOTH 1.0 Release Notes

> **Release stage: `1.0.0-beta.1`.** The v1.0 surface is substantially
> shipped and usable for real personal use, but this is a BETA, not the final
> 1.0 — see **Known v1.0 gaps** below for the honest list of what is not yet
> complete. Pre-release version on purpose; nothing here claims more than it
> delivers.

NEOTH 1.0 is the first public release intended for real personal use: one
operator, one private memory, many approved surfaces, local-first defaults, and
operator-readable proof.

## Known v1.0 gaps (beta)

These are the deltas between this beta and a final 1.0 — tracked, not hidden:

- **GUI settings depth (GU-01):** all 10 post-onboarding settings tabs are now real
  panels (GU-01 closed in the Session-37 GUI batch — see the GUI honest-status note
  below). A few stay intentionally thin — the Channels tab shows status and defers
  connect/disconnect to the CLI/wizard, the Chat tab is a launch-point for the composer,
  Hemispheres/Plugins/Memory are read-only views, and not every individual `freedom.yaml`
  flag has its own toggle yet — but everything is fully operable via the CLI today.
  (GUI rendering is compile-verified; visual QA is a manual step.)
- **Migration shadow-run (ARCH-05):** the deterministic recall-parity GATE +
  runbook ship; the 14-day shadow-run, grading, and cutover are
  operator-operational steps you perform, not code that runs itself.
- **Signed release artifacts:** `neoth wal export --sign` / `verify-proof` /
  `wal proof-key` (the OPERATOR proof key) work today. RELEASE-artifact signing
  (the minisign release keypair behind MAR-02 / signed downloads) is pending the
  operator generating + wiring the CI keypair — the verify code is already built.

## What works

| Area | Status |
| :-- | :-- |
| GUI first run | Guided setup, privacy defaults, provider/local-model choice, memory consent, channel selection. |
| CLI | Chat, recall, profile, privacy audit, Doctor, providers, channels, plugins, cluster, coding, backup, WAL verification. |
| Memory | Five-tier local memory + vault ingest, with profile facts, evidence, confidence, redaction, recall, and consolidation. |
| Privacy | Fail-closed profile extraction, explicit destinations, provider audit, WAL verification, plugin hostcall audit. |
| Local models | Qwen profile path, optional local thinking model path, model cache diagnostics. |
| Providers | Configured cloud providers, provider status, usage caps, circuit breakers, flapping detection. |
| Channels | CLI + onboarding GUI: Telegram, WhatsApp Business, Slack Socket Mode, Discord, Keet/private path. The post-onboarding GUI Channels tab (GU-01) shows per-channel status; live connect/disconnect remains a CLI/wizard action via `neoth init --reconfigure` + `freedom.yaml`/`credentials.yaml` (the `/connect` `/disconnect` chat commands print that flow). |
| Coding buddy | Planning, canvas/Kanban, repo memory, cargo/check loop, review promotion, recall of decisions. |
| Automation | Local cron and localhost n8n API under the same policy/audit surface. |
| Plugins | Skills and WASM plugins with capabilities, signatures, revocation, hostcall WAL events. |
| Private mesh | LAN/mDNS discovery, Tailscale path, Hysteria transport, consent-gated cluster behavior. |
| Doctor | Setup diagnostics for config, secrets, models, channels, plugins, providers, disk, WAL, and cluster discovery. |
| Docs | Quickstart, privacy proof, install, CLI, providers, local models, channels, plugins, compare pages, security policy. |

> **GUI settings coverage (honest status):** the post-onboarding settings window has
> 10 tabs and — since the Session-37 GU-01 batch — all 10 are real panels (Privacy,
> Cluster, Code Sessions, Config, Chat, Hemispheres, Channels, Skills, Plugins, Memory).
> A few are intentionally thin: Channels shows status and defers connect/disconnect to
> the CLI/wizard, Chat is a launch-point for the composer, and Hemispheres/Plugins/Memory
> are read-only views (rebind/enable still flow through the CLI), and not every single
> `freedom.yaml` flag has a dedicated toggle yet. Everything is fully operable via the
> CLI; GUI rendering is compile-verified, not yet visually QA'd. This note exists so the
> GUI claim is never read as more than it is.

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
