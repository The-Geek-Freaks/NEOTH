# REFERENCE_DEPLOYMENT — One Example Architecture

Status: Reference only. This is **one** example of how NEOTH can be deployed, drawn from the original developer's setup. Your own deployment will look different — that is the point of the operator-agnostic rebrand.

## Purpose

The specs in `PLAN/` are operator-neutral by design. But "operator-neutral" can read as "abstract", and abstract designs are hard to reason about. This document grounds the architecture in one concrete deployment so you can see how the pieces fit together when actually wired up.

## The reference setup

**Hardware:**
- Daemon host: Debian VM (192.168.178.117 on a local LAN, 8 GB RAM, 4 vCPU)
- Local inference: separate machine with 3 GPUs (one of them an Nvidia card with ~16 GB VRAM dedicated to Qwen3-4B-INT4)
- Backup/standby: macOS workstation, intermittently connected
- Channels reachable from anywhere via Tailscale mesh (no public ingress)

**Topology:**

```
                 ┌─────────────────────┐
                 │  Operator's phone   │
                 │  (Telegram client)  │
                 └──────────┬──────────┘
                            │
                  Telegram Bot API (egress only)
                            │
   ┌────────────────────────▼────────────────────────┐
   │                  Daemon VM                       │
   │  ┌──────────────────────────────────────────┐   │
   │  │  neothd                                  │   │
   │  │  - WAL writer (tokio, fdatasync)         │   │
   │  │  - Channel adapters (Telegram first)     │   │
   │  │  - LLM provider clients (Claude/Gemini)  │   │
   │  │  - Profile extractor → local Qwen        │   │
   │  └──────────┬───────────────────────────────┘   │
   │             │                                    │
   │  ~/.neoth/  │   freedom.yaml, policy.yaml,       │
   │             │   wal/, vault/, plugins/, skills/   │
   └─────────────┼────────────────────────────────────┘
                 │
                 ▼ (gRPC over Tailscale)
        ┌────────────────────┐
        │  Inference host    │
        │  Qwen3-4B-INT4     │
        │  on candle / GPU   │
        └────────────────────┘
```

**File layout on the daemon VM:**

```
~/.neoth/
├── freedom.yaml          # operator identity, channel tokens, LLM keys
├── policy.yaml           # per-deployment server safety rules
├── soul.md               # identity template (operator-edited)
├── claude.md             # operational rules
├── wal/                  # tamper-evident event log (mode 0600)
│   ├── 000001.wal
│   └── 000002.wal
├── vault/                # SHADOW_COPY archive for destructive WAL ops
├── plugins/              # WASM plugin manifests + binaries
├── skills/               # YAML skill descriptors
└── panic.log             # daemon panic frames
```

## What this means for your deployment

You do **not** have to replicate this setup. Reasonable variations:

| Concern | Reference setup | Your options |
|---------|-----------------|--------------|
| Daemon host | Linux VM | Bare metal, container, WSL2, Mac, NAS — anything that runs Rust |
| Channels | Telegram + WhatsApp + Slack | Any subset. Telegram is the easiest start. |
| LLM Left/Right | Claude Opus + Gemini Pro | Any combination from the [supported providers](../docs/configuration.md) |
| Local inference | Qwen3-4B-INT4 on dedicated GPU | Smaller model on CPU; or disable local inference and use cloud fallback (sets `inference.allow_cloud_fallback = true`) |
| Network | Tailscale mesh, no public ingress | Any topology; channel webhooks are the only required ingress |
| Backup | Nightly git of vault/ to private remote | Whatever your backup story already is |
| Recovery host | Mac standby that can take over | Optional. Single-node is fine for most operators. |

## What NEOTH assumes

Regardless of deployment topology, NEOTH requires:

1. **A POSIX-like filesystem** that supports `fsync()` semantics on regular files and `umask`. Linux/macOS native. Windows WSL2 works. Native Windows builds run but durability guarantees are weaker (no `fdatasync`).
2. **A persistent home directory** at `~/.neoth/` that survives reboots.
3. **Outbound HTTPS** to your configured LLM providers and channel APIs.
4. **One trusted operator** — NEOTH does not have multi-tenant isolation. Anyone who can read `~/.neoth/freedom.yaml` can impersonate you.

## Network requirements

| Direction | Endpoint | Required? |
|-----------|----------|-----------|
| Outbound | api.anthropic.com, generativelanguage.googleapis.com, api.openai.com | At least one provider |
| Outbound | api.telegram.org | If using Telegram |
| Outbound | graph.facebook.com | If using WhatsApp Business |
| Outbound | slack.com | If using Slack |
| Inbound | Telegram webhook (optional) or long-polling | Telegram works either way |
| Inbound | WhatsApp Business webhook | Required for WhatsApp |

If you cannot accept inbound webhooks (NAT, no public IP), NEOTH supports long-polling for Telegram and outbound-only patterns for WhatsApp Business. See `docs/channels.md`.

## Compute footprint (reference setup)

| Component | Steady-state | Peak |
|-----------|--------------|------|
| `neothd` resident memory | ~80 MB | ~250 MB during compaction |
| WAL writer CPU | <1% of one core | ~5% during burst writes |
| Qwen3-4B-INT4 inference | ~3 GB VRAM | ~3.2 GB during prefill |
| Inference latency | ~200ms first token, ~30 tokens/sec | — |
| Cloud LLM calls | ~3-7% of turns (council triggers only) | — |

Without local inference, the resident memory drops to ~50 MB; council triggers fall back to additional cloud calls.

## Operational habits (from the reference deployment)

These are not requirements, but they were learned by trial-and-error and may save you the same pain:

1. **Never reboot a daemon host you cannot physically reach.** Reference deployment lost remote access twice this way. Use `systemctl restart neothd` instead — NEOTH recovers cleanly from process restart.
2. **Treat `~/.neoth/freedom.yaml` like an SSH private key.** Rotate quarterly. Mode 0600 enforced at startup; if NEOTH refuses to start citing permissions, that is working as designed.
3. **Run `neoth wal verify --crc` weekly** as a cron. Catches silent disk corruption before it cascades.
4. **Keep one tested backup off the daemon host.** Reference setup runs nightly git-push of vault/ to a private remote.
5. **The 0.95 / 5% rule:** if more than 5% of recall queries return nothing for a week, your importance threshold is wrong, not your hardware.

## What is NOT in this reference

The reference deployment does not currently exercise:
- Multi-operator scenarios (single human, single daemon)
- Council pipeline (still Phase 2)
- WASM plugins at scale (Day-23 milestone)
- The Phase-3 migration from a predecessor system (covered in `RUNBOOK_phase3_cutover.md`)

When those become production-tested in the reference setup, this document will be updated.

---

**TL;DR:** One way to run NEOTH. Yours will differ. The specs in `PLAN/` are normative; this is illustrative.
