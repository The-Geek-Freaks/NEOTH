# NEOTH vs OpenHuman

OpenHuman's public pitch is strong: a friendly personal AI with local memory,
managed services where useful, desktop installers, a UI-first onboarding path,
and a broad integration story.

NEOTH should win users who like that idea but want the trust boundary moved
back to their machine.

Baseline sources — OpenHuman capabilities below were assessed **as of 2026-06-07** against
the project's then-current `main` branch and live docs. No tagged release or pinned commit
was published to anchor against, so treat every competitor claim as a point-in-time snapshot
that may have moved since:

- <https://github.com/tinyhumansai/openhuman>
- <https://tinyhumans.gitbook.io/>

## Short version

| If you want... | Pick |
| :-- | :-- |
| Managed convenience, OAuth-heavy integrations, and a polished consumer-first path | OpenHuman |
| Local-first loyalty, fail-closed profile extraction, coding workflow, plugin caps, WAL audit, and private mesh | NEOTH |

## Capability comparison

| Area | NEOTH | OpenHuman (as of 2026-06-07) |
| :-- | :-- | :-- |
| Product center | Private buddy plus operator runtime | Personal AI with UI-first managed convenience |
| Normal-user onboarding | GUI wizard, no YAML happy path | Strong UI-first onboarding |
| Managed backend dependency | None by default | Managed services used for account/model/integration convenience by default |
| Memory | Five-tier local memory + vault, with evidence-linked profile facts | Memory Tree and local vault concepts |
| Profile extraction | Local/fail-closed by policy | Local plus managed path depending on configuration |
| Privacy audit | WAL-backed audit, provider destinations, profile evidence, plugin hostcalls | Privacy story exists, but trust boundary includes managed services |
| Coding workflow | Canvas, Kanban, repo memory, checks, review promotion | Not the primary differentiator |
| Automation | Built-in cron and localhost n8n | Integration-centric |
| Plugins | Skills plus WASM capability sandbox | Integration/tool ecosystem |
| Runtime self-diagnosis | Babel-Index: collapse prediction on NEOTH's own event stream, pre-registered failure labels, self-calibrating early warning ([details](../babel-index.md)) | None documented |
| Private mesh | LAN/mDNS, Tailscale, Hysteria, Keet-style path | Not core |
| Best user | Wants a loyal assistant that can grow from simple GUI into serious local control | Wants consumer convenience and many managed integrations fast |

