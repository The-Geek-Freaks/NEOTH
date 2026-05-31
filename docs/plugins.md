# Plugins And Skills

NEOTH has two extension surfaces:

| Extension | Best for | Safety model |
| :-- | :-- | :-- |
| **Skills** | Instructions, templates, workflows, domain knowledge. | Data-only; no code execution. |
| **WASM plugins** | Real logic at lifecycle hooks. | Capability declarations, fuel limits, memory caps, timeout, hostcall allowlist. |

## Skills

Skills are portable knowledge packs.

```text
~/.neoth/skills/my-skill/
  skill.yaml
  README.md
  templates/
```

Example:

```yaml
id: rust-review
name: Rust Review
description: Review Rust code for correctness, safety, and maintainability.
triggers:
  - rust review
  - cargo clippy
  - unsafe
context_files:
  - README.md
```

Commands:

```bash
neoth skill list
neoth skill install ./rust-review
neoth skill enable rust-review
neoth skill disable rust-review
neoth reload-skills
```

## Plugins

Plugins are code and therefore need stronger boundaries.

```text
~/.neoth/plugins/my-plugin/
  plugin.toml
  my-plugin.wasm
```

Example manifest:

```toml
id = "my-plugin"
name = "My Plugin"
version = "1.0.0"

[permissions]
memory_read = true
memory_write = false
network = false
filesystem = "none"

[limits]
memory_mb = 64
fuel = 1000000
timeout_ms = 250
```

## Hook points

| Hook | Purpose |
| :-- | :-- |
| `on_message_ingest` | Inspect/sanitize inbound content. |
| `on_profile_candidate` | Validate or enrich profile proposals. |
| `on_recall_result` | Re-rank or annotate recall. |
| `on_tool_result` | Process tool outcomes. |
| `on_channel_send` | Format or block outbound messages. |
| `on_coding_session_end` | Promote review findings or decisions. |

## Permission model

| Permission | Grants |
| :-- | :-- |
| `memory_read` | Read approved memory views. |
| `memory_write` | Propose memory writes through policy gate. |
| `network` | Use declared outbound destinations only. |
| `filesystem` | Access scoped paths only. |
| `channel_send` | Propose outbound messages through channel policy. |
| `tool_call` | Call allowed host tools. |

No plugin should get ambient access to the operator's filesystem, network, profile, channels, or credentials.

## Audit

```bash
neoth plugin list
neoth plugin ledger
neoth privacy audit --last 7d
```

Audit should show:

- plugin ID and version
- declared capabilities
- hostcalls used
- memory writes proposed
- channel sends proposed
- denied operations
- resource-limit failures

## Install and manage

```bash
neoth plugin install ./my-plugin
neoth plugin enable my-plugin
neoth plugin disable my-plugin
neoth plugin remove my-plugin
neoth plugin ledger my-plugin
```

## Security expectations

| Rule | Reason |
| :-- | :-- |
| Capabilities are explicit | Operators can inspect what a plugin wants. |
| Hostcalls are allowlisted | Plugins cannot invent new powers at runtime. |
| Memory/fuel/time are capped | Bad plugins cannot consume the machine. |
| Network is opt-in and scoped | No silent exfiltration path. |
| Writes go through policy | Plugins propose; the operator policy decides. |
| WAL records activity | Operators can investigate behavior after the fact. |
