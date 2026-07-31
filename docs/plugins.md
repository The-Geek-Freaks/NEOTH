# Plugins And Skills

NEOTH has two extension surfaces:

| Extension | Best for | Safety model |
| :-- | :-- | :-- |
| **Skills** | Instructions, templates, workflows, domain knowledge. | Data-only; no code execution. |
| **WASM plugins** | Real logic at lifecycle hooks. | Exact approval binding, fuel limits, memory caps, hostcall allowlist. |

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
neoth skills --list
neoth skills --install ./rust-review
neoth skills --test rust-review
neoth skills --uninstall rust-review
# Skills hot-reload automatically (file watcher) — no reload command needed.
```

Local Skill installation is capability-bound: NEOTH validates `skill.yaml`
before publication, copies only bounded regular files without following links
or reparse points, and commits a complete generation under a cross-process
lock. Replacing an existing Skill requires explicit `--force`; interrupted
replacements are recovered before the next runtime load, inventory, update
probe, Self-Improve write, or uninstall.

Install and create use a two-step generation contract. Preflight reports the
exact source manifest/generation and the current destination generation (or
`absent`). The mutation must echo those expectations, rechecks the destination
under the store lock, and returns the generation it replaced. The desktop
accepts success only after the typed receipt and an exact post-commit readback.
Uninstall likewise requires an ID/generation-bound receipt and confirms that
the ID is absent afterwards. Broken inventory rows are typed as
`manifest_replaceable` or `remove_only`; the GUI never offers a manifest repair
for an unsafe or structurally ambiguous directory.

This storage contract prevents partial generations, link traversal and stale
GUI success. It is **not runtime authority**. An external installed Skill is
routable only through a versioned authenticated authority record and Current
Anchor that exactly bind package generation/incarnation, terminal receipt,
provenance, enabled state, effective tool scope, delegation, model, source, and
policy. Missing, stale, revoked, edited, or mismatched authority falls back to
bundled-only routing; a generation receipt alone never grants tools or assigns
a permissive meaning to an omitted/empty `tool_allowlist`. GOLD-R3-17 remains
open for running-daemon adoption/revocation, subprocess MCP
reconnect/poisoning, Buddy parity, and exact-head gates.

An optional `source: git+https://...` enables version checks only for an
effectively enabled Skill. Version probes currently accept repositories hosted
on `github.com`, `gitlab.com`, or `codeberg.org`; self-hosted forges remain
disabled until an explicit operator host policy exists. Userinfo, non-default
ports, redirects, credential helpers, interactive prompts, and inherited Git
request configuration are rejected or disabled. A disabled Skill never starts
the Git probe. Even an eligible source does not create recurring daemon egress
in the current release candidate: updater lanes return `SkippedByGate` until
request-bound transport authorization and intent/result WAL are complete.

The running registry uses the daemon's exact `freedom.yaml` path, including a
custom `neoth serve --config ...` instance. It rebuilds Skill routing only from
a configuration generation accepted by the shared reload controller; malformed
or rejected candidates leave the previous validated routing snapshot active.

## Plugins

Plugins are code and therefore need stronger boundaries.

```text
~/.neoth/plugins/my_plugin/
  plugin.toml
  plugin.wasm
```

Example manifest:

```toml
id = "my_plugin"
name = "My Plugin"
version = "1.0.0"
description = "Example ABI v1 plugin"
requested_permissions = "read_only"
hook_stages = ["on_recall_query"]

# Optional, validated per-invocation/per-instance ceilings.
fuel_budget_override = 1000000
memory_limit_bytes = 67108864

# Optional updater source and read-only GUI WAL feed.
# source = "git+https://github.com/example/my_plugin"
# [ui_surface]
# kind = "wal_feed"
# title = "My Plugin"
```

The same updater-source restrictions apply to plugins. A plugin source is
probed only while the WASM host is enabled and the exact plugin has an active,
approval-bound activation record and is not revoked. Pending, inactive, or
revoked plugins do not create background network traffic; a malformed existing
`freedom.yaml` fails the probe closed instead of falling back to permissive
defaults. The same recurring-daemon deny gate applies after those eligibility
checks; manual operator-initiated probes remain separate.

`id` must be snake_case and the artifact filename is always `plugin.wasm`.
`requested_permissions` is one of `none`, `read_only`, `write`, `execute`, or
`dangerous`. Explicit fuel must be non-zero and is capped at 10,000,000; memory
must be at least one 64-KiB WASM page and is capped at 256 MiB. The accepted
limits are carried into each Wasmtime store; omitted values use the daemon
defaults (1,000,000 fuel and 64 MiB).

Discovery also applies a namespace-wide payload ceiling: each `plugin.wasm` is
limited to 128 MiB and one discovery snapshot retains at most 256 MiB across
all plugins, including inactive candidates inspected before activation policy.
The updater's read-only inventory has its own 512 MiB aggregate scan ceiling.
Exceeding either limit is a visible discovery/probe error, not an empty plugin
set or a partially accepted success.

> **Feature gate:** WASM plugin support is compiled in only when `neothd` is built with
> `--features wasm-plugin-host`. Stock release binaries (from GitHub Releases / winget) already
> include this feature. If you built from source with a plain `cargo build`, rebuild with:
> ```
> cargo build --release --features wasm-plugin-host
> ```
> Runtime execution is separately gated by `freedom.yaml::plugins.wasm.enabled` (default `true`
> on builds that include the feature).

## Rust guest ABI

Rust WASM plugins depend on `neoth-plugin-sdk = "=0.1.0-alpha.0"`, compile as a
`cdylib` for `wasm32-unknown-unknown`, and export through the SDK macro:

```rust
use neoth_plugin_sdk::guest::{GuestHost, HostcallError};
use neoth_plugin_sdk::permission::ReadOnly;

fn run(host: GuestHost<ReadOnly>) -> Result<(), HostcallError> {
    host.log(b"plugin invoked")?;
    let _hits = host.recall_top(42)?;
    Ok(())
}

neoth_plugin_sdk::export_wasm_plugin!(ReadOnly, run);
```

ABI v1 requires `neoth_abi_version() -> i32` and `neoth_run() -> i32` exports.
The macro generates both. The daemon rejects a missing or mismatched ABI before
calling `neoth_run` and treats a non-zero run status as failure.
`GuestHost<L>` exposes the correctly typed wrappers for `neoth.log`,
`neoth.fuel_left`, `neoth.recall_top`, and `neoth.emit_event`; the daemon still
enforces the separately approved runtime permission on every call.

## Declared hook stages

| Manifest value | Purpose |
| :-- | :-- |
| `pre_provider_call` | Before a provider request. |
| `post_provider_call` | After a provider reply. |
| `pre_channel_send` | Before a reply is sent to a channel. |
| `post_channel_receive` | After a channel message is received. |
| `on_recall_query` | A recall query ran. |
| `on_consolidation_pass` | A memory consolidation pass ran. |

These declarations are advisory metadata. They do not auto-register code at a
pipeline stage. The operator must add an explicit plugin action in
`~/.neoth/hooks.toml`; this prevents a manifest alone from intercepting every
provider call or outbound message.

## Permission model

| Permission | ABI v1 hostcalls |
| :-- | :-- |
| `none` | `log`, `fuel_left` |
| `read_only` | Above plus `recall_top` |
| `write` | Above plus `emit_event` |
| `execute` | No additional ABI v1 hostcall yet. |
| `dangerous` | No additional ABI v1 hostcall yet. |

The SDK's type markers guide which wrappers plugin code can call, but they are
not authority. The daemon derives the runtime grant from the exact persisted
approval and checks it on every hostcall. ABI v1 exposes no WASI, filesystem,
network, channel, credential, or arbitrary tool surface.

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
neoth plugin enable my_plugin
neoth plugin disable my_plugin
neoth plugin remove my_plugin
neoth plugin ledger my_plugin
```

Install and discovery do not activate code. `enable` records the approved
permission plus canonical manifest and WASM digests. Any later manifest,
permission, or binary change requires explicit re-consent and a daemon restart;
disable/revocation takes effect fail-closed on the next daemon restart. Revoking a plugin in a *running* daemon is not yet implemented — that is tracked as GOLD-R3-17.

## Security expectations

| Rule | Reason |
| :-- | :-- |
| Capabilities are explicit | Operators can inspect what a plugin wants. |
| Hostcalls are allowlisted | Plugins cannot invent new powers at runtime. |
| Memory/fuel/time are capped | Bad plugins cannot consume the machine. |
| Network is opt-in and scoped | No silent exfiltration path. |
| Writes go through policy | Plugins propose; the operator policy decides. |
| WAL records activity | Operators can investigate behavior after the fact. |
