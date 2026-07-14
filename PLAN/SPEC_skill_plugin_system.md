# SPEC: Skill + Plugin Extension System — NEOTH v1.1

> **Status:** CURRENT IMPLEMENTATION CONTRACT (corrected 2026-07-14).
> `PermissionToken<T>` exists as typed Rust API guidance; it is not an
> unforgeable runtime grant. WASM authority is enforced by the operator-bound
> activation record and the Wasmtime hostcall gate described below.
> **Framework-Basis:** Tool-Framework v4.1 "Pflegbarer Garten"
> **Design-Basis:** `00_DESIGN_v1.0_FINAL.md` (NEOTH brand) + ADVERSARIAL/00 review

## 0. Scope

Extension surface for NEOTH v1.1:
- Skill vs Plugin distinction
- Skill YAML schema
- Plugin compiled-in (Phase 1) + WASM via wasmtime (Phase 2 opt-in)
- `PermissionToken<T>` typestate implementation (S3 fix)
- Loader lifecycle: discover → validate → load → register → unload
- 8 hook types
- Skill auto-loading via Basal Ganglia
- Multi-node distribution
- Security + permission system
- MVP skill list

Out of scope: Ecology-Schicht integration (Phase 4), skill marketplace, MCP bridge for plugins.

## 1. Skill vs Plugin Distinction

**Skill = data-only.** YAML file + optional template partials. No Rust code. Injects domain-specific context into Pipeline-Router's Block-B (cache) or Block-D (volatile). Skills hot-reload via SIGHUP without restart.

**Plugin = code.** Two flavors:
- **Phase 1 (compiled-in)**: Rust crate compiled into `neothd` binary via `inventory` crate. No `.so`/`.dll`. Single-binary constraint preserved.
- **Phase 2 (WASM)**: `.wasm` module loaded via `wasmtime` runtime at startup. Hot-reload by daemon restart. Used for opt-in plugins (needle on-device router, CloakBrowser stealth, react-doctor) where Phase 1 inventory wouldn't allow on/off without recompile.

### Framework Traceability

- **Skills don't violate G.2/G.5:** they inject content into Context-Engine block, NOT executable composition. Tools unchanged. Deklarative Referenz, not aktiver Tool-Aufruf.
- **Plugins don't violate G.1:** hooks execute at Schicht-1 (Pipeline) boundaries, never Schicht-0. Tools stay pure functions.
- **WASM in Phase 2:** capability-API hostcalls (see §10) ensure no ambient filesystem/network; fuel-limited + memory-capped per call. Codex v0.6 review verified WASM design correct.

## 2. Skill Format

Storage: `~/.neoth/skills/<skill_id>/skill.yaml` + optional `templates/`.

```yaml
skill_id: neoth_identity            # globally unique, snake_case
version: 0.6.0                       # semver
content_hash: auto_computed_on_load  # sha256(yaml + templates)
description: SOUL.md excerpt + LOWKEY rules

mount:
  target: block_b    # block_b | block_d | basal_ganglia_context

trigger:
  mode: always       # always | keyword | explicit
  hemisphere_filter: left  # left | right | both | any
  permission_required: None  # None | ReadOnly | Write | Execute | Dangerous

content:
  template_file: templates/identity_block.md
  max_tokens: 400

locality:
  sandboxed: true
  forbidden_side_effects: [filesystem, network, wal, oauth_vault, other_skills]

health_check:
  test_render: true
  mode: hard_fail

introspection:
  exposes_rendered_template: true
```

## 3. Plugin Format

### 3.1 Native Rust SDK hooks

The published SDK exposes a typed `Hook<L>` interface for trusted, compiled-in
Rust integrations:

```rust
use neoth_plugin_sdk::{Hook, HookContext, HookOutput, HookResult, PipelineStage, ReadOnly};

pub struct ExamplePlugin;

impl Hook<ReadOnly> for ExamplePlugin {
    fn id(&self) -> &'static str { "example_plugin" }
    fn stage(&self) -> PipelineStage { PipelineStage::PrePipeline }
    fn run(&self, _ctx: HookContext<'_, ReadOnly>) -> HookResult {
        Ok(HookOutput::Continue)
    }
}
```

There is currently no `inventory`-based auto-discovery path in `neothd`.
Native hooks are trusted in-process code and must be wired explicitly by the
daemon. The typed marker catches Rust API level mismatches; it does not sandbox
native code or authorize effects at runtime.

### 3.2 Phase 2 WASM Manifest

`plugin.toml` for WASM plugins (separate from compiled-in):

```toml
id = "needle"
name = "Cactus Needle on-device router"
version = "0.1.0"
description = "Local routing plugin"
requested_permissions = "read_only"
# Advisory/display metadata; it does not auto-register the plugin as a hook.
hook_stages = ["pre_provider_call"]
fuel_budget_override = 1000000
memory_limit_bytes = 67108864
```

The sibling payload is always `plugin.wasm`. A discovered plugin defaults to
`pending`; the operator activates it with `neoth plugin enable needle`.
`freedom.yaml::plugins.wasm.activations` then stores an approval bound to the
canonical manifest hash, WASM hash, and exact requested permission. Any change
requires explicit re-consent; legacy active entries without that binding grant
no authority.

### 3.3 Guest ABI v1

Rust guests should use `neoth_plugin_sdk::export_wasm_plugin!`, which emits the
two exports required by the daemon:

```text
neoth_abi_version() -> i32  # must return 1
neoth_run() -> i32          # 0 = success; non-zero = failed invocation
```

The host validates `neoth_abi_version` before calling `neoth_run`; a missing,
mistyped, or mismatched export is rejected. Every invocation receives a fresh
Wasmtime store whose fuel and memory limits are the validated values captured
from the same manifest covered by the activation approval. The guest ABI is a
compatibility contract; authority still comes only from the hash-bound approval
and per-hostcall runtime checks.

## 4. Loader Lifecycle

```
discover → validate → load → register → [running] → unload
```

**Discover** (startup): scan `~/.neoth/skills/`. Plugin `inventory::iter` walk (Phase 1). WASM scan `~/.neoth/plugins/*/plugin.toml` (Phase 2).
**Validate**: schema conformance, `max_tokens<=2000`, no code fields in skills.
For WASM plugins, validate manifest/WASM integrity, cap fuel and memory, and
require the persisted approval to match permission plus both hashes exactly.
**Load**: render `health_check.test_render`. Skills cached in Block-B (session-length) or Block-D (per-request). Plugins immutable post-startup.
**Register**: `SkillRegistry` HashMap by `skill_id` + keyword-trigger entries in Basal Ganglia `idx_habit`. HookTable frozen.
**Unload**: SIGHUP or `neoth reload-skills` — skills only. Plugins require rebuild + restart.

## 5. Hook Contracts (8 types)

All hooks Schicht-1, receive `HookContext`, return `HookResult::Continue | Abort(reason)`.

| Hook | When | May mutate |
|------|------|-----------|
| `pre_recall` | Before `recall.query` dispatch | recall_params (append-only) |
| `post_recall` | After recall results | block_d_additions |
| `pre_provider_call` | Before LLM request | context blocks (append-only) |
| `post_provider_call` | After LLM response | none (read-only) |
| `on_tool_invocation` | Before any Schicht-0 tool | none (audit) |
| `on_refusal` | After refusal_detect classifies | none (notification) |
| `on_council_verdict` | After CouncilVerdict produced | none (notification) |
| `on_wal_event` | After WAL frame written | none (metrics) |

**Critical:** `HookContext` intentionally exposes no tool-call method. That is a
useful API-shape restriction, not a security boundary for trusted native Rust
code. Operator effects still require the daemon's runtime permission gate. WASM
plugins can reach only the explicitly linked hostcalls, each checked at runtime.

## 6. PermissionToken<T>: current scope and limits

**Original problem:** the design referenced `PermissionToken<Execute>` before a
type existed. The SDK now implements the five-level sealed lattice,
`PermissionToken<L>`, `FreedomGrant<L>`, `AtLeast<L>`, and type erasure for Rust
adapter ergonomics.

**Security correction:** these zero-sized values are not runtime authority.
Constructors and upgrades are hidden from the default SDK surface behind the
`_host` Cargo feature, but dependency features are consumer-selectable. Any
consumer can opt into `_host` and construct the markers. Sealing prevents new
lattice types; it does not make existing tokens or grants unforgeable.

For WASM plugins no token crosses the ABI. The real boundary is the Wasmtime
sandbox plus the activation approval bound to manifest/WASM hashes and the
runtime `HostcallPermission` check on every hostcall. For native integrations,
privileged operations must independently pass the daemon's `Action`/`Gate`
policy; a typed function signature is compile-time guidance only.

### 6.1 PermissionLevel sealed marker types

```rust
// Visibility note: each marker type is a public unit struct, BUT the
// `sealed::PermissionLevel` trait is private to this crate. External plugin
// authors cannot implement PermissionLevel for their own types because the
// trait is sealed.

pub struct None;
pub struct ReadOnly;
pub struct Write;
pub struct Execute;
pub struct Dangerous;

mod sealed {
    pub trait PermissionLevel {}
    impl PermissionLevel for super::None {}
    impl PermissionLevel for super::ReadOnly {}
    impl PermissionLevel for super::Write {}
    impl PermissionLevel for super::Execute {}
    impl PermissionLevel for super::Dangerous {}
}

pub trait PermissionLevel: sealed::PermissionLevel {}
impl<T: sealed::PermissionLevel> PermissionLevel for T {}
```

### 6.2 PermissionToken<T>

```rust
use std::marker::PhantomData;

/// Zero-sized Rust API marker at permission level T.
pub struct PermissionToken<Level: PermissionLevel>(PhantomData<Level>);

impl<L: PermissionLevel> PermissionToken<L> {
    /// Host-integration constructor. Feature gating prevents accidental use,
    /// not deliberate construction by a Cargo consumer.
    #[cfg(feature = "_host")]
    pub fn mint() -> Self {
        PermissionToken(PhantomData)
    }
}

/// Typed transition for Rust adapters. This models an intended policy flow;
/// the caller must validate real operator authority separately.
impl PermissionToken<ReadOnly> {
    #[cfg(feature = "_host")]
    pub fn upgrade_to_execute(self, _grant: FreedomGrant<Execute>) -> PermissionToken<Execute> {
        PermissionToken(PhantomData)
    }
}

impl PermissionToken<Execute> {
    #[cfg(feature = "_host")]
    pub fn upgrade_to_dangerous(self, _grant: FreedomGrant<Dangerous>) -> PermissionToken<Dangerous> {
        PermissionToken(PhantomData)
    }
}

/// Typed marker for Rust integration transitions; not a persisted or
/// cryptographic grant and not automatically issued by freedom.yaml checks.
pub struct FreedomGrant<Level: PermissionLevel> {
    _phantom: PhantomData<Level>,
}

impl<L: PermissionLevel> FreedomGrant<L> {
    #[cfg(feature = "_host")]
    pub fn issue() -> Self {
        FreedomGrant { _phantom: PhantomData }
    }
}
```

### 6.3 What the type system does enforce

Rust APIs can require `PermissionToken<L>` or `L: AtLeast<Required>`. The
compiler then catches accidental level mismatches at those call sites. This is
valuable interface discipline, but it protects only code that voluntarily uses
the typed API. It cannot authorize a provider call, file write, process spawn,
or network request and cannot sandbox trusted in-process Rust code.

### 6.4 WASM runtime authorization

1. `neoth plugin enable <id>` persists the exact approved permission,
   canonical manifest SHA-256, and WASM SHA-256.
2. Discovery refuses legacy/unbound activations and any changed permission,
   manifest, or module until the operator re-enables the plugin.
3. Dispatch derives `HostcallPermission` only from that bound approval; a
   missing approval defaults to `None`.
4. Every linked hostcall checks `granted.allows(required)` inside the Wasmtime
   closure before performing its effect.

### 6.5 Permission audit trail

A denied WASM hostcall emits immediate-sync `0xC7 PLUGIN_CAP_DENIED` with the
plugin id, hostcall, required level, and granted level. Successful privileged
hostcalls emit their corresponding `0xC4 PLUGIN_HOSTCALL` or `0xC6
PLUGIN_CAP_USED` frame. There is no `0x4A VAULT_ACCESSED` event in the current
registry; `0x4A` is `CHANNEL_SILENCE_ALERT`. Documentation must not reuse event
codes from speculative designs.

## 7. Skill Auto-Loading Routing

Mechanism: Basal Ganglia `idx_habit` (v0.5 Day 22 deliverable). At skill load, `trigger.keywords` inserted with `habit_type: skill_trigger`.

Request-preprocessing → tokenize user msg → `idx_habit` keyword lookup → matched skills sorted by (permission_level, mount_target) → inject into Block-B/D before assembly proceeds.

**No hippo-turbo embedding routing:** keyword matching via `idx_habit` is already built. Basal Ganglia promotion/demotion = organic selection (Framework F.3 Variation+Selektion).

## 8. Multi-Node Distribution

**Skills:** Loaded per-node from `~/.neoth/skills/`. No replication. Operator syncs via rsync/git.

**Plugins (Phase 1 compiled-in):** Same binary deployed to all nodes = same plugins.

**Plugins (Phase 2 WASM):** Per-node `~/.neoth/plugins/`. No replication. Operator decides which nodes load which.

**WAL on skill activation:** No event emitted (Schicht-1 transient state). Response `PROVIDER_RESPONSE` event already captures full assembled context — implicit tracing.

## 9. Cherry-Pick from Sources

- **openclaw `extensions/`:** Manifest-declares-hooks principle adopted (`plugin.toml [hooks].registered`). Node loader pattern NOT adopted.
- **openhuman `traits.rs`:** `PermissionLevel` enum adopted directly. `ToolCategory::Skill` variant for Basal Ganglia routing tracking. `ToolScope` reserved for future parallel dispatch.
- **hermes `extensions.py`:** Path-traversal guard `_is_safe_relative_path()` adopted in `skill::load_template()`. `_MAX_URL_LIST = 32` → NEOTH caps keyword triggers at 32 per skill.

## 10. Phase 2 WASM Hostcall Surface

The current linker exposes exactly four imports:

| Import | Required runtime permission | Effect |
|--------|-----------------------------|--------|
| `neoth.log` | `none` | bounded diagnostic log |
| `neoth.fuel_left` | `none` | remaining fuel counter |
| `neoth.recall_top` | `read_only` | bounded recall hit-count query |
| `neoth.emit_event` | `write` | bounded WAL plugin event |

The manifest requests one maximum permission level; it does not provide a
consumer-controlled hostcall allowlist. The operator approves the exact
permission together with both artifact hashes. At invocation, each linker
closure reads the approval-derived `PluginStoreState::granted`, refuses calls
above that level before the effect, and writes `0xC7 PLUGIN_CAP_DENIED` on the
denied path. Successful privileged calls write `0xC4`/`0xC6` audit frames.

Fuel and linear-memory limits are enforced by the Wasmtime store (defaults:
1,000,000 fuel and 64 MiB; manifest overrides are capped). No WASI filesystem
or socket interface is linked, so the module has no ambient file or network
access. Adding an Execute/Dangerous hostcall requires a new explicit linker
binding, permission level, audit contract, and tests.

## 11. Built-in Skills — Phase 1 MVP (Day 23)

| Skill | Mount | Trigger | Description |
|-------|-------|---------|-------------|
| `neoth_identity` | block_b | always/left | SOUL.md + LOWKEY rules for every Left response |
| `server_safety` | block_b | keyword: [cube, 100.68.210.50, reboot, unraid] | Server-safety constraints |
| `security_research` | block_d | keyword: [pentest, exploit, payload, cve, nuclei, nmap] | FREEDOM.yaml security_research scope required |
| `obsidian_context` | block_d | keyword: [vault, obsidian, note, zettelkasten] | Vault topology summary |
| `neoth_providers` | block_d | keyword: [provider, claude, gemini, codex, llm] | Provider cascade knowledge |
| `neoth_tools` | basal_ganglia_context | keyword: [tool, pipeline, wal, emit, recall] | Tool registry for meta-queries |
| `freedom_scope` | block_b | always/any | Active FREEDOM.yaml scope summary |

## 12. Framework Compliance Checklist

| Rule | Skill System | Plugin System |
|------|--------------|---------------|
| G.1 Stateful Tool | N/A (data only) | Hooks run Schicht-1 — transient |
| G.2 Self-Modifying | Skills immutable post-load | HookTable frozen at startup |
| G.4 Meta-Decision | Skills inject data | Hooks return Continue/Abort |
| G.5 Emergent Comp | Skills don't call tools | WASM has only fixed, runtime-gated hostcalls; native hooks remain trusted code and require explicit daemon wiring |
| G.11 Closed-Loop | Ecology RO only | Same |
| G.12 Level-Confusion | Skills mount Schicht-1 boundary | Hooks execute Schicht-1 |
| G.13 Bateson-III | No identity/self-reflection | No self-modification path |
| H.8 Human Agency | Skill reload via `neoth reload-skills` or SIGHUP | Plugin changes require human rebuild (Phase 1) or daemon restart (Phase 2 WASM) |

## 13. Open Questions for Operator

1. **Skill hot-reload scope**: SIGHUP all or per-skill `neoth reload-skill <id>`?
2. **Plugin SDK crate boundary**: internal-only or published crate (allows Veronica different plugins via separate binary build)?
3. **`security_research` skill permission gate**: `permission_required: Execute` (generic) or named `freedom_scope: security_research` (explicit 1:1 FREEDOM.yaml mapping)?
4. **WASM activation default**: opt-in (config flag) vs auto-detect (presence of `~/.neoth/plugins/<name>/`)? Currently opt-in to prevent accidental activation.

## 14. Status

**Current implementation:** the SDK typestate is implemented and useful for
compile-time Rust API checks, but it is deliberately not described as an
authorization primitive. Operator-loadable WASM plugins are default-pending,
artifact/permission approvals are hash-bound, and hostcall authority is
enforced and audited at runtime. Native SDK hooks have no automatic inventory
loader and remain an explicitly wired trusted-code surface.
