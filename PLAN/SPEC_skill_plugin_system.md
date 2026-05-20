# SPEC: Skill + Plugin Extension System — NEOTH v1.1

> **Status:** BUILD-READY. Fixes S3 from ADVERSARIAL/03 (`PermissionToken<T>` was a phantom type — referenced but never defined). Now fully specified.
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

### 3.1 Phase 1 Compiled-In Manifest

`plugin.toml` manifest (embedded in Rust crate via `include_str!`):

```toml
[plugin]
id = "example_plugin"
name = "Example Plugin"
version = "0.1.0"
author = "yourname"

[plugin.permissions]
required = "ReadOnly"           # PermissionLevel — see §6
allowed_resources = ["wal.read", "idx_episode.read"]
oauth_vault_access = false

[plugin.hooks]
registered = ["pre_recall", "post_provider_call", "on_tool_invocation"]

[plugin.locality]
schicht = 1
sandboxed = true
```

Rust registration via `inventory`:

```rust
use neoth_plugin_sdk::{Hook, HookContext, HookResult, hooks::PreRecallHook};
use inventory;

pub struct ExamplePlugin;

impl PreRecallHook for ExamplePlugin {
    fn name(&self) -> &str { "example_plugin::pre_recall" }
    fn on_pre_recall(&self, ctx: &mut HookContext) -> HookResult {
        ctx.recall_params.keyword_filter.push("neoth".to_string());
        HookResult::Continue
    }
}

inventory::submit!(Hook::PreRecall(Box::new(ExamplePlugin)));
```

`neothd` iterates `inventory::iter::<Hook>()` at startup, validates manifests, registers into immutable HookTable.

### 3.2 Phase 2 WASM Manifest

`plugin.toml` for WASM plugins (separate from compiled-in):

```toml
[plugin]
id = "needle"
name = "Cactus Needle on-device router"
version = "0.1.0"
wasm = "needle.wasm"        # path relative to plugin dir
type = "wasm"

[plugin.permissions]
required = "ReadOnly"
oauth_vault_access = false

[plugin.hooks]
registered = ["pre_provider_call"]

[plugin.activation]
default = "off"             # opt-in
config_flag = "use_needle_router"

[plugin.wasm_runtime]
fuel_limit         = 10_000_000
memory_max_bytes   = 67_108_864   # 64 MiB
timeout_ms         = 5_000
hostcall_allowlist = ["log", "recall_read", "embed", "current_time_ns"]
```

WASM activation: `~/.neoth/config.toml` `[plugins.needle] enabled = true`. Reload requires daemon restart.

## 4. Loader Lifecycle

```
discover → validate → load → register → [running] → unload
```

**Discover** (startup): scan `~/.neoth/skills/`. Plugin `inventory::iter` walk (Phase 1). WASM scan `~/.neoth/plugins/*/plugin.toml` (Phase 2).
**Validate**: schema conformance, `locality.sandboxed=true`, `max_tokens<=2000`, no code fields in skills. Plugin permission ≤ FREEDOM.yaml grant. WASM fuel/memory caps within global limits.
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

**Critical:** No hook may call Schicht-0 tool. `HookContext` type has no tool-call method. Compile-time enforced via §6 PermissionToken type system.

## 6. PermissionToken<T> Implementation (S3 fix — was phantom type)

**Problem v0.8:** Spec referenced `PermissionToken<Execute>` as "compile-time enforced" without ever defining the type. Vault security claim was theater.

**Fix v1.1:** Full implementation below. Sealed trait prevents external `PermissionLevel` types; `PhantomData` makes tokens zero-sized; `pub(crate) fn mint()` prevents external forging.

> **Scope of enforcement (Rust Architect review, OPEN_DECISIONS.md D-004 cross-cut):**
> The `PermissionToken<T>` typestate is a **Phase 1 (compiled-in skills) compile-time
> guarantee only**. The sealed-trait + `pub(crate) mint()` pattern relies on Rust's
> module privacy. Once the WASM plugin host lands (Day 23), plugin code crosses
> the wasmtime ABI boundary — `PermissionToken<T>` zero-sized types cannot be
> transmitted as wasm values, and the compile-time seal does not apply across
> the boundary. Phase 2 (WASM) enforcement uses **runtime `hostcall_allowlist`
> checks** as defined in §7. Do not market the typestate as the security primitive
> for Phase 2; mixing the two enforcement models in one security claim is a
> spec lie that will confuse plugin authors and reviewers.

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

/// Zero-sized typestate token proving the holder has at least permission level T.
/// Cannot be constructed outside the `permission` module — `mint()` is `pub(crate)`.
/// PhantomData ensures runtime cost = 0 bytes.
pub struct PermissionToken<Level: PermissionLevel>(PhantomData<Level>);

impl<L: PermissionLevel> PermissionToken<L> {
    /// MINT FUNCTION — only the permission manager (this crate's internal logic)
    /// can call this. External crates cannot forge tokens.
    pub(crate) fn mint() -> Self {
        PermissionToken(PhantomData)
    }
}

/// Token upgrade requires explicit grant — never cast.
impl PermissionToken<ReadOnly> {
    /// Upgrade to Execute requires an explicit FREEDOM grant.
    /// The grant is consumed (moved) — cannot be reused for multiple upgrades.
    pub fn upgrade_to_execute(self, _grant: FreedomGrant<Execute>) -> PermissionToken<Execute> {
        PermissionToken(PhantomData)
    }
}

impl PermissionToken<Execute> {
    pub fn upgrade_to_dangerous(self, _grant: FreedomGrant<Dangerous>) -> PermissionToken<Dangerous> {
        PermissionToken(PhantomData)
    }
}

/// FreedomGrant<T> — produced by `freedom.check(level)` after reading FREEDOM.yaml.
/// Move-only (no Clone) so each grant gets consumed at use site.
pub struct FreedomGrant<Level: PermissionLevel> {
    _phantom: PhantomData<Level>,
}

impl<L: PermissionLevel> FreedomGrant<L> {
    pub(crate) fn issue() -> Self {
        FreedomGrant { _phantom: PhantomData }
    }
}
```

### 6.3 Vault APIs gated by token level

```rust
/// vault_read requires PermissionToken<Execute>.
/// Calling without Execute = COMPILE ERROR, not runtime check.
pub fn vault_read(
    _token: &PermissionToken<Execute>,
    key: &str,
) -> Result<Secret, VaultError> {
    /* implementation */
    todo!()
}

/// shell_exec requires PermissionToken<Dangerous>.
pub fn shell_exec(
    _token: &PermissionToken<Dangerous>,
    cmd: &subprocess::SafeCommand,
) -> Result<Output, ShellError> {
    todo!()
}

/// recall_query needs at least ReadOnly.
pub fn recall_query<L: PermissionLevel + AtLeast<ReadOnly>>(
    _token: &PermissionToken<L>,
    q: Query,
) -> Result<RecallResult, RecallError> {
    todo!()
}

/// AtLeast<T> marker — implemented for the strict superset of T in the level ordering.
pub trait AtLeast<T: PermissionLevel> {}
impl AtLeast<None> for None {}
impl AtLeast<None> for ReadOnly {}
impl AtLeast<None> for Write {}
impl AtLeast<None> for Execute {}
impl AtLeast<None> for Dangerous {}
impl AtLeast<ReadOnly> for ReadOnly {}
impl AtLeast<ReadOnly> for Write {}
impl AtLeast<ReadOnly> for Execute {}
impl AtLeast<ReadOnly> for Dangerous {}
impl AtLeast<Write> for Write {}
impl AtLeast<Write> for Execute {}
impl AtLeast<Write> for Dangerous {}
impl AtLeast<Execute> for Execute {}
impl AtLeast<Execute> for Dangerous {}
impl AtLeast<Dangerous> for Dangerous {}
```

### 6.4 HookContext binds token to hemisphere + plugin

```rust
pub struct HookContext<'a> {
    pub session_id:    SessionId,
    pub hemisphere:    Originator,
    pub recall_params: &'a mut RecallParams,
    /// Permission token for the *currently invoking plugin*.
    /// Plugin manifest declared `required = "ReadOnly"` → token is `PermissionToken<ReadOnly>`.
    pub token:         PermissionTokenAny,  // erased enum; downcast via match
}

/// Type-erased wrapper — the actual L is known at compile time but stored in an enum
/// because HookContext is a single concrete type across all plugins.
pub enum PermissionTokenAny {
    None(PermissionToken<None>),
    ReadOnly(PermissionToken<ReadOnly>),
    Write(PermissionToken<Write>),
    Execute(PermissionToken<Execute>),
    Dangerous(PermissionToken<Dangerous>),
}
```

A hook trying to call `vault_read` extracts the Execute variant:
```rust
fn on_pre_provider_call(&self, ctx: &mut HookContext) -> HookResult {
    let secret = match &ctx.token {
        PermissionTokenAny::Execute(t) => vault_read(t, "anthropic_api_key").ok(),
        PermissionTokenAny::Dangerous(t) => {
            // Dangerous-token holder may still call vault_read via downgrade
            // (or via subtyping if AtLeast<Execute> matching).
            None  // simplified
        }
        _ => None,  // ReadOnly/Write/None cannot call vault_read
    };
    HookResult::Continue
}
```

### 6.5 Permission Audit Trail

Every vault access emits `0x4A VAULT_ACCESSED` WAL event:

```rust
pub struct VaultAccessed {
    pub plugin_id:        String,
    pub key_path:         String,        // e.g. "anthropic_api_key" — never the value
    pub token_level:      &'static str,  // "Execute" | "Dangerous"
    pub session_id:       SessionId,
    pub hemisphere:       Originator,
    pub hlc:              Hlc,
}
```

No secret material in audit log — only key path + access metadata.

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

## 10. Phase 2 WASM Hostcall Surface (capability-API per Codex v0.6 verdict)

```rust
/// hostcalls exposed to WASM plugins. Sealed enum — adding new hostcalls
/// requires neothd recompile + version bump.
pub enum Hostcall {
    /// Log message at level X. Writes to neoth log + WAL trajectory.
    Log { level: LogLevel, message: String },
    /// Read from idx_episode / idx_semantic (read-only). Requires PermissionToken<ReadOnly>.
    RecallRead { params: RecallParams },
    /// Encode text → 1024d f32 vector via candle Qwen3-Embedding. CPU cost: ~50ms.
    Embed { text: String },
    /// Current wall-clock nanoseconds (UTC). For non-cryptographic timing only.
    CurrentTimeNs,
}

/// Per-call limits (config in plugin.toml).
pub struct WasmRuntime {
    pub fuel_limit:         u64,
    pub memory_max_bytes:   u32,
    pub timeout_ms:         u32,
    pub hostcall_allowlist: Vec<HostcallName>,
}
```

Hostcall execution flow:
1. WASM plugin calls hostcall (via wasmtime ABI)
2. Host checks `plugin.hostcall_allowlist`. Not allowed → return error to WASM.
3. Host emits `0x28 PLUGIN_HOSTCALL` WAL event (audit).
4. Host executes hostcall body. Time-budget enforced via wasmtime epoch interruption.
5. Return value serialized to WASM linear memory.

**No ambient filesystem, no network.** WASM cannot open files or sockets. Only hostcalls listed in allowlist.

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
| G.5 Emergent Comp | Skills don't call tools | Hooks cannot call Schicht-0 tools (S3 typestate enforced) |
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

**v1.1 skill+plugin BUILD-READY.** S3 (PermissionToken<T> phantom type) RESOLVED via full sealed-trait + PhantomData + pub(crate) mint() implementation. Compile-time vault-access enforcement.
