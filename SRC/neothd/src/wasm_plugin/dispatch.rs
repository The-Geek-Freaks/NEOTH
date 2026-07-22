//! Pick #34 follow-up — plugin pre-flight + dispatch site.
//!
//! Two responsibilities split across small helpers:
//!
//! 1. [`compile_all_discovered`] walks the discovery report and
//!    compiles every loaded plugin against the live wasmtime engine.
//!    Operator-facing `neoth plugins list` calls this so the listing
//!    surfaces compile errors before any plugin is actually invoked.
//!
//! 2. [`InvocationOutcome`] captures one live invocation: instantiate, validate
//!    the SDK ABI version export, then call `neoth_run`. The same path backs the
//!    hook engine and `neoth plugin test`.

use std::collections::HashMap;
use std::sync::Arc;

use neoth_plugin_sdk::guest::{ABI_VERSION, ABI_VERSION_EXPORT, RUN_EXPORT};
use wasmtime::Module;

use crate::security::redact::redact_text;
use crate::wal::writer::WalWriterHandle;
use crate::wasm_plugin::discovery::{DiscoveredPlugin, DiscoveryReport, PluginApproval};
use crate::wasm_plugin::engine::{
    DEFAULT_FUEL_BUDGET, DEFAULT_MEMORY_LIMIT_BYTES, NeothEngine, PluginStoreState, RecallDbHandle,
};
use crate::wasm_plugin::hostcalls::HostcallPermission;
use crate::wasm_plugin::manifest::PluginManifest;

/// Validated resource limits bound to one compiled plugin.
///
/// These values come from the same manifest whose canonical digest is stored in
/// [`PluginApproval`]. Keeping them beside the compiled module prevents the
/// production invoker from silently falling back to global defaults after an
/// operator approved per-plugin limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PluginExecutionLimits {
    pub fuel_budget: u64,
    pub memory_limit_bytes: usize,
}

impl PluginExecutionLimits {
    #[must_use]
    pub fn from_manifest(manifest: &PluginManifest) -> Self {
        Self {
            fuel_budget: manifest.fuel_budget_override.unwrap_or(DEFAULT_FUEL_BUDGET),
            memory_limit_bytes: manifest
                .memory_limit_bytes
                .unwrap_or(DEFAULT_MEMORY_LIMIT_BYTES),
        }
    }
}

impl Default for PluginExecutionLimits {
    fn default() -> Self {
        Self {
            fuel_budget: DEFAULT_FUEL_BUDGET,
            memory_limit_bytes: DEFAULT_MEMORY_LIMIT_BYTES,
        }
    }
}

/// Outcome of compiling one discovered plugin.
#[derive(Debug, Clone)]
pub enum CompileOutcome {
    /// Compilation succeeded — module is ready for instantiation.
    Compiled {
        plugin_id: String,
        module: Arc<Module>,
        execution_limits: PluginExecutionLimits,
    },
    /// Compilation failed — operator-facing error message included
    /// so `neoth plugins list` can render the cause without re-running.
    Failed { plugin_id: String, error: String },
}

impl CompileOutcome {
    pub fn plugin_id(&self) -> &str {
        match self {
            CompileOutcome::Compiled { plugin_id, .. } => plugin_id,
            CompileOutcome::Failed { plugin_id, .. } => plugin_id,
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, CompileOutcome::Compiled { .. })
    }
}

/// Compile every loaded plugin from a discovery report. Returns one
/// `CompileOutcome` per discovered plugin in the same order. The
/// caller decides what to do with `Failed` entries — `plugins list`
/// renders them inline; the hook engine skips them.
pub fn compile_all_discovered(
    engine: &NeothEngine,
    report: &DiscoveryReport,
) -> Vec<CompileOutcome> {
    let mut out = Vec::with_capacity(report.loaded.len());
    for plugin in &report.loaded {
        out.push(compile_one(engine, plugin));
    }
    out
}

fn compile_one(engine: &NeothEngine, plugin: &DiscoveredPlugin) -> CompileOutcome {
    match engine.compile_from_bytes(&plugin.wasm_bytes) {
        Ok(module) => CompileOutcome::Compiled {
            plugin_id: plugin.manifest.id.clone(),
            module: Arc::new(module),
            execution_limits: PluginExecutionLimits::from_manifest(&plugin.manifest),
        },
        Err(e) => CompileOutcome::Failed {
            plugin_id: plugin.manifest.id.clone(),
            error: format!("{e}"),
        },
    }
}

/// Result the dispatcher hands back to the caller (CLI list / hook
/// engine / future scheduler). Stable struct so hook-engine code can
/// pattern-match on it before the live invocation wire lands.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InvocationOutcome {
    pub plugin_id: String,
    pub stage: InvocationStage,
    pub error: Option<String>,
}

/// Where the invocation stopped. The hook engine logs this to
/// `EVENT_TYPE_PLUGIN_HOSTCALL` so the operator can see at-a-glance
/// whether the dispatch reached the plugin or bailed earlier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationStage {
    /// Pre-flight compile of the .wasm bytes.
    Compile,
    /// Instantiating the module in a fresh per-plugin Store.
    Instantiate,
    /// Looking up the `neoth_run` export.
    ExportLookup,
    /// Looking up or validating the versioned guest ABI export.
    AbiVersion,
    /// Calling the export — `neoth_run` returned a trap or normal
    /// completion. The completing path arrives here without an error
    /// set; trap paths set both `error` + this stage.
    Run,
    /// Invocation skipped because compile failed earlier.
    SkippedDueToCompileFailure,
}

/// Convenience constructor for the common "did not reach the plugin"
/// failure shape. The CLI uses this when a plugin is rejected by
/// pre-flight compile.
pub fn skip_due_to_compile(
    plugin_id: impl Into<String>,
    error: impl Into<String>,
) -> InvocationOutcome {
    InvocationOutcome {
        plugin_id: plugin_id.into(),
        stage: InvocationStage::SkippedDueToCompileFailure,
        error: Some(error.into()),
    }
}

/// Promote a `CompileOutcome::Failed` directly into an
/// `InvocationOutcome::SkippedDueToCompileFailure`. The hook engine
/// uses this when iterating compile-then-dispatch.
pub fn invocation_outcome_from_compile_failure(o: &CompileOutcome) -> Option<InvocationOutcome> {
    match o {
        CompileOutcome::Failed { plugin_id, error } => Some(skip_due_to_compile(plugin_id, error)),
        CompileOutcome::Compiled { .. } => None,
    }
}

/// Phase 2 — instantiate the compiled module + look up the
/// `neoth_run` export + call it.
///
/// Behaviour pinned for v0.1:
///   - Plugin store gets `PluginStoreState::new(plugin_id)` with the
///     manifest's memory_limit + fuel budget honoured, and the operator-
///     granted permission level (`granted`) wired in via `with_granted`
///     so the hostcall capability gate (SC-04) enforces it at run time.
///   - The module must export `fn neoth_abi_version() -> i32` returning the
///     SDK's exact [`ABI_VERSION`] before `fn neoth_run() -> i32` is called.
///   - `neoth_run` return `0` means success; non-zero is a failed invocation.
///   - A missing `neoth_run` export surfaces as
///     `InvocationOutcome::ExportLookup` with a clear error string
///     so the operator knows the plugin doesn't follow the ABI.
///
/// The wasmtime `Linker` parameter is the one
/// `hostcalls::build_linker(engine)` returns — it owns the four
/// `neoth.*` hostcalls.
pub fn invoke_plugin(
    engine: &NeothEngine,
    module: &wasmtime::Module,
    linker: &wasmtime::Linker<crate::wasm_plugin::engine::PluginStoreState>,
    plugin_id: impl Into<String>,
    granted: HostcallPermission,
    execution_limits: PluginExecutionLimits,
    wal_writer: Option<WalWriterHandle>,
    recall_db: Option<RecallDbHandle>,
) -> InvocationOutcome {
    let plugin_id = plugin_id.into();
    // SC-04: attach the grant AND the runtime handles so the hostcall
    // gate can both ENFORCE (grant) and AUDIT (the writer emits 0xC7 on
    // a denied call, 0xC4/0xC6 on a used one). Without the writer the
    // refusal still holds, but the denial would be invisible in the WAL
    // — and the "No ambient plugin power" guarantee is only worth
    // anything if it is PROVABLE, so the production path must carry it.
    let mut state = crate::wasm_plugin::engine::PluginStoreState::new(&plugin_id)
        .with_fuel(execution_limits.fuel_budget)
        .with_memory_limit(execution_limits.memory_limit_bytes)
        .with_granted(granted);
    if let Some(w) = wal_writer {
        state = state.with_wal_writer(w);
    }
    if let Some(db) = recall_db {
        state = state.with_recall_db(db);
    }
    invoke_plugin_with_state(engine, module, linker, state)
}

/// UX-07b — invoke a plugin with a CALLER-BUILT [`PluginStoreState`] instead of
/// constructing it from `(granted, wal_writer, recall_db)` internally. Lets the
/// test/dev harness (`neoth plugin test --capture-wal`) inject a real WAL
/// writer + grant and then observe the `0xC4 PLUGIN_HOSTCALL` /
/// `0xC6 PLUGIN_CAP_USED` / `0xC7 PLUGIN_CAP_DENIED` frames the invocation
/// emits. [`invoke_plugin`] is the thin wrapper that builds the state from its
/// params and delegates here — the body below is the identical instantiation +
/// `neoth_run` call, minus the state construction. The outcome's `plugin_id`
/// comes from `state.plugin_id`.
pub fn invoke_plugin_with_state(
    engine: &NeothEngine,
    module: &wasmtime::Module,
    linker: &wasmtime::Linker<crate::wasm_plugin::engine::PluginStoreState>,
    state: crate::wasm_plugin::engine::PluginStoreState,
) -> InvocationOutcome {
    let plugin_id = state.plugin_id.clone();

    let mut store = match engine.new_store(state) {
        Ok(s) => s,
        Err(e) => {
            return InvocationOutcome {
                plugin_id,
                stage: InvocationStage::Instantiate,
                error: Some(redact_text(&format!("new_store: {e}"))),
            };
        }
    };

    let instance = match linker.instantiate(&mut store, module) {
        Ok(i) => i,
        Err(e) => {
            return InvocationOutcome {
                plugin_id,
                stage: InvocationStage::Instantiate,
                error: Some(redact_text(&format!("linker.instantiate: {e}"))),
            };
        }
    };

    let func = match instance.get_typed_func::<(), i32>(&mut store, RUN_EXPORT) {
        Ok(f) => f,
        Err(e) => {
            return InvocationOutcome {
                plugin_id,
                stage: InvocationStage::ExportLookup,
                error: Some(redact_text(&format!(
                    "missing `fn {RUN_EXPORT}() -> i32` export: {e}"
                ))),
            };
        }
    };

    let abi_version = match instance.get_typed_func::<(), i32>(&mut store, ABI_VERSION_EXPORT) {
        Ok(f) => f,
        Err(e) => {
            return InvocationOutcome {
                plugin_id,
                stage: InvocationStage::AbiVersion,
                error: Some(redact_text(&format!(
                    "missing `fn {ABI_VERSION_EXPORT}() -> i32` export required by guest ABI v{ABI_VERSION}: {e}"
                ))),
            };
        }
    };
    let reported_version = match abi_version.call(&mut store, ()) {
        Ok(version) => version,
        Err(e) => {
            return InvocationOutcome {
                plugin_id,
                stage: InvocationStage::AbiVersion,
                error: Some(redact_text(&format!("`{ABI_VERSION_EXPORT}` trapped: {e}"))),
            };
        }
    };
    if reported_version != ABI_VERSION {
        return InvocationOutcome {
            plugin_id,
            stage: InvocationStage::AbiVersion,
            error: Some(format!(
                "guest ABI version mismatch: plugin={reported_version}, host={ABI_VERSION}; rebuild the plugin against neoth-plugin-sdk"
            )),
        };
    }

    match func.call(&mut store, ()) {
        Ok(0) => InvocationOutcome {
            plugin_id,
            stage: InvocationStage::Run,
            error: None,
        },
        Ok(rc) => InvocationOutcome {
            plugin_id,
            stage: InvocationStage::Run,
            error: Some(format!("{RUN_EXPORT} returned non-zero status {rc}")),
        },
        Err(e) => {
            // GOLD-ADAPT-G-02 — a fuel-exhausted plugin is a resource-abuse
            // signal, not a generic trap: anchor it as `0xC5
            // PLUGIN_FUEL_EXHAUSTED` so WAL replay shows which plugin burned
            // its budget. Best-effort like every plugin frame.
            if matches!(
                e.downcast_ref::<wasmtime::Trap>(),
                Some(wasmtime::Trap::OutOfFuel)
            ) && let Some(w) = &store.data().wal_writer
            {
                let payload = serde_json::to_vec(&serde_json::json!({
                    "plugin": plugin_id,
                    "fuel_budget": store.data().fuel_budget,
                }))
                .unwrap_or_else(|_| b"{}".to_vec());
                let header = crate::wal::HeaderBuilder::new(
                    crate::wal::events::EVENT_TYPE_PLUGIN_FUEL_EXHAUSTED,
                    &payload,
                )
                .build();
                if let Err(we) = w.try_append_sync(header, payload) {
                    tracing::warn!(error = %we, plugin = %plugin_id,
                            "0xC5 fuel-exhausted WAL frame failed (best-effort)");
                }
            }
            InvocationOutcome {
                plugin_id,
                stage: InvocationStage::Run,
                error: Some(redact_text(&format!("neoth_run trapped: {e}"))),
            }
        }
    }
}

/// Daemon-side `hooks::PluginInvoker` impl. Holds the engine, the
/// compiled-module registry, and the hostcalls linker — everything
/// `invoke_plugin()` needs to fire a plugin by id. The daemon
/// bootstrap discovers + compiles + builds an instance of this
/// struct, then hands an `Arc<CompiledPluginInvoker>` to the hook
/// engine.
///
/// The approved plugin set is a bootstrap snapshot. Re-discovery (for example,
/// after an operator installs or re-enables a plugin) requires a daemon
/// restart because the hook invoker is fixed for that daemon lifetime. Its
/// registration is released at shutdown so a later in-process daemon can bind
/// a fresh home. Live reload can only remove authority: every call re-checks
/// revocation and the exact approval record captured here.
pub struct CompiledPluginInvoker {
    engine: Arc<NeothEngine>,
    linker: Arc<wasmtime::Linker<PluginStoreState>>,
    /// Module, exact approval, and manifest-derived limits are inserted as one
    /// value. An executable module therefore cannot drift away from the
    /// authority and resource ceilings that admitted it.
    plugins: HashMap<String, ApprovedCompiledPlugin>,
    /// SC-04: the daemon's WAL writer handle (a clone of the single
    /// segment writer — NOT a second writer, which would race). Threaded
    /// into every plugin store so the hostcall gate's `0xC7` deny audit
    /// (and the `0xC4`/`0xC6` use frames) actually land in the WAL.
    /// `None` in tests / the `neoth plugin test` dry-run path.
    wal_writer: Option<WalWriterHandle>,
    /// Shared read-only `views.db` handle so `recall_top` can return
    /// real hit counts in production (not just 0). Best-effort: `None`
    /// degrades recall_top to "no signal".
    recall_db: Option<RecallDbHandle>,
    /// Live config handle for the per-invoke revocation and exact-approval
    /// check. Without it, a disable, revocation, or approval mutation made by
    /// `neoth reload` would not reach the process-global invoker until restart.
    /// `None` is limited to tests and dry-run paths with no reload surface.
    reload_controller: Option<Arc<crate::config::reload::ReloadController>>,
}

struct ApprovedCompiledPlugin {
    module: Arc<Module>,
    approval: PluginApproval,
    execution_limits: PluginExecutionLimits,
    integrity_policy: Option<PluginIntegrityPolicyFingerprint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PluginIntegrityPolicyFingerprint {
    pinned_hash: Option<String>,
    require_all_pinned: bool,
    author_pubkey: Option<String>,
    require_signature: bool,
}

impl PluginIntegrityPolicyFingerprint {
    fn capture(plugin_id: &str, config: &crate::config::WasmPluginsConfig) -> Self {
        Self {
            pinned_hash: config
                .pinned_hashes
                .get(plugin_id)
                .map(|hash| hash.to_ascii_lowercase()),
            require_all_pinned: config.require_all_pinned,
            author_pubkey: config.author_pubkey.clone(),
            require_signature: config.require_signature,
        }
    }

    fn matches(&self, plugin_id: &str, config: &crate::config::WasmPluginsConfig) -> bool {
        self == &Self::capture(plugin_id, config)
    }
}

impl CompiledPluginInvoker {
    /// Build an invoker from a compile-pass result, linker, and the exact
    /// approvals that admitted those modules. Runtime grants are derived here
    /// from `PluginApproval::approved_permission`; callers cannot supply a
    /// different grant map. Only `Compiled` outcomes are registered; `Failed`
    /// entries are dropped after the operator-facing compile report. Empty
    /// input is legal and fails every invoke as an unknown plugin id.
    pub fn from_compile_outcomes(
        engine: Arc<NeothEngine>,
        outcomes: &[CompileOutcome],
        linker: Arc<wasmtime::Linker<PluginStoreState>>,
        approval_bindings: HashMap<String, PluginApproval>,
    ) -> anyhow::Result<Self> {
        let mut plugins = HashMap::new();
        for o in outcomes {
            if let CompileOutcome::Compiled {
                plugin_id,
                module,
                execution_limits,
            } = o
            {
                let approval = approval_bindings.get(plugin_id).cloned().ok_or_else(|| {
                    anyhow::anyhow!(
                        "compiled plugin {plugin_id:?} has no exact operator approval binding"
                    )
                })?;
                plugins.insert(
                    plugin_id.clone(),
                    ApprovedCompiledPlugin {
                        module: module.clone(),
                        approval,
                        execution_limits: *execution_limits,
                        integrity_policy: None,
                    },
                );
            }
        }
        Ok(Self {
            engine,
            linker,
            plugins,
            wal_writer: None,
            recall_db: None,
            reload_controller: None,
        })
    }

    /// SC-04: attach the daemon's runtime handles (a CLONE of the single
    /// WAL writer + a shared read-only views.db) so plugin hostcalls
    /// audit + read in production. Builder-style so the daemon bootstrap
    /// reads naturally and tests can omit it (None = no audit frames /
    /// recall_top returns 0).
    #[must_use]
    pub fn with_runtime_handles(
        mut self,
        wal_writer: Option<WalWriterHandle>,
        recall_db: Option<RecallDbHandle>,
    ) -> Self {
        self.wal_writer = wal_writer;
        self.recall_db = recall_db;
        self
    }

    /// Attach the daemon's live-config handle so every invoke re-checks the
    /// host switch, revocations, complete approval record, and immutable
    /// bootstrap integrity-policy fingerprint. Authority removal takes effect
    /// immediately; artifact-admission policy drift refuses execution until a
    /// restart can revalidate the compiled generation.
    #[must_use]
    pub fn with_reload_controller(
        mut self,
        controller: Arc<crate::config::reload::ReloadController>,
    ) -> Self {
        self.reload_controller = Some(controller);
        self
    }

    /// Bind each compiled plugin to the exact integrity posture that admitted
    /// it at bootstrap. A live reload may revoke/disable a plugin, but a pin,
    /// require-all, author-key, or signature-policy change requires restart so
    /// the artifact can be verified again before another invocation.
    #[must_use]
    pub fn with_integrity_policy(mut self, config: &crate::config::WasmPluginsConfig) -> Self {
        for (plugin_id, plugin) in &mut self.plugins {
            plugin.integrity_policy =
                Some(PluginIntegrityPolicyFingerprint::capture(plugin_id, config));
        }
        self
    }

    /// True when no plugins are registered. Useful for the daemon's
    /// bootstrap to decide whether to wire the invoker into the
    /// hook engine at all — wiring an empty invoker is fine but the
    /// log line `no PluginInvoker wired` is more honest.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Number of registered plugins. Surfaces in the
    /// `neoth doctor --explain plugins` output.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }
}

impl crate::hooks::dispatcher::PluginInvoker for CompiledPluginInvoker {
    fn invoke(&self, plugin_id: &str) -> anyhow::Result<()> {
        let plugin = self.plugins.get(plugin_id).ok_or_else(|| {
            anyhow::anyhow!(
                "CompiledPluginInvoker: unknown plugin id {plugin_id:?} — known: [{}]",
                self.plugins.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        })?;

        // Live authority gate. `ReloadController::latest()` is a lock-free
        // ArcSwap load; revoked_ids is expected to remain a short operator list.
        if let Some(ctrl) = &self.reload_controller {
            let cfg = ctrl.latest();
            if !cfg.plugins.wasm.enabled {
                anyhow::bail!(
                    "plugin {plugin_id:?} host is disabled in live config — refusing invoke"
                );
            }
            if cfg
                .plugins
                .wasm
                .revoked_ids
                .iter()
                .any(|id| id == plugin_id)
            {
                anyhow::bail!(
                    "plugin {plugin_id:?} is revoked (plugins.wasm.revoked_ids, \
                     live config) — refusing invoke"
                );
            }
            let current = cfg.plugins.wasm.activations.get(plugin_id).ok_or_else(|| {
                anyhow::anyhow!(
                    "plugin {plugin_id:?} activation approval is missing in live config — \
                         refusing invoke"
                )
            })?;
            if current.state != crate::wasm_plugin::discovery::PluginActivation::Active
                || current.approval.as_ref() != Some(&plugin.approval)
            {
                anyhow::bail!(
                    "plugin {plugin_id:?} activation approval changed after bootstrap — \
                    refusing invoke; explicitly re-enable and restart the daemon"
                );
            }
            let integrity_policy = plugin.integrity_policy.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "plugin {plugin_id:?} has no bootstrap integrity-policy binding — \
                     refusing live-config invoke"
                )
            })?;
            if !integrity_policy.matches(plugin_id, &cfg.plugins.wasm) {
                anyhow::bail!(
                    "plugin {plugin_id:?} integrity policy changed after bootstrap — \
                     refusing invoke; restart the daemon to revalidate the artifact"
                );
            }
        }
        // Authority and resource limits come from the same immutable binding
        // as the executable module; there is no separately supplied grant map.
        let granted = HostcallPermission::from(plugin.approval.approved_permission);
        let outcome = invoke_plugin(
            &self.engine,
            &plugin.module,
            &self.linker,
            plugin_id,
            granted,
            plugin.execution_limits,
            self.wal_writer.clone(),
            self.recall_db.clone(),
        );
        if let Some(err) = outcome.error {
            anyhow::bail!(
                "plugin {plugin_id:?} stage={stage:?}: {err}",
                stage = outcome.stage,
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm_plugin::manifest::{PluginManifest, RequestedPermission};
    use std::path::PathBuf;

    fn minimal_wasm() -> Vec<u8> {
        // Magic `\0asm` + version 1 LE. Smallest valid module.
        vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
    }

    fn approvals_for(
        ids: &[&str],
        permission: RequestedPermission,
    ) -> HashMap<String, PluginApproval> {
        ids.iter()
            .map(|id| {
                (
                    (*id).to_string(),
                    PluginApproval {
                        approved_permission: permission,
                        manifest_sha256: format!("manifest-{id}"),
                        wasm_sha256: format!("wasm-{id}"),
                    },
                )
            })
            .collect()
    }

    fn active_plugin_config() -> crate::config::FreedomConfig {
        let mut config = crate::config::FreedomConfig::default();
        config.plugins.wasm.activations.insert(
            "alpha".to_string(),
            crate::wasm_plugin::discovery::PluginActivationRecord {
                state: crate::wasm_plugin::discovery::PluginActivation::Active,
                approval: Some(PluginApproval {
                    approved_permission: RequestedPermission::None,
                    manifest_sha256: "manifest-at-bootstrap".to_string(),
                    wasm_sha256: "wasm-at-bootstrap".to_string(),
                }),
            },
        );
        config
    }

    fn live_config_invoker(
        initial: &crate::config::FreedomConfig,
        config_path: PathBuf,
    ) -> (
        CompiledPluginInvoker,
        Arc<crate::config::reload::ReloadController>,
    ) {
        let controller = Arc::new(crate::config::reload::ReloadController::new(
            initial.clone(),
            config_path,
        ));
        let engine = Arc::new(NeothEngine::new().expect("engine"));
        let linker =
            Arc::new(crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker"));
        let module = engine
            .compile_from_bytes(&minimal_wasm())
            .expect("minimal must compile");
        let outcomes = vec![CompileOutcome::Compiled {
            plugin_id: "alpha".into(),
            module: Arc::new(module),
            execution_limits: PluginExecutionLimits::default(),
        }];
        let approval = initial.plugins.wasm.activations["alpha"]
            .approval
            .clone()
            .expect("active fixture approval");
        let invoker = CompiledPluginInvoker::from_compile_outcomes(
            engine,
            &outcomes,
            linker,
            HashMap::from([("alpha".to_string(), approval)]),
        )
        .expect("approved invoker")
        .with_integrity_policy(&initial.plugins.wasm)
        .with_reload_controller(controller.clone());
        (invoker, controller)
    }

    /// A complete WASM module that:
    ///   - imports all four ABI v1 NEOTH hostcalls
    ///   - exports `fn neoth_abi_version() -> i32` (returns ABI v1)
    ///   - exports `fn neoth_run() -> i32` (returns 0)
    ///   - exports a `memory` page (required by neoth.log / neoth.emit_event)
    ///
    /// Encoded by hand from this WAT:
    ///
    /// ```wat
    /// (module
    ///   (type (func (param i32 i32)))              ;; 0: log
    ///   (type (func (result i64)))                 ;; 1: fuel_left
    ///   (type (func (param i32 i32 i32 i32) (result i32))) ;; 2: emit_event
    ///   (type (func (param i64) (result i32)))     ;; 3: recall_top
    ///   (type (func (result i32)))                 ;; 4: neoth_run
    ///   (import "neoth" "log"         (func (type 0)))
    ///   (import "neoth" "fuel_left"   (func (type 1)))
    ///   (import "neoth" "emit_event"  (func (type 2)))
    ///   (import "neoth" "recall_top"  (func (type 3)))
    ///   (func (type 4) (i32.const 1))  ;; func index 4 = neoth_abi_version
    ///   (func (type 4) (i32.const 0))  ;; func index 5 = neoth_run
    ///   (memory 1)
    ///   (export "neoth_abi_version" (func 4))
    ///   (export "neoth_run" (func 5))
    ///   (export "memory"    (mem  0))
    /// )
    /// ```
    ///
    /// Used by tests that need a plugin which actually reaches the Run stage.
    fn echo_wasm() -> Vec<u8> {
        echo_wasm_with_version(ABI_VERSION)
    }

    fn echo_wasm_with_version(abi_version: i32) -> Vec<u8> {
        assert!((0..=63).contains(&abi_version));
        // Helper: encode a LEB128 unsigned integer.
        fn uleb(n: u32) -> Vec<u8> {
            let mut out = Vec::new();
            let mut v = n;
            loop {
                let byte = (v & 0x7F) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(byte);
                    break;
                } else {
                    out.push(byte | 0x80);
                }
            }
            out
        }

        // Helper: prepend a LEB128 length to a byte slice (section body encoding).
        fn with_len(body: Vec<u8>) -> Vec<u8> {
            let mut out = uleb(body.len() as u32);
            out.extend(body);
            out
        }

        // Helper: WASM string encoding (u32 length + UTF-8 bytes).
        fn wasm_str(s: &str) -> Vec<u8> {
            let mut out = uleb(s.len() as u32);
            out.extend_from_slice(s.as_bytes());
            out
        }

        // ── Type section ────────────────────────────────────────────────────
        // 5 function types. 0x60 = func type marker.
        let mut type_body: Vec<u8> = uleb(5); // count
        // type 0: (i32, i32) -> ()
        type_body.extend([0x60, 0x02, 0x7f, 0x7f, 0x00]);
        // type 1: () -> (i64)
        type_body.extend([0x60, 0x00, 0x01, 0x7e]);
        // type 2: (i32, i32, i32, i32) -> (i32)
        type_body.extend([0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f]);
        // type 3: (i64) -> (i32)
        type_body.extend([0x60, 0x01, 0x7e, 0x01, 0x7f]);
        // type 4: () -> (i32)
        type_body.extend([0x60, 0x00, 0x01, 0x7f]);
        let type_section = [vec![0x01], with_len(type_body)].concat();

        // ── Import section ──────────────────────────────────────────────────
        // 4 imports, all function (kind=0x00).
        let mut import_body: Vec<u8> = uleb(4); // count
        for (module, name, type_idx) in &[
            (
                neoth_plugin_sdk::guest::IMPORT_MODULE,
                neoth_plugin_sdk::guest::HOSTCALL_LOG,
                0u32,
            ),
            (
                neoth_plugin_sdk::guest::IMPORT_MODULE,
                neoth_plugin_sdk::guest::HOSTCALL_FUEL_LEFT,
                1,
            ),
            (
                neoth_plugin_sdk::guest::IMPORT_MODULE,
                neoth_plugin_sdk::guest::HOSTCALL_EMIT_EVENT,
                2,
            ),
            (
                neoth_plugin_sdk::guest::IMPORT_MODULE,
                neoth_plugin_sdk::guest::HOSTCALL_RECALL_TOP,
                3,
            ),
        ] {
            import_body.extend(wasm_str(module));
            import_body.extend(wasm_str(name));
            import_body.push(0x00); // import kind: function
            import_body.extend(uleb(*type_idx));
        }
        let import_section = [vec![0x02], with_len(import_body)].concat();

        // ── Function section ────────────────────────────────────────────────
        // ABI-version export + run export, both using type index 4.
        let mut func_body: Vec<u8> = uleb(2); // count
        func_body.extend(uleb(4));
        func_body.extend(uleb(4));
        let func_section = [vec![0x03], with_len(func_body)].concat();

        // ── Memory section ──────────────────────────────────────────────────
        // 1 memory, min 1 page (64 KiB), no max.
        let mem_body: Vec<u8> = vec![
            0x01, // count: 1 memory
            0x00, // limit kind: min-only
            0x01, // min: 1 page
        ];
        let mem_section = [vec![0x05], with_len(mem_body)].concat();

        // ── Export section ──────────────────────────────────────────────────
        // 3 exports: ABI version (func 4), run (func 5), memory (mem 0).
        let mut export_body: Vec<u8> = uleb(3); // count
        export_body.extend(wasm_str(ABI_VERSION_EXPORT));
        export_body.push(0x00); // export kind: function
        export_body.extend(uleb(4)); // func index 4 (4 imports + 0th local = index 4)
        export_body.extend(wasm_str(RUN_EXPORT));
        export_body.push(0x00);
        export_body.extend(uleb(5));
        // export "memory" → memory index 0
        export_body.extend(wasm_str("memory"));
        export_body.push(0x02); // export kind: memory
        export_body.extend(uleb(0)); // memory index 0
        let export_section = [vec![0x07], with_len(export_body)].concat();

        // ── Code section ────────────────────────────────────────────────────
        let abi_body: Vec<u8> = vec![
            0x00, // local declaration count: 0
            0x41,
            abi_version as u8,
            0x0b,
        ];
        let run_body: Vec<u8> = vec![
            0x00, // local declaration count: 0
            0x41, 0x00, // i32.const 0
            0x0b, // end
        ];
        let mut code_body: Vec<u8> = uleb(2); // count of function bodies
        code_body.extend(with_len(abi_body));
        code_body.extend(with_len(run_body));
        let code_section = [vec![0x0a], with_len(code_body)].concat();

        // ── Assemble ─────────────────────────────────────────────────────────
        let mut wasm = vec![
            0x00, 0x61, 0x73, 0x6d, // magic
            0x01, 0x00, 0x00, 0x00, // version
        ];
        wasm.extend(type_section);
        wasm.extend(import_section);
        wasm.extend(func_section);
        wasm.extend(mem_section);
        wasm.extend(export_section);
        wasm.extend(code_section);
        wasm
    }

    /// A plugin that imports neoth.recall_top + neoth.emit_event, calls
    /// them, and returns 0.  Structurally identical to echo_wasm() in
    /// encoding — the runtime behaviour exercised by tests is the same
    /// (both reach InvocationStage::Run without error).
    ///
    /// Keeping the two distinct helpers maps 1-to-1 to the two example
    /// plugin source trees under `examples/wasm_plugins/`.
    fn recall_summariser_wasm() -> Vec<u8> {
        // The binary shape is identical to echo_wasm — it imports all 4
        // hostcalls (the linker requires all declared imports to be
        // satisfiable) and returns 0 from neoth_run.  The real plugin
        // source in `examples/wasm_plugins/recall_summariser/` calls the
        // hostcalls at runtime; here we just need the wasm to pass through
        // the full linker→instantiate→run pipeline.
        echo_wasm()
    }

    /// SC-04 gate proof: build a module whose `neoth_run` body actually
    /// CALLS a hostcall at runtime (the existing `echo_wasm` only
    /// imports them and returns 0, so it never reaches the gate). The
    /// import index space is: log=0, fuel_left=1, emit_event=2,
    /// recall_top=3; `neoth_abi_version` is index 4 and `neoth_run` is index 5.
    /// `body_instrs` is
    /// the code-section function body (locals-count byte + instructions
    /// + `0x0b end`). The rest of the module is byte-identical to
    /// `echo_wasm` so only the runtime behaviour differs.
    fn calling_wasm(body_instrs: Vec<u8>) -> Vec<u8> {
        fn uleb(n: u32) -> Vec<u8> {
            let mut out = Vec::new();
            let mut v = n;
            loop {
                let byte = (v & 0x7F) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(byte);
                    break;
                }
                out.push(byte | 0x80);
            }
            out
        }
        fn with_len(body: Vec<u8>) -> Vec<u8> {
            let mut out = uleb(body.len() as u32);
            out.extend(body);
            out
        }
        fn wasm_str(s: &str) -> Vec<u8> {
            let mut out = uleb(s.len() as u32);
            out.extend_from_slice(s.as_bytes());
            out
        }

        let mut type_body: Vec<u8> = uleb(5);
        type_body.extend([0x60, 0x02, 0x7f, 0x7f, 0x00]); // 0: (i32,i32)->()
        type_body.extend([0x60, 0x00, 0x01, 0x7e]); // 1: ()->(i64)
        type_body.extend([0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f]); // 2: (i32*4)->(i32)
        type_body.extend([0x60, 0x01, 0x7e, 0x01, 0x7f]); // 3: (i64)->(i32)
        type_body.extend([0x60, 0x00, 0x01, 0x7f]); // 4: ()->(i32)
        let type_section = [vec![0x01], with_len(type_body)].concat();

        let mut import_body: Vec<u8> = uleb(4);
        for (module, name, type_idx) in &[
            (
                neoth_plugin_sdk::guest::IMPORT_MODULE,
                neoth_plugin_sdk::guest::HOSTCALL_LOG,
                0u32,
            ),
            (
                neoth_plugin_sdk::guest::IMPORT_MODULE,
                neoth_plugin_sdk::guest::HOSTCALL_FUEL_LEFT,
                1,
            ),
            (
                neoth_plugin_sdk::guest::IMPORT_MODULE,
                neoth_plugin_sdk::guest::HOSTCALL_EMIT_EVENT,
                2,
            ),
            (
                neoth_plugin_sdk::guest::IMPORT_MODULE,
                neoth_plugin_sdk::guest::HOSTCALL_RECALL_TOP,
                3,
            ),
        ] {
            import_body.extend(wasm_str(module));
            import_body.extend(wasm_str(name));
            import_body.push(0x00);
            import_body.extend(uleb(*type_idx));
        }
        let import_section = [vec![0x02], with_len(import_body)].concat();

        let mut func_body: Vec<u8> = uleb(2);
        func_body.extend(uleb(4)); // neoth_abi_version: ()->i32
        func_body.extend(uleb(4)); // neoth_run: ()->i32
        let func_section = [vec![0x03], with_len(func_body)].concat();

        let mem_body: Vec<u8> = vec![0x01, 0x00, 0x01];
        let mem_section = [vec![0x05], with_len(mem_body)].concat();

        let mut export_body: Vec<u8> = uleb(3);
        export_body.extend(wasm_str(ABI_VERSION_EXPORT));
        export_body.push(0x00);
        export_body.extend(uleb(4));
        export_body.extend(wasm_str(RUN_EXPORT));
        export_body.push(0x00);
        export_body.extend(uleb(5));
        export_body.extend(wasm_str("memory"));
        export_body.push(0x02);
        export_body.extend(uleb(0));
        let export_section = [vec![0x07], with_len(export_body)].concat();

        let abi_body = vec![0x00, 0x41, ABI_VERSION as u8, 0x0b];
        let mut code_body: Vec<u8> = uleb(2);
        code_body.extend(with_len(abi_body));
        code_body.extend(with_len(body_instrs));
        let code_section = [vec![0x0a], with_len(code_body)].concat();

        let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        wasm.extend(type_section);
        wasm.extend(import_section);
        wasm.extend(func_section);
        wasm.extend(mem_section);
        wasm.extend(export_section);
        wasm.extend(code_section);
        wasm
    }

    /// `neoth_run` body: `i64.const 1; call recall_top; end`. Returns the
    /// i32 the gated `recall_top` hostcall produces.
    fn calling_recall_wasm() -> Vec<u8> {
        calling_wasm(vec![0x00, 0x42, 0x01, 0x10, 0x03, 0x0b])
    }

    /// `neoth_run` body: `i32.const 0 ×4; call emit_event; end`. Returns
    /// the i32 return code the gated `emit_event` hostcall produces.
    fn calling_emit_wasm() -> Vec<u8> {
        calling_wasm(vec![
            0x00, 0x41, 0x00, 0x41, 0x00, 0x41, 0x00, 0x41, 0x00, 0x10, 0x02, 0x0b,
        ])
    }

    fn views_db_with_hash(hash: &str) -> std::sync::Arc<std::sync::Mutex<rusqlite::Connection>> {
        let conn = rusqlite::Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE idx_episode (
                event_id   INTEGER PRIMARY KEY,
                event_type INTEGER NOT NULL,
                ts_ns      INTEGER NOT NULL,
                text       TEXT NOT NULL,
                text_hash  TEXT NOT NULL,
                importance REAL NOT NULL DEFAULT 0.5,
                last_access_ts INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX idx_episode_hash ON idx_episode (text_hash);",
        )
        .expect("fixture schema");
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (1, 1, 1700000000000000000, 'probe', ?1)",
            rusqlite::params![hash],
        )
        .expect("insert fixture row");
        std::sync::Arc::new(std::sync::Mutex::new(conn))
    }

    /// Run a `calling_*` module against a store and return `neoth_run`'s
    /// i32. Shared by the gate tests so each one only varies the grant.
    fn run_neoth_run(wasm: &[u8], state: PluginStoreState) -> i32 {
        let engine = NeothEngine::new().expect("engine");
        let module = engine.compile_from_bytes(wasm).expect("compile");
        let linker =
            crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker build");
        let mut store = engine.new_store(state).expect("store seed");
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("instantiate");
        let func = instance
            .get_typed_func::<(), i32>(&mut store, "neoth_run")
            .expect("neoth_run export");
        func.call(&mut store, ()).expect("neoth_run must not trap")
    }

    #[test]
    fn recall_top_gate_denies_at_none_grant() {
        // recall_top(1) matches the {:016x} row, so a granted plugin
        // would read 1 hit — but a None-granted plugin (the fail-closed
        // default) must be REFUSED and get 0, indistinguishable from an
        // empty store. Proves the gate fires (contrast with the allow
        // test which gets 1 from the SAME db).
        let db = views_db_with_hash("0000000000000001");
        let state = PluginStoreState::new("snoop").with_recall_db(db);
        // default grant is None
        let rc = run_neoth_run(&calling_recall_wasm(), state);
        assert_eq!(rc, 0, "None-granted recall_top MUST be denied (return 0)");
    }

    #[test]
    fn recall_top_gate_allows_at_readonly_grant() {
        // SAME db + row as the deny test; the only difference is the
        // grant. ReadOnly covers recall_top → the real hit count (1)
        // flows back. This pair is the definitive proof the gate is the
        // thing controlling access, not db state.
        let db = views_db_with_hash("0000000000000001");
        let state = PluginStoreState::new("reader")
            .with_recall_db(db)
            .with_granted(HostcallPermission::ReadOnly);
        let rc = run_neoth_run(&calling_recall_wasm(), state);
        assert_eq!(rc, 1, "ReadOnly-granted recall_top MUST read the hit (1)");
    }

    #[test]
    fn emit_event_gate_denies_below_write() {
        // emit_event requires Write; a ReadOnly plugin must be refused
        // with code 7 and write NO frame. No writer attached — the deny
        // happens before any WAL touch.
        let state =
            PluginStoreState::new("writer-wannabe").with_granted(HostcallPermission::ReadOnly);
        let rc = run_neoth_run(&calling_emit_wasm(), state);
        assert_eq!(rc, 7, "below-Write emit_event MUST be denied (code 7)");
    }

    #[tokio::test]
    async fn emit_event_gate_allows_at_write_grant() {
        // Write grant + a real writer → emit_event succeeds (code 0).
        // tokio runtime needed: `wal::writer::spawn` spawns a writer task.
        use crate::wal::writer::spawn;
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let (writer, _join) = spawn(dir.path().join("000001.wal")).expect("spawn writer");
        let state = PluginStoreState::new("real-writer")
            .with_wal_writer(writer)
            .with_granted(HostcallPermission::Write);
        let rc = run_neoth_run(&calling_emit_wasm(), state);
        assert_eq!(rc, 0, "Write-granted emit_event MUST succeed (code 0)");
    }

    /// Count frames of a given event type in a WAL segment file. Mirrors
    /// the robust v1/v2 read pattern the `neoth plugin ledger` walker uses.
    fn count_event_frames(segment: &std::path::Path, event_type: u8) -> usize {
        use crate::wal::compress::decompress_frames;
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::parse_segment_header;
        let bytes = std::fs::read(segment).expect("read segment");
        let hdr = parse_segment_header(&bytes).expect("parse segment header");
        let body = &bytes[hdr.header_len()..];
        let frames = if hdr.is_compressed() {
            decompress_frames(body).expect("decompress frames")
        } else {
            body.to_vec()
        };
        let mut count = 0usize;
        let mut cursor = 0usize;
        while cursor < frames.len() {
            let dec = match decode_frame(&frames[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == event_type {
                count += 1;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        count
    }

    /// SC-04 PRODUCTION-PATH proof: a denied hostcall invoked through the
    /// real `CompiledPluginInvoker::invoke` (the path the daemon hook
    /// engine uses) must leave a durable `0xC7 PLUGIN_CAP_DENIED` frame in
    /// the WAL. This closes the gap where the gate refused correctly but
    /// the production store carried no writer, so the denial was invisible
    /// — making `neoth wal show --type plugin_cap_denied` hollow.
    #[tokio::test]
    async fn compiled_invoker_emits_cap_denied_frame_via_production_path() {
        use crate::hooks::dispatcher::PluginInvoker;
        use crate::wal::events::EVENT_TYPE_PLUGIN_CAP_DENIED;
        use crate::wal::writer::spawn;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = spawn(seg.clone()).expect("spawn writer");

        let engine = Arc::new(NeothEngine::new().expect("engine"));
        let module = engine
            .compile_from_bytes(&calling_emit_wasm())
            .expect("compile calling-emit plugin");
        let linker =
            Arc::new(crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker"));
        let outcomes = vec![CompileOutcome::Compiled {
            plugin_id: "snoop".into(),
            module: Arc::new(module),
            execution_limits: PluginExecutionLimits::default(),
        }];
        // Exact approval grants None → emit_event (Write) is denied at the gate.
        // Writer attached via with_runtime_handles
        // so the 0xC7 audit frame lands.
        let inv = CompiledPluginInvoker::from_compile_outcomes(
            engine,
            &outcomes,
            linker,
            approvals_for(&["snoop"], RequestedPermission::None),
        )
        .expect("approved invoker")
        .with_runtime_handles(Some(writer), None);

        // Invoke via the PRODUCTION trait path (not a direct store build).
        // The denial is in-band (return code 7, not a trap), so invoke
        // reaches Run and returns Ok.
        inv.invoke("snoop").expect("invoke reaches Run");

        // Flush: drop every writer clone (store clone already dropped
        // inside invoke; the invoker holds the last one) then join.
        drop(inv);
        join.await.expect("writer task join");

        let denied = count_event_frames(&seg, EVENT_TYPE_PLUGIN_CAP_DENIED);
        assert!(
            denied >= 1,
            "production invoke path MUST emit a 0xC7 PLUGIN_CAP_DENIED frame on a denied hostcall; found {denied}"
        );
    }

    /// UX-07b: `invoke_plugin_with_state` honours a CALLER-BUILT state. Inject a
    /// Write grant + a real writer, run a hostcall-emitting plugin, and prove
    /// the injected writer captured the `0xC4 PLUGIN_HOSTCALL` frame + that the
    /// outcome id comes from `state.plugin_id`. This is the seam the
    /// `neoth plugin test --capture-wal` harness rides on.
    #[tokio::test]
    async fn invoke_plugin_with_state_uses_injected_writer() {
        use crate::wal::events::EVENT_TYPE_PLUGIN_HOSTCALL;
        use crate::wal::writer::spawn;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = spawn(seg.clone()).expect("spawn writer");

        let engine = NeothEngine::new().expect("engine");
        let module = engine
            .compile_from_bytes(&calling_emit_wasm())
            .expect("compile calling-emit plugin");
        let linker = crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker");

        // Caller builds the state — the whole point of the new entry point.
        let state = PluginStoreState::new("injected")
            .with_granted(HostcallPermission::Write)
            .with_wal_writer(writer);
        let outcome = invoke_plugin_with_state(&engine, &module, &linker, state);
        assert_eq!(outcome.stage, InvocationStage::Run);
        assert_eq!(
            outcome.plugin_id, "injected",
            "outcome id must come from state.plugin_id"
        );

        // The writer was moved into the state → into the store → dropped when
        // invoke returned. No clone is held here, so join drains cleanly.
        join.await.expect("writer task join");
        let used = count_event_frames(&seg, EVENT_TYPE_PLUGIN_HOSTCALL);
        assert!(
            used >= 1,
            "Write-granted emit via the injected writer MUST leave a 0xC4 frame; found {used}"
        );
    }

    /// GOLD-ADAPT-G-02 — versioned guest whose `neoth_run` loops forever, so
    /// the wasmtime fuel budget must trap it (`Trap::OutOfFuel`).
    fn spin_wasm() -> Vec<u8> {
        calling_wasm(vec![
            0x00, // no locals
            0x03, 0x40, // loop(void)
            0x0c, 0x00, // br 0
            0x0b, // end loop
            0x00, // unreachable result path
            0x0b, // end function
        ])
    }

    /// Pre-SDK legacy shape: exports `neoth_run` but no ABI version function.
    fn legacy_run_only_wasm() -> Vec<u8> {
        vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
            0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, // type section: () -> i32
            0x03, 0x02, 0x01, 0x00, // function section: func 0 uses type 0
            0x07, 0x0d, 0x01, 0x09, b'n', b'e', b'o', b't', b'h', b'_', b'r', b'u', b'n', 0x00,
            0x00, // export "neoth_run" = func 0
            0x0a, 0x06, 0x01, 0x04, 0x00, // code section: 1 body, 4 bytes, 0 locals
            0x41, 0x00, 0x0b, // i32.const 0; end
        ]
    }

    #[tokio::test]
    async fn fuel_exhausted_run_leaves_0xc5_frame() {
        use crate::wal::events::EVENT_TYPE_PLUGIN_FUEL_EXHAUSTED;
        use crate::wal::writer::spawn;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (writer, join) = spawn(seg.clone()).expect("spawn writer");

        let engine = NeothEngine::new().expect("engine");
        let module = engine
            .compile_from_bytes(&spin_wasm())
            .expect("compile spin plugin");
        let linker = crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker");
        let state = PluginStoreState::new("spin").with_wal_writer(writer);
        let outcome = invoke_plugin_with_state(&engine, &module, &linker, state);
        assert_eq!(outcome.stage, InvocationStage::Run);
        assert!(
            outcome.error.as_deref().unwrap_or("").contains("trapped"),
            "spin plugin must trap on fuel exhaustion, got: {:?}",
            outcome.error
        );

        join.await.expect("writer join");
        let frames = count_event_frames(&seg, EVENT_TYPE_PLUGIN_FUEL_EXHAUSTED);
        assert_eq!(
            frames, 1,
            "exactly one 0xC5 frame for the fuel-exhausted run"
        );
    }

    /// UX-07b regression: the refactored `invoke_plugin` wrapper still runs a
    /// plain plugin end-to-end with no writer/db (the pre-refactor behaviour).
    #[test]
    fn invoke_plugin_wrapper_still_runs_without_handles() {
        let engine = NeothEngine::new().expect("engine");
        let module = engine
            .compile_from_bytes(&echo_wasm())
            .expect("compile echo");
        let linker = crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker");
        let outcome = invoke_plugin(
            &engine,
            &module,
            &linker,
            "echo",
            HostcallPermission::None,
            PluginExecutionLimits::default(),
            None,
            None,
        );
        assert_eq!(outcome.stage, InvocationStage::Run);
        assert!(outcome.error.is_none());
        assert_eq!(outcome.plugin_id, "echo");
    }

    fn sample_manifest(id: &str) -> PluginManifest {
        PluginManifest {
            id: id.into(),
            name: id.into(),
            version: "0.1.0".into(),
            description: None,
            requested_permissions: Default::default(),
            hook_stages: vec![],
            fuel_budget_override: None,
            memory_limit_bytes: None,
            source: None,
            ui_surface: None,
        }
    }

    fn discovered(id: &str, bytes: Vec<u8>) -> DiscoveredPlugin {
        let content_hash = super::super::discovery::sha256_hex(&bytes);
        let manifest = sample_manifest(id);
        let manifest_hash = super::super::discovery::canonical_manifest_sha256(&manifest);
        DiscoveredPlugin {
            dir: PathBuf::from(format!("/tmp/{id}")),
            manifest,
            manifest_hash,
            wasm_bytes: bytes,
            content_hash,
            signature: None,
        }
    }

    #[test]
    fn compile_outcome_plugin_id_works_for_both_variants() {
        let ok = CompileOutcome::Compiled {
            plugin_id: "good".into(),
            module: Arc::new(
                NeothEngine::new()
                    .unwrap()
                    .compile_from_bytes(&minimal_wasm())
                    .unwrap(),
            ),
            execution_limits: PluginExecutionLimits::default(),
        };
        assert_eq!(ok.plugin_id(), "good");
        assert!(ok.is_ok());

        let fail = CompileOutcome::Failed {
            plugin_id: "broken".into(),
            error: "x".into(),
        };
        assert_eq!(fail.plugin_id(), "broken");
        assert!(!fail.is_ok());
    }

    #[test]
    fn compile_all_succeeds_for_minimal_wasm() {
        let engine = NeothEngine::new().expect("engine");
        let report = DiscoveryReport {
            loaded: vec![discovered("alpha", minimal_wasm())],
            rejected: vec![],
        };
        let outcomes = compile_all_discovered(&engine, &report);
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].is_ok());
        assert_eq!(outcomes[0].plugin_id(), "alpha");
    }

    #[test]
    fn compile_all_binds_manifest_execution_limits() {
        let engine = NeothEngine::new().expect("engine");
        let mut plugin = discovered("bounded", minimal_wasm());
        plugin.manifest.fuel_budget_override = Some(42_000);
        plugin.manifest.memory_limit_bytes = Some(8 * 1024 * 1024);
        let report = DiscoveryReport {
            loaded: vec![plugin],
            rejected: vec![],
        };

        let outcomes = compile_all_discovered(&engine, &report);
        let CompileOutcome::Compiled {
            execution_limits, ..
        } = &outcomes[0]
        else {
            panic!("validated plugin must compile");
        };
        assert_eq!(execution_limits.fuel_budget, 42_000);
        assert_eq!(execution_limits.memory_limit_bytes, 8 * 1024 * 1024);
    }

    #[test]
    fn compile_all_reports_broken_bytes_as_failed() {
        let engine = NeothEngine::new().expect("engine");
        let report = DiscoveryReport {
            loaded: vec![discovered("broken", vec![0xff, 0xff, 0xff, 0xff])],
            rejected: vec![],
        };
        let outcomes = compile_all_discovered(&engine, &report);
        assert_eq!(outcomes.len(), 1);
        assert!(!outcomes[0].is_ok());
        if let CompileOutcome::Failed { plugin_id, error } = &outcomes[0] {
            assert_eq!(plugin_id, "broken");
            assert!(
                !error.is_empty(),
                "Failed must carry an operator-readable error"
            );
        } else {
            panic!("expected Failed variant");
        }
    }

    #[test]
    fn compile_all_preserves_input_order() {
        // The CLI relies on a stable order so `neoth plugins list`
        // doesn't reshuffle between calls. Discovery itself is
        // already sorted; we just promise to mirror it.
        let engine = NeothEngine::new().expect("engine");
        let report = DiscoveryReport {
            loaded: vec![
                discovered("first", minimal_wasm()),
                discovered("second", minimal_wasm()),
                discovered("third", minimal_wasm()),
            ],
            rejected: vec![],
        };
        let outcomes = compile_all_discovered(&engine, &report);
        assert_eq!(outcomes[0].plugin_id(), "first");
        assert_eq!(outcomes[1].plugin_id(), "second");
        assert_eq!(outcomes[2].plugin_id(), "third");
    }

    #[test]
    fn skip_due_to_compile_carries_both_id_and_reason() {
        let o = skip_due_to_compile("broken", "non-wasm bytes");
        assert_eq!(o.plugin_id, "broken");
        assert_eq!(o.stage, InvocationStage::SkippedDueToCompileFailure);
        assert_eq!(o.error.as_deref(), Some("non-wasm bytes"));
    }

    #[test]
    fn invocation_outcome_from_compile_failure_promotes_only_failed() {
        let failed = CompileOutcome::Failed {
            plugin_id: "x".into(),
            error: "boom".into(),
        };
        let promoted = invocation_outcome_from_compile_failure(&failed).unwrap();
        assert_eq!(promoted.stage, InvocationStage::SkippedDueToCompileFailure);
        assert_eq!(promoted.error.as_deref(), Some("boom"));

        let ok = CompileOutcome::Compiled {
            plugin_id: "y".into(),
            module: Arc::new(
                NeothEngine::new()
                    .unwrap()
                    .compile_from_bytes(&minimal_wasm())
                    .unwrap(),
            ),
            execution_limits: PluginExecutionLimits::default(),
        };
        assert!(invocation_outcome_from_compile_failure(&ok).is_none());
    }

    #[test]
    fn invoke_plugin_reports_missing_neoth_run_export() {
        // A minimal WASM module has no exports. invoke_plugin must
        // surface the missing-export path as InvocationStage::ExportLookup
        // with a non-empty error so the operator gets a clear "plugin
        // doesn't follow the ABI" diagnostic.
        let engine = NeothEngine::new().expect("engine");
        let module = engine
            .compile_from_bytes(&minimal_wasm())
            .expect("minimal wasm must compile");
        let linker = crate::wasm_plugin::hostcalls::build_linker(engine.raw())
            .expect("hostcalls linker must build");
        let outcome = invoke_plugin(
            &engine,
            &module,
            &linker,
            "test-no-export",
            HostcallPermission::None,
            PluginExecutionLimits::default(),
            None,
            None,
        );

        assert_eq!(outcome.plugin_id, "test-no-export");
        assert_eq!(outcome.stage, InvocationStage::ExportLookup);
        let err = outcome.error.expect("missing-export must carry error");
        assert!(
            err.contains("neoth_run"),
            "error must name the missing export: {err}"
        );
    }

    #[test]
    fn versioned_guest_abi_roundtrip_reaches_run() {
        let engine = NeothEngine::new().expect("engine");
        let module = engine
            .compile_from_bytes(&echo_wasm())
            .expect("versioned guest must compile");
        let linker = crate::wasm_plugin::hostcalls::build_linker(engine.raw())
            .expect("hostcalls linker must build");
        let outcome = invoke_plugin(
            &engine,
            &module,
            &linker,
            "abi-v1",
            HostcallPermission::None,
            PluginExecutionLimits::default(),
            None,
            None,
        );
        assert_eq!(outcome.stage, InvocationStage::Run);
        assert!(
            outcome.error.is_none(),
            "roundtrip failed: {:?}",
            outcome.error
        );
    }

    #[test]
    fn invoke_plugin_rejects_missing_guest_abi_version() {
        let engine = NeothEngine::new().expect("engine");
        let module = engine
            .compile_from_bytes(&legacy_run_only_wasm())
            .expect("legacy guest must still compile");
        let linker = crate::wasm_plugin::hostcalls::build_linker(engine.raw())
            .expect("hostcalls linker must build");
        let outcome = invoke_plugin(
            &engine,
            &module,
            &linker,
            "legacy-abi",
            HostcallPermission::None,
            PluginExecutionLimits::default(),
            None,
            None,
        );
        assert_eq!(outcome.stage, InvocationStage::AbiVersion);
        let error = outcome
            .error
            .expect("missing ABI export must refuse invoke");
        assert!(
            error.contains(ABI_VERSION_EXPORT),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn invoke_plugin_rejects_guest_abi_version_mismatch() {
        let engine = NeothEngine::new().expect("engine");
        let module = engine
            .compile_from_bytes(&echo_wasm_with_version(ABI_VERSION + 1))
            .expect("mismatched guest must still compile");
        let linker = crate::wasm_plugin::hostcalls::build_linker(engine.raw())
            .expect("hostcalls linker must build");
        let outcome = invoke_plugin(
            &engine,
            &module,
            &linker,
            "future-abi",
            HostcallPermission::None,
            PluginExecutionLimits::default(),
            None,
            None,
        );
        assert_eq!(outcome.stage, InvocationStage::AbiVersion);
        let error = outcome.error.expect("mismatch must explain refusal");
        assert!(
            error.contains("version mismatch"),
            "unexpected error: {error}"
        );
        assert!(error.contains("plugin=2"), "unexpected error: {error}");
        assert!(error.contains("host=1"), "unexpected error: {error}");
    }

    #[test]
    fn invoke_plugin_treats_nonzero_guest_status_as_failure() {
        let engine = NeothEngine::new().expect("engine");
        let module = engine
            .compile_from_bytes(&calling_wasm(vec![0x00, 0x41, 0x01, 0x0b]))
            .expect("status guest must compile");
        let linker = crate::wasm_plugin::hostcalls::build_linker(engine.raw())
            .expect("hostcalls linker must build");
        let outcome = invoke_plugin(
            &engine,
            &module,
            &linker,
            "failed-entry",
            HostcallPermission::None,
            PluginExecutionLimits::default(),
            None,
            None,
        );
        assert_eq!(outcome.stage, InvocationStage::Run);
        assert_eq!(
            outcome.error.as_deref(),
            Some("neoth_run returned non-zero status 1")
        );
    }

    #[test]
    fn invoke_plugin_applies_manifest_fuel_budget() {
        let engine = NeothEngine::new().expect("engine");
        // neoth_run returns the remaining fuel as i32. A correctly wired
        // 100-unit budget must never look like the one-million-unit default.
        let module = engine
            .compile_from_bytes(&calling_wasm(vec![0x00, 0x10, 0x01, 0xa7, 0x0b]))
            .expect("fuel probe guest must compile");
        let linker = crate::wasm_plugin::hostcalls::build_linker(engine.raw())
            .expect("hostcalls linker must build");
        let outcome = invoke_plugin(
            &engine,
            &module,
            &linker,
            "fuel-probe",
            HostcallPermission::None,
            PluginExecutionLimits {
                fuel_budget: 100,
                memory_limit_bytes: DEFAULT_MEMORY_LIMIT_BYTES,
            },
            None,
            None,
        );
        assert_eq!(outcome.stage, InvocationStage::Run);
        let error = outcome.error.expect("remaining fuel is a non-zero status");
        let remaining: i32 = error
            .rsplit_once(' ')
            .expect("status suffix")
            .1
            .parse()
            .expect("numeric status");
        assert!(
            (1..=100).contains(&remaining),
            "custom fuel was not applied: {error}"
        );
    }

    #[test]
    fn invoke_plugin_applies_manifest_memory_limit() {
        let engine = NeothEngine::new().expect("engine");
        // The module starts with one 64-KiB page and returns memory.grow(1).
        // A one-page cap makes the grow fail with Wasm's -1 sentinel.
        let module = engine
            .compile_from_bytes(&calling_wasm(vec![0x00, 0x41, 0x01, 0x40, 0x00, 0x0b]))
            .expect("memory probe guest must compile");
        let linker = crate::wasm_plugin::hostcalls::build_linker(engine.raw())
            .expect("hostcalls linker must build");
        let outcome = invoke_plugin(
            &engine,
            &module,
            &linker,
            "memory-probe",
            HostcallPermission::None,
            PluginExecutionLimits {
                fuel_budget: DEFAULT_FUEL_BUDGET,
                memory_limit_bytes: 64 * 1024,
            },
            None,
            None,
        );
        assert_eq!(outcome.stage, InvocationStage::Run);
        assert_eq!(
            outcome.error.as_deref(),
            Some("neoth_run returned non-zero status -1")
        );
    }

    #[test]
    fn compiled_invoker_is_empty_when_no_compiled_outcomes() {
        let engine = Arc::new(NeothEngine::new().expect("engine"));
        let linker =
            Arc::new(crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker"));
        let inv = CompiledPluginInvoker::from_compile_outcomes(engine, &[], linker, HashMap::new())
            .expect("empty invoker");
        assert!(inv.is_empty());
        assert_eq!(inv.len(), 0);
    }

    #[test]
    fn compiled_invoker_registers_compiled_outcomes() {
        // Two compile passes, only one succeeds. The invoker holds
        // exactly the Compiled module — Failed entries silently drop.
        let engine = Arc::new(NeothEngine::new().expect("engine"));
        let linker =
            Arc::new(crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker"));
        let module = engine
            .compile_from_bytes(&minimal_wasm())
            .expect("minimal must compile");
        let outcomes = vec![
            CompileOutcome::Compiled {
                plugin_id: "alpha".into(),
                module: Arc::new(module),
                execution_limits: PluginExecutionLimits::default(),
            },
            CompileOutcome::Failed {
                plugin_id: "broken".into(),
                error: "non-wasm bytes".into(),
            },
        ];
        let inv = CompiledPluginInvoker::from_compile_outcomes(
            engine,
            &outcomes,
            linker,
            approvals_for(&["alpha"], RequestedPermission::None),
        )
        .expect("approved invoker");
        assert!(!inv.is_empty());
        assert_eq!(inv.len(), 1);
    }

    #[test]
    fn compiled_invoker_refuses_compiled_module_without_approval_binding() {
        let engine = Arc::new(NeothEngine::new().expect("engine"));
        let linker =
            Arc::new(crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker"));
        let module = engine
            .compile_from_bytes(&echo_wasm())
            .expect("guest must compile");
        let outcomes = vec![CompileOutcome::Compiled {
            plugin_id: "unapproved".into(),
            module: Arc::new(module),
            execution_limits: PluginExecutionLimits::default(),
        }];
        let error = match CompiledPluginInvoker::from_compile_outcomes(
            engine,
            &outcomes,
            linker,
            HashMap::new(),
        ) {
            Ok(_) => panic!("unapproved code entered the invoker"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("no exact operator approval"));
    }

    #[test]
    fn compiled_invoker_errors_on_unknown_plugin_id() {
        // The hook engine's dispatcher catches this Err + logs a
        // warn + continues. Pin that the error names both the
        // unknown id and the registered set so the operator can
        // diagnose a typo in `~/.neoth/hooks.toml`.
        use crate::hooks::dispatcher::PluginInvoker;
        let engine = Arc::new(NeothEngine::new().expect("engine"));
        let linker =
            Arc::new(crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker"));
        let module = engine
            .compile_from_bytes(&minimal_wasm())
            .expect("minimal must compile");
        let outcomes = vec![CompileOutcome::Compiled {
            plugin_id: "alpha".into(),
            module: Arc::new(module),
            execution_limits: PluginExecutionLimits::default(),
        }];
        let inv = CompiledPluginInvoker::from_compile_outcomes(
            engine,
            &outcomes,
            linker,
            approvals_for(&["alpha"], RequestedPermission::None),
        )
        .expect("approved invoker");
        let err = inv.invoke("ghost").unwrap_err().to_string();
        assert!(err.contains("ghost"), "error must name unknown id: {err}");
        assert!(
            err.contains("alpha"),
            "error must list registered ids: {err}"
        );
    }

    #[test]
    fn compiled_invoker_propagates_export_lookup_failure() {
        // Minimal-WASM has no `neoth_run` export — invoke_plugin
        // surfaces ExportLookup. The PluginInvoker trait impl
        // promotes that to Err so the hook dispatcher records a
        // warn (+ continues without blocking the operator turn).
        use crate::hooks::dispatcher::PluginInvoker;
        let engine = Arc::new(NeothEngine::new().expect("engine"));
        let linker =
            Arc::new(crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker"));
        let module = engine
            .compile_from_bytes(&minimal_wasm())
            .expect("minimal must compile");
        let outcomes = vec![CompileOutcome::Compiled {
            plugin_id: "alpha".into(),
            module: Arc::new(module),
            execution_limits: PluginExecutionLimits::default(),
        }];
        let inv = CompiledPluginInvoker::from_compile_outcomes(
            engine,
            &outcomes,
            linker,
            approvals_for(&["alpha"], RequestedPermission::None),
        )
        .expect("approved invoker");
        let err = inv.invoke("alpha").unwrap_err().to_string();
        assert!(
            err.contains("neoth_run"),
            "error names missing export: {err}"
        );
    }

    #[test]
    fn compiled_invoker_refuses_revoked_plugin_after_config_swap() {
        // Reload gap regression test: a plugin added to
        // `plugins.wasm.revoked_ids` via `neoth reload` must be refused
        // by the very next invoke — WITHOUT rebuilding the invoker during the
        // current daemon lifetime.
        use crate::config::reload::{ReloadController, ReloadResult};
        use crate::hooks::dispatcher::PluginInvoker;

        let dir = tempfile::tempdir().unwrap();
        let yaml_path = dir.path().join("freedom.yaml");
        let approval = crate::wasm_plugin::discovery::PluginApproval {
            approved_permission: crate::wasm_plugin::manifest::RequestedPermission::None,
            manifest_sha256: "manifest-at-bootstrap".to_string(),
            wasm_sha256: "wasm-at-bootstrap".to_string(),
        };
        let mut initial = crate::config::FreedomConfig::default();
        initial.plugins.wasm.activations.insert(
            "alpha".to_string(),
            crate::wasm_plugin::discovery::PluginActivationRecord {
                state: crate::wasm_plugin::discovery::PluginActivation::Active,
                approval: Some(approval.clone()),
            },
        );
        let ctrl = Arc::new(ReloadController::new(initial.clone(), yaml_path.clone()));

        let engine = Arc::new(NeothEngine::new().expect("engine"));
        let linker =
            Arc::new(crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker"));
        let module = engine
            .compile_from_bytes(&minimal_wasm())
            .expect("minimal must compile");
        let outcomes = vec![CompileOutcome::Compiled {
            plugin_id: "alpha".into(),
            module: Arc::new(module),
            execution_limits: PluginExecutionLimits::default(),
        }];
        let mut approvals = HashMap::new();
        approvals.insert("alpha".to_string(), approval);
        let inv =
            CompiledPluginInvoker::from_compile_outcomes(engine, &outcomes, linker, approvals)
                .expect("approved invoker")
                .with_integrity_policy(&initial.plugins.wasm)
                .with_reload_controller(ctrl.clone());

        // Pre-swap: the gate passes (revoked_ids empty) and the invoke
        // proceeds to export lookup — proving the check is non-blocking
        // for un-revoked plugins.
        let err = inv.invoke("alpha").unwrap_err().to_string();
        assert!(
            err.contains("neoth_run"),
            "pre-swap invoke must reach export lookup, not the revocation gate: {err}"
        );

        // Operator revokes "alpha" + runs `neoth reload`.
        let mut revoked_cfg = initial;
        revoked_cfg.plugins.wasm.revoked_ids = vec!["alpha".into()];
        std::fs::write(&yaml_path, serde_yaml::to_string(&revoked_cfg).unwrap()).unwrap();
        match ctrl.try_reload().expect("reload must succeed") {
            ReloadResult::Reloaded { .. } => {}
            other => panic!("expected Reloaded, got {other:?}"),
        }

        // Post-swap: the SAME invoker instance refuses the invoke.
        let err = inv.invoke("alpha").unwrap_err().to_string();
        assert!(
            err.contains("revoked"),
            "post-swap invoke must hit the live revocation gate: {err}"
        );
    }

    #[test]
    fn compiled_invoker_refuses_changed_approval_after_config_swap() {
        use crate::config::reload::{ReloadController, ReloadResult};
        use crate::hooks::dispatcher::PluginInvoker;

        let dir = tempfile::tempdir().unwrap();
        let yaml_path = dir.path().join("freedom.yaml");
        let approval = crate::wasm_plugin::discovery::PluginApproval {
            approved_permission: crate::wasm_plugin::manifest::RequestedPermission::None,
            manifest_sha256: "manifest-at-bootstrap".to_string(),
            wasm_sha256: "wasm-at-bootstrap".to_string(),
        };
        let mut initial = crate::config::FreedomConfig::default();
        initial.plugins.wasm.activations.insert(
            "alpha".to_string(),
            crate::wasm_plugin::discovery::PluginActivationRecord {
                state: crate::wasm_plugin::discovery::PluginActivation::Active,
                approval: Some(approval.clone()),
            },
        );
        let ctrl = Arc::new(ReloadController::new(initial.clone(), yaml_path.clone()));

        let engine = Arc::new(NeothEngine::new().expect("engine"));
        let linker =
            Arc::new(crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker"));
        let module = engine
            .compile_from_bytes(&minimal_wasm())
            .expect("minimal must compile");
        let outcomes = vec![CompileOutcome::Compiled {
            plugin_id: "alpha".into(),
            module: Arc::new(module),
            execution_limits: PluginExecutionLimits::default(),
        }];
        let mut approvals = HashMap::new();
        approvals.insert("alpha".to_string(), approval);
        let inv =
            CompiledPluginInvoker::from_compile_outcomes(engine, &outcomes, linker, approvals)
                .expect("approved invoker")
                .with_integrity_policy(&initial.plugins.wasm)
                .with_reload_controller(ctrl.clone());

        let err = inv.invoke("alpha").unwrap_err().to_string();
        assert!(
            err.contains("neoth_run"),
            "unchanged approval must reach the module: {err}"
        );

        let mut escalated = initial;
        escalated
            .plugins
            .wasm
            .activations
            .get_mut("alpha")
            .unwrap()
            .approval
            .as_mut()
            .unwrap()
            .approved_permission = crate::wasm_plugin::manifest::RequestedPermission::Write;
        std::fs::write(&yaml_path, serde_yaml::to_string(&escalated).unwrap()).unwrap();
        assert!(matches!(
            ctrl.try_reload().expect("reload must succeed"),
            ReloadResult::Reloaded { .. }
        ));

        let err = inv.invoke("alpha").unwrap_err().to_string();
        assert!(
            err.contains("approval changed"),
            "post-swap invoke must reject the changed approval: {err}"
        );
    }

    #[test]
    fn compiled_invoker_refuses_live_plugin_host_disable() {
        use crate::config::reload::ReloadResult;
        use crate::hooks::dispatcher::PluginInvoker;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("freedom.yaml");
        let initial = active_plugin_config();
        let (invoker, controller) = live_config_invoker(&initial, config_path.clone());

        let mut disabled = initial;
        disabled.plugins.wasm.enabled = false;
        std::fs::write(&config_path, serde_yaml::to_string(&disabled).unwrap()).unwrap();
        assert!(matches!(
            controller.try_reload().expect("reload must succeed"),
            ReloadResult::Reloaded { .. }
        ));

        let error = invoker.invoke("alpha").unwrap_err().to_string();
        assert!(
            error.contains("host is disabled"),
            "live host disable must fail before module invocation: {error}"
        );
    }

    #[test]
    fn compiled_invoker_refuses_integrity_policy_tightening_until_restart() {
        use crate::config::reload::ReloadResult;
        use crate::hooks::dispatcher::PluginInvoker;

        let cases: [(&str, fn(&mut crate::config::WasmPluginsConfig)); 3] = [
            ("pin", |config| {
                config
                    .pinned_hashes
                    .insert("alpha".to_string(), "0".repeat(64));
            }),
            ("require_all_pinned", |config| {
                config.require_all_pinned = true;
            }),
            ("signature", |config| {
                config.author_pubkey =
                    Some("RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3".to_string());
                config.require_signature = true;
            }),
        ];

        for (case, tighten) in cases {
            let dir = tempfile::tempdir().unwrap();
            let config_path = dir.path().join("freedom.yaml");
            let initial = active_plugin_config();
            let (invoker, controller) = live_config_invoker(&initial, config_path.clone());
            let mut tightened = initial;
            tighten(&mut tightened.plugins.wasm);
            std::fs::write(&config_path, serde_yaml::to_string(&tightened).unwrap()).unwrap();
            assert!(matches!(
                controller.try_reload().expect("reload must succeed"),
                ReloadResult::Reloaded { .. }
            ));

            let error = invoker.invoke("alpha").unwrap_err().to_string();
            assert!(
                error.contains("integrity policy changed"),
                "{case} tightening must fail before module invocation: {error}"
            );
        }
    }

    #[test]
    fn invocation_outcome_serialises_stage_as_snake_case() {
        // The JSON output of `neoth plugins list --output json`
        // exposes the stage to operators. Snake-case is the wire-form
        // contract; pin it.
        let o = InvocationOutcome {
            plugin_id: "x".into(),
            stage: InvocationStage::ExportLookup,
            error: None,
        };
        let json = serde_json::to_string(&o).unwrap();
        assert!(json.contains("\"stage\":\"export_lookup\""));
    }

    // ── V10-04 Workstream G: echo + recall_summariser round-trip tests ───────

    #[test]
    fn echo_wasm_bytes_compile_via_neoth_engine() {
        // The echo_wasm() helper produces bytes that cranelift can
        // compile without error. This pins that the hand-crafted binary
        // encoding is well-formed WASM.
        let engine = NeothEngine::new().expect("engine");
        let result = engine.compile_from_bytes(&echo_wasm());
        assert!(
            result.is_ok(),
            "echo_wasm must compile cleanly: {:?}",
            result.err()
        );
    }

    #[test]
    fn echo_plugin_round_trip_reaches_run_stage() {
        // Full path: compile → linker → instantiate → call neoth_run.
        // The echo plugin imports all four ABI v1 hostcalls and exports
        // neoth_run. The outcome must be InvocationStage::Run without
        // any error (return code 0 is not an error by the ABI contract).
        let engine = NeothEngine::new().expect("engine");
        let module = engine
            .compile_from_bytes(&echo_wasm())
            .expect("echo_wasm must compile");
        let linker =
            crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker must build");
        let outcome = invoke_plugin(
            &engine,
            &module,
            &linker,
            "echo",
            HostcallPermission::None,
            PluginExecutionLimits::default(),
            None,
            None,
        );

        assert_eq!(outcome.plugin_id, "echo");
        assert_eq!(
            outcome.stage,
            InvocationStage::Run,
            "echo plugin must reach Run stage, got {:?}: {:?}",
            outcome.stage,
            outcome.error
        );
        assert!(
            outcome.error.is_none(),
            "echo plugin must complete without error: {:?}",
            outcome.error
        );
    }

    #[test]
    fn recall_summariser_plugin_round_trip_reaches_run_stage() {
        // Full path for the recall_summariser example plugin.
        // No recall_db is attached → neoth.recall_top returns 0;
        // no WAL writer is attached → neoth.emit_event falls back to
        // tracing-log. Both are acceptable per the hostcall contracts.
        let engine = NeothEngine::new().expect("engine");
        let module = engine
            .compile_from_bytes(&recall_summariser_wasm())
            .expect("recall_summariser_wasm must compile");
        let linker =
            crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker must build");
        let outcome = invoke_plugin(
            &engine,
            &module,
            &linker,
            "recall-summariser",
            HostcallPermission::None,
            PluginExecutionLimits::default(),
            None,
            None,
        );

        assert_eq!(outcome.plugin_id, "recall-summariser");
        assert_eq!(
            outcome.stage,
            InvocationStage::Run,
            "recall_summariser plugin must reach Run stage: {:?}: {:?}",
            outcome.stage,
            outcome.error
        );
        assert!(
            outcome.error.is_none(),
            "recall_summariser must complete without trap: {:?}",
            outcome.error
        );
    }

    #[test]
    fn compiled_invoker_invokes_echo_plugin_successfully() {
        // End-to-end CompiledPluginInvoker path with a real neoth_run
        // export. Verifies that PluginInvoker::invoke returns Ok(())
        // for a well-formed plugin.
        use crate::hooks::dispatcher::PluginInvoker;
        let engine = Arc::new(NeothEngine::new().expect("engine"));
        let linker =
            Arc::new(crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker"));
        let module = engine
            .compile_from_bytes(&echo_wasm())
            .expect("echo_wasm must compile");
        let outcomes = vec![CompileOutcome::Compiled {
            plugin_id: "echo".into(),
            module: Arc::new(module),
            execution_limits: PluginExecutionLimits::default(),
        }];
        let inv = CompiledPluginInvoker::from_compile_outcomes(
            engine,
            &outcomes,
            linker,
            approvals_for(&["echo"], RequestedPermission::None),
        )
        .expect("approved invoker");
        let result = inv.invoke("echo");
        assert!(
            result.is_ok(),
            "echo plugin must invoke without error via PluginInvoker: {:?}",
            result.err()
        );
    }

    #[test]
    fn compiled_invoker_invokes_recall_summariser_successfully() {
        // End-to-end path for recall_summariser plugin via the invoker.
        use crate::hooks::dispatcher::PluginInvoker;
        let engine = Arc::new(NeothEngine::new().expect("engine"));
        let linker =
            Arc::new(crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker"));
        let module = engine
            .compile_from_bytes(&recall_summariser_wasm())
            .expect("recall_summariser_wasm must compile");
        let outcomes = vec![CompileOutcome::Compiled {
            plugin_id: "recall-summariser".into(),
            module: Arc::new(module),
            execution_limits: PluginExecutionLimits::default(),
        }];
        let inv = CompiledPluginInvoker::from_compile_outcomes(
            engine,
            &outcomes,
            linker,
            approvals_for(&["recall-summariser"], RequestedPermission::None),
        )
        .expect("approved invoker");
        let result = inv.invoke("recall-summariser");
        assert!(
            result.is_ok(),
            "recall_summariser must invoke via PluginInvoker: {:?}",
            result.err()
        );
    }

    #[test]
    fn echo_wasm_export_is_discoverable_as_typed_func() {
        // Confirm the export section encoding is correct by looking up
        // neoth_run directly on the instance without going through
        // invoke_plugin. Catches a mis-encoded export name or type.
        let engine = NeothEngine::new().expect("engine");
        let module = engine
            .compile_from_bytes(&echo_wasm())
            .expect("echo_wasm must compile");
        let linker =
            crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker must build");
        let state = crate::wasm_plugin::engine::PluginStoreState::new("echo-export-check");
        let mut store = engine.new_store(state).expect("store must seed");
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("echo_wasm must instantiate with neoth linker");
        let typed = instance.get_typed_func::<(), i32>(&mut store, "neoth_run");
        assert!(
            typed.is_ok(),
            "neoth_run must be a discoverable `() -> i32` export on echo_wasm"
        );
    }

    #[test]
    fn recall_summariser_wasm_has_memory_export() {
        // neoth.log and neoth.emit_event both read the plugin's linear
        // memory via `caller.get_export("memory")`. Pin that the
        // recall_summariser example wasm exports it.
        let engine = NeothEngine::new().expect("engine");
        let module = engine
            .compile_from_bytes(&recall_summariser_wasm())
            .expect("recall_summariser_wasm must compile");
        let linker =
            crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker must build");
        let state = crate::wasm_plugin::engine::PluginStoreState::new("recall-mem-check");
        let mut store = engine.new_store(state).expect("store must seed");
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("recall_summariser_wasm must instantiate");
        let mem = instance.get_export(&mut store, "memory");
        assert!(
            mem.is_some(),
            "recall_summariser_wasm must export 'memory' for hostcall pointer reads"
        );
    }

    #[test]
    fn echo_plugin_with_recall_db_invokes_cleanly() {
        // Attach a real in-memory views.db so neoth.recall_top follows
        // the SQL path rather than the "no db" fast-return. The echo
        // plugin doesn't call recall_top itself, but attaching a db
        // exercises the Store wiring path used by recall_summariser.
        use crate::wasm_plugin::engine::PluginStoreState;
        let engine = NeothEngine::new().expect("engine");
        let module = engine
            .compile_from_bytes(&echo_wasm())
            .expect("echo_wasm compile");
        let linker =
            crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker build");

        // Synthetic idx_episode table — same fixture shape as hostcalls tests.
        let conn = rusqlite::Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE idx_episode (
                event_id   INTEGER PRIMARY KEY,
                event_type INTEGER NOT NULL,
                ts_ns      INTEGER NOT NULL,
                text       TEXT NOT NULL,
                text_hash  TEXT NOT NULL,
                importance REAL NOT NULL DEFAULT 0.5,
                last_access_ts INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX idx_episode_hash ON idx_episode (text_hash);",
        )
        .expect("fixture schema");

        let db = std::sync::Arc::new(std::sync::Mutex::new(conn));
        let state = PluginStoreState::new("echo-with-db").with_recall_db(db);
        let mut store = engine.new_store(state).expect("store with db");
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("instantiate echo with recall_db");
        let func = instance
            .get_typed_func::<(), i32>(&mut store, "neoth_run")
            .expect("neoth_run export");
        let rc = func.call(&mut store, ()).expect("neoth_run must not trap");
        assert_eq!(rc, 0, "echo plugin must return 0");
    }

    #[test]
    fn recall_summariser_plugin_with_populated_db_invokes_cleanly() {
        // Full recall_summariser round-trip with a populated idx_episode.
        // The plugin calls neoth.recall_top(PROBE_HASH) — with matching
        // rows in the DB the hostcall returns > 0; without, returns 0.
        // Both branches reach neoth_run return 0 cleanly.
        use crate::wasm_plugin::engine::PluginStoreState;
        let engine = NeothEngine::new().expect("engine");
        let module = engine
            .compile_from_bytes(&recall_summariser_wasm())
            .expect("recall_summariser compile");
        let linker =
            crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker build");

        let conn = rusqlite::Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE idx_episode (
                event_id   INTEGER PRIMARY KEY,
                event_type INTEGER NOT NULL,
                ts_ns      INTEGER NOT NULL,
                text       TEXT NOT NULL,
                text_hash  TEXT NOT NULL,
                importance REAL NOT NULL DEFAULT 0.5,
                last_access_ts INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX idx_episode_hash ON idx_episode (text_hash);",
        )
        .expect("fixture schema");
        // Insert a row matching the plugin's PROBE_HASH so the "seen" branch fires.
        let probe: u64 = 0x5e4d_3c2b_1a09_8765;
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (1, 1, 1700000000000000000, 'probe', ?1)",
            rusqlite::params![format!("{:016x}", probe)],
        )
        .expect("insert probe row");

        let db = std::sync::Arc::new(std::sync::Mutex::new(conn));
        let state = PluginStoreState::new("recall-summariser-with-db").with_recall_db(db);
        let mut store = engine.new_store(state).expect("store with db");
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("instantiate recall_summariser with db");
        let func = instance
            .get_typed_func::<(), i32>(&mut store, "neoth_run")
            .expect("neoth_run export");
        let rc = func
            .call(&mut store, ())
            .expect("recall_summariser must not trap");
        assert_eq!(rc, 0, "recall_summariser must return 0");
    }
}
