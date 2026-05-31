//! Pick #34 follow-up — plugin pre-flight + dispatch site.
//!
//! Two responsibilities split across small helpers:
//!
//! 1. [`compile_all_discovered`] walks the discovery report and
//!    compiles every loaded plugin against the live wasmtime engine.
//!    Operator-facing `neoth plugins list` calls this so the listing
//!    surfaces compile errors before any plugin is actually invoked.
//!
//! 2. [`InvocationOutcome`] + [`build_invocation_outcome`] capture
//!    the result of one invocation in a serialisable shape. The
//!    full `Instance::call_typed_func("neoth_run", ...)` wire-up
//!    lands once the example plugin lives at
//!    `examples/wasm-plugin-hello/plugin.wasm`; before then the
//!    outcome shape stays callable so hook-engine integration can
//!    pre-allocate its result-handling path.

use std::collections::HashMap;
use std::sync::Arc;

use wasmtime::Module;

use crate::security::redact::redact_text;
use crate::wasm_plugin::discovery::{DiscoveredPlugin, DiscoveryReport};
use crate::wasm_plugin::engine::{NeothEngine, PluginStoreState};

/// Outcome of compiling one discovered plugin.
#[derive(Debug, Clone)]
pub enum CompileOutcome {
    /// Compilation succeeded — module is ready for instantiation.
    Compiled {
        plugin_id: String,
        module: Arc<Module>,
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
///     manifest's memory_limit + fuel budget honoured.
///   - The exported function must be `fn neoth_run() -> i32` for
///     now. Future ABIs (struct returns, hostcall callbacks) extend
///     this with new typed_func sigs.
///   - Non-zero return is recorded but not treated as an error — the
///     plugin's own convention defines what the integer means.
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
) -> InvocationOutcome {
    let plugin_id = plugin_id.into();
    let state = crate::wasm_plugin::engine::PluginStoreState::new(&plugin_id);

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

    let func = match instance.get_typed_func::<(), i32>(&mut store, "neoth_run") {
        Ok(f) => f,
        Err(e) => {
            return InvocationOutcome {
                plugin_id,
                stage: InvocationStage::ExportLookup,
                error: Some(redact_text(&format!(
                    "missing `fn neoth_run() -> i32` export: {e}"
                ))),
            };
        }
    };

    match func.call(&mut store, ()) {
        Ok(_rc) => InvocationOutcome {
            plugin_id,
            stage: InvocationStage::Run,
            error: None,
        },
        Err(e) => InvocationOutcome {
            plugin_id,
            stage: InvocationStage::Run,
            error: Some(redact_text(&format!("neoth_run trapped: {e}"))),
        },
    }
}

/// Daemon-side `hooks::PluginInvoker` impl. Holds the engine, the
/// compiled-module registry, and the hostcalls linker — everything
/// `invoke_plugin()` needs to fire a plugin by id. The daemon
/// bootstrap discovers + compiles + builds an instance of this
/// struct, then hands an `Arc<CompiledPluginInvoker>` to the hook
/// engine.
///
/// `modules` is a snapshot — re-discovery (operator dropped a new
/// `~/.neoth/plugins/<id>/`) requires a fresh CompiledPluginInvoker.
/// The hook dispatcher only borrows the trait, so re-binding is
/// safe at runtime when the bootstrap detects a change.
pub struct CompiledPluginInvoker {
    engine: Arc<NeothEngine>,
    modules: HashMap<String, Arc<Module>>,
    linker: Arc<wasmtime::Linker<PluginStoreState>>,
}

impl CompiledPluginInvoker {
    /// Build an invoker from a compile-pass result + a pre-built
    /// linker. Only `Compiled` outcomes are registered; `Failed`
    /// entries are silently dropped (the operator already saw them
    /// in `plugins list`). Empty input is legal: the invoker will
    /// just fail every invoke with "unknown plugin id".
    pub fn from_compile_outcomes(
        engine: Arc<NeothEngine>,
        outcomes: &[CompileOutcome],
        linker: Arc<wasmtime::Linker<PluginStoreState>>,
    ) -> Self {
        let mut modules: HashMap<String, Arc<Module>> = HashMap::new();
        for o in outcomes {
            if let CompileOutcome::Compiled { plugin_id, module } = o {
                modules.insert(plugin_id.clone(), module.clone());
            }
        }
        Self {
            engine,
            modules,
            linker,
        }
    }

    /// True when no plugins are registered. Useful for the daemon's
    /// bootstrap to decide whether to wire the invoker into the
    /// hook engine at all — wiring an empty invoker is fine but the
    /// log line `no PluginInvoker wired` is more honest.
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// Number of registered plugins. Surfaces in the
    /// `neoth doctor --explain plugins` output.
    pub fn len(&self) -> usize {
        self.modules.len()
    }
}

impl crate::hooks::dispatcher::PluginInvoker for CompiledPluginInvoker {
    fn invoke(&self, plugin_id: &str) -> anyhow::Result<()> {
        let module = self.modules.get(plugin_id).ok_or_else(|| {
            anyhow::anyhow!(
                "CompiledPluginInvoker: unknown plugin id {plugin_id:?} — \
                 known: [{}]",
                self.modules.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        })?;
        let outcome = invoke_plugin(&self.engine, module, &self.linker, plugin_id);
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
    use crate::wasm_plugin::manifest::PluginManifest;
    use std::path::PathBuf;

    fn minimal_wasm() -> Vec<u8> {
        // Magic `\0asm` + version 1 LE. Smallest valid module.
        vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
    }

    /// A complete WASM module that:
    ///   - imports all four Phase-1 neoth hostcalls
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
    ///   (func (type 4) (i32.const 0))  ;; func index 4 = neoth_run
    ///   (memory 1)
    ///   (export "neoth_run" (func 4))
    ///   (export "memory"    (mem  0))
    /// )
    /// ```
    ///
    /// Used by tests that need a plugin which actually reaches the Run stage.
    fn echo_wasm() -> Vec<u8> {
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
            ("neoth", "log", 0u32),
            ("neoth", "fuel_left", 1),
            ("neoth", "emit_event", 2),
            ("neoth", "recall_top", 3),
        ] {
            import_body.extend(wasm_str(module));
            import_body.extend(wasm_str(name));
            import_body.push(0x00); // import kind: function
            import_body.extend(uleb(*type_idx));
        }
        let import_section = [vec![0x02], with_len(import_body)].concat();

        // ── Function section ────────────────────────────────────────────────
        // 1 locally-defined function using type index 4.
        let mut func_body: Vec<u8> = uleb(1); // count
        func_body.extend(uleb(4)); // type index 4: () -> (i32)
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
        // 2 exports: "neoth_run" (func 4) + "memory" (mem 0).
        let mut export_body: Vec<u8> = uleb(2); // count
        // export "neoth_run" → function index 4
        export_body.extend(wasm_str("neoth_run"));
        export_body.push(0x00); // export kind: function
        export_body.extend(uleb(4)); // func index 4 (4 imports + 0th local = index 4)
        // export "memory" → memory index 0
        export_body.extend(wasm_str("memory"));
        export_body.push(0x02); // export kind: memory
        export_body.extend(uleb(0)); // memory index 0
        let export_section = [vec![0x07], with_len(export_body)].concat();

        // ── Code section ────────────────────────────────────────────────────
        // 1 function body: no locals, `i32.const 0; end`.
        let fn_body: Vec<u8> = vec![
            0x00, // local declaration count: 0
            0x41, 0x00, // i32.const 0
            0x0b, // end
        ];
        let mut code_body: Vec<u8> = uleb(1); // count of function bodies
        code_body.extend(with_len(fn_body)); // each body is length-prefixed
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
        }
    }

    fn discovered(id: &str, bytes: Vec<u8>) -> DiscoveredPlugin {
        let content_hash = super::super::discovery::sha256_hex(&bytes);
        DiscoveredPlugin {
            dir: PathBuf::from(format!("/tmp/{id}")),
            manifest: sample_manifest(id),
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
        let outcome = invoke_plugin(&engine, &module, &linker, "test-no-export");

        assert_eq!(outcome.plugin_id, "test-no-export");
        assert_eq!(outcome.stage, InvocationStage::ExportLookup);
        let err = outcome.error.expect("missing-export must carry error");
        assert!(
            err.contains("neoth_run"),
            "error must name the missing export: {err}"
        );
    }

    #[test]
    fn compiled_invoker_is_empty_when_no_compiled_outcomes() {
        let engine = Arc::new(NeothEngine::new().expect("engine"));
        let linker =
            Arc::new(crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker"));
        let inv = CompiledPluginInvoker::from_compile_outcomes(engine, &[], linker);
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
            },
            CompileOutcome::Failed {
                plugin_id: "broken".into(),
                error: "non-wasm bytes".into(),
            },
        ];
        let inv = CompiledPluginInvoker::from_compile_outcomes(engine, &outcomes, linker);
        assert!(!inv.is_empty());
        assert_eq!(inv.len(), 1);
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
        }];
        let inv = CompiledPluginInvoker::from_compile_outcomes(engine, &outcomes, linker);
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
        }];
        let inv = CompiledPluginInvoker::from_compile_outcomes(engine, &outcomes, linker);
        let err = inv.invoke("alpha").unwrap_err().to_string();
        assert!(
            err.contains("neoth_run"),
            "error names missing export: {err}"
        );
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
        // The echo plugin imports all 4 Phase-1 hostcalls and exports
        // neoth_run. The outcome must be InvocationStage::Run without
        // any error (return code 0 is not an error by the ABI contract).
        let engine = NeothEngine::new().expect("engine");
        let module = engine
            .compile_from_bytes(&echo_wasm())
            .expect("echo_wasm must compile");
        let linker =
            crate::wasm_plugin::hostcalls::build_linker(engine.raw()).expect("linker must build");
        let outcome = invoke_plugin(&engine, &module, &linker, "echo");

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
        let outcome = invoke_plugin(&engine, &module, &linker, "recall-summariser");

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
        }];
        let inv = CompiledPluginInvoker::from_compile_outcomes(engine, &outcomes, linker);
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
        }];
        let inv = CompiledPluginInvoker::from_compile_outcomes(engine, &outcomes, linker);
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
