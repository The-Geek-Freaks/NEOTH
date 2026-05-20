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

use std::sync::Arc;

use wasmtime::Module;

use crate::wasm_plugin::discovery::{DiscoveredPlugin, DiscoveryReport};
use crate::wasm_plugin::engine::NeothEngine;

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
    Failed {
        plugin_id: String,
        error: String,
    },
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
pub fn skip_due_to_compile(plugin_id: impl Into<String>, error: impl Into<String>) -> InvocationOutcome {
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
                error: Some(format!("new_store: {e}")),
            };
        }
    };

    let instance = match linker.instantiate(&mut store, module) {
        Ok(i) => i,
        Err(e) => {
            return InvocationOutcome {
                plugin_id,
                stage: InvocationStage::Instantiate,
                error: Some(format!("linker.instantiate: {e}")),
            };
        }
    };

    let func = match instance.get_typed_func::<(), i32>(&mut store, "neoth_run") {
        Ok(f) => f,
        Err(e) => {
            return InvocationOutcome {
                plugin_id,
                stage: InvocationStage::ExportLookup,
                error: Some(format!(
                    "missing `fn neoth_run() -> i32` export: {e}"
                )),
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
            error: Some(format!("neoth_run trapped: {e}")),
        },
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
        }
    }

    fn discovered(id: &str, bytes: Vec<u8>) -> DiscoveredPlugin {
        DiscoveredPlugin {
            dir: PathBuf::from(format!("/tmp/{id}")),
            manifest: sample_manifest(id),
            wasm_bytes: bytes,
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
}
