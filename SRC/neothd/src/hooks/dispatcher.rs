//! Run hooks at a given stage — Phase 29 R-15 H-3.
//!
//! The dispatcher takes the loaded hook set, walks the subset that matches
//! the current stage, applies each in order, and returns a [`StageOutcome`]
//! that the caller folds into its own dispatch logic.

use std::sync::{Arc, OnceLock};

use anyhow::Result;
use regex::Regex;

use super::schema::{HookAction, HookDef};
use super::stages::HookStage;

/// Process-wide registered plugin invoker. The daemon's startup
/// bootstrap (cli::serve) builds a `CompiledPluginInvoker` from
/// discovered plugins + registers it once. Existing `run_stage`
/// call sites automatically pick it up — no per-call-site wiring.
static GLOBAL_INVOKER: OnceLock<Arc<dyn PluginInvoker>> = OnceLock::new();

/// Register the process-wide PluginInvoker. Called exactly once by
/// the daemon bootstrap after discovery + compile complete. Returns
/// the prior value's existence — if non-None, the daemon already
/// registered an invoker and the caller chose not to overwrite
/// (OnceLock semantics).
pub fn register_global_invoker(inv: Arc<dyn PluginInvoker>) -> bool {
    GLOBAL_INVOKER.set(inv).is_ok()
}

/// Read the current process-wide invoker. `None` before
/// register_global_invoker fires (early startup, slim daemon,
/// tests). Hook actions of kind `Plugin` degrade to Allow + warn in
/// that case.
pub fn current_global_invoker() -> Option<&'static Arc<dyn PluginInvoker>> {
    GLOBAL_INVOKER.get()
}

/// What the dispatcher decided after running every applicable hook.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StageOutcome {
    /// Pipeline continues. Body is the (possibly replaced) text.
    Continue { body: String, hits: Vec<String> },
    /// Pipeline stops. `reason` is the operator-visible explanation,
    /// `name` is the hook that blocked. Callers usually drop the turn.
    Block { name: String, reason: String },
}

/// Pick #34 follow-up (2026-05-20): operator-supplied callback the
/// hook dispatcher uses to invoke a discovered WASM plugin without
/// importing wasmtime. Concrete impl lives in `wasm_plugin::dispatch`
/// and is wired by the daemon's bootstrap; hook unit tests pass `None`
/// and the dispatcher degrades Plugin actions to Allow.
pub trait PluginInvoker: Send + Sync {
    /// Invoke the plugin by id. Errors propagate up so the dispatcher
    /// can record them; they do NOT block the stage (a misbehaving
    /// plugin should not stop the operator's turn).
    fn invoke(&self, plugin_id: &str) -> Result<()>;
}

/// Apply every hook for `stage` to `body` in declaration order.
///
/// Replace-actions update the body and the next hook sees the updated
/// text. The first Block wins — later hooks at the same stage do not run.
/// Regex compile errors on a single hook log + skip that hook but do not
/// abort the stage.
///
/// Picks up the daemon's globally-registered PluginInvoker
/// (`register_global_invoker`) automatically. Pre-registration calls
/// (early startup, slim daemon, tests) see `None` and Plugin actions
/// degrade to Allow.
pub fn run_stage(stage: HookStage, body: &str, hooks: &[HookDef]) -> Result<StageOutcome> {
    let invoker = current_global_invoker().map(|arc| arc.as_ref());
    run_stage_with_plugins(stage, body, hooks, invoker)
}

/// Extended form that accepts a plugin invoker. When a hook's action is
/// `Plugin { plugin_id }`, the dispatcher calls
/// `invoker.invoke(plugin_id)`; failure surfaces in tracing but does
/// not block the stage. When `invoker` is `None`, Plugin actions
/// degrade to Allow with a warn log so the slim-daemon path stays
/// usable.
pub fn run_stage_with_plugins(
    stage: HookStage,
    body: &str,
    hooks: &[HookDef],
    invoker: Option<&dyn PluginInvoker>,
) -> Result<StageOutcome> {
    run_stage_with_config(stage, body, hooks, invoker, false)
}

/// AR-03 (Session 24) — full-form dispatcher with the per-stage
/// `fail_fast` policy threaded through.
///
/// When `fail_fast = false` (the pre-AR-03 lenient default), a hook
/// with an unparseable regex matcher logs warn + is skipped, and the
/// stage continues with the remaining hooks.
///
/// When `fail_fast = true`, the same regex compile failure escalates
/// to `StageOutcome::Block { name: <hook>, reason: "fail_fast: regex
/// compile failed ..." }`. Used by operators who put a safety hook in
/// `[hook_chain.pre_provider_call]` with `fail_fast: true` so a
/// typo'd matcher doesn't silently degrade the gate they wrote
/// precisely BECAUSE they wanted a block.
pub fn run_stage_with_config(
    stage: HookStage,
    body: &str,
    hooks: &[HookDef],
    invoker: Option<&dyn PluginInvoker>,
    fail_fast: bool,
) -> Result<StageOutcome> {
    let mut current = body.to_string();
    let mut hits = Vec::new();

    for hook in hooks.iter().filter(|h| h.stage == stage && h.is_enabled()) {
        let fires = match &hook.matcher {
            None => true,
            Some(m) => match Regex::new(&m.pattern) {
                Ok(re) => re.is_match(&current),
                Err(e) => {
                    if fail_fast {
                        // AR-03 — operator opted this stage into
                        // strict mode. A typo'd matcher escalates to
                        // Block so a safety hook can't silently fail
                        // open.
                        tracing::error!(
                            hook = %hook.name,
                            pattern = %m.pattern,
                            error = %e,
                            "fail_fast: bad regex in hook matcher — blocking stage",
                        );
                        return Ok(StageOutcome::Block {
                            name: hook.name.clone(),
                            reason: format!(
                                "fail_fast: regex compile failed for hook `{name}`: {e}",
                                name = hook.name,
                            ),
                        });
                    }
                    tracing::warn!(
                        hook = %hook.name,
                        pattern = %m.pattern,
                        error = %e,
                        "bad regex in hook matcher — skipping hook",
                    );
                    continue;
                }
            },
        };
        if !fires {
            continue;
        }
        match &hook.action {
            HookAction::Allow => {
                hits.push(hook.name.clone());
            }
            HookAction::Replace { template } => {
                hits.push(hook.name.clone());
                if let Some(m) = &hook.matcher {
                    if let Ok(re) = Regex::new(&m.pattern) {
                        current = re.replace_all(&current, template.as_str()).into_owned();
                        continue;
                    }
                }
                // No matcher → replace the entire body.
                current = template.clone();
            }
            HookAction::Block { reason } => {
                return Ok(StageOutcome::Block {
                    name: hook.name.clone(),
                    reason: reason.clone(),
                });
            }
            HookAction::Plugin {
                plugin_id,
                required,
            } => {
                hits.push(hook.name.clone());
                match invoker {
                    Some(inv) => {
                        if let Err(e) = inv.invoke(plugin_id) {
                            if *required {
                                // R2-P0-3: required plugin failure
                                // MUST escalate to Block. Silent-Allow
                                // on a safety hook was the documented
                                // hole — fix it here.
                                tracing::error!(
                                    hook = %hook.name,
                                    plugin_id = %plugin_id,
                                    error = %e,
                                    "required plugin invocation failed — blocking stage"
                                );
                                return Ok(StageOutcome::Block {
                                    name: hook.name.clone(),
                                    reason: format!("required plugin `{plugin_id}` failed: {e}"),
                                });
                            }
                            tracing::warn!(
                                hook = %hook.name,
                                plugin_id = %plugin_id,
                                error = %e,
                                "plugin invocation failed — stage continues (required=false)"
                            );
                        }
                    }
                    None => {
                        if *required {
                            // R2-P0-3: no invoker + required hook is a
                            // safety policy gap. Block immediately + log
                            // at error level so doctor can surface the
                            // policy hole.
                            tracing::error!(
                                hook = %hook.name,
                                plugin_id = %plugin_id,
                                "required plugin hook has no PluginInvoker — \
                                 blocking stage (safety contract violation)"
                            );
                            return Ok(StageOutcome::Block {
                                name: hook.name.clone(),
                                reason: format!(
                                    "required plugin `{plugin_id}` unavailable — no invoker registered"
                                ),
                            });
                        }
                        tracing::warn!(
                            hook = %hook.name,
                            plugin_id = %plugin_id,
                            "no PluginInvoker wired — optional Plugin action degrades to Allow"
                        );
                    }
                }
            }
        }
    }

    Ok(StageOutcome::Continue {
        body: current,
        hits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::schema::{HookAction, HookMatcher};

    fn allow_hook(name: &str, stage: HookStage) -> HookDef {
        HookDef {
            name: name.into(),
            stage,
            enabled: Some(true),
            priority: None,
            matcher: None,
            action: HookAction::Allow,
        }
    }

    fn replace_hook(name: &str, stage: HookStage, pattern: &str, template: &str) -> HookDef {
        HookDef {
            name: name.into(),
            stage,
            enabled: Some(true),
            priority: None,
            matcher: Some(HookMatcher {
                pattern: pattern.into(),
            }),
            action: HookAction::Replace {
                template: template.into(),
            },
        }
    }

    fn block_hook(name: &str, stage: HookStage, reason: &str) -> HookDef {
        HookDef {
            name: name.into(),
            stage,
            enabled: Some(true),
            priority: None,
            matcher: None,
            action: HookAction::Block {
                reason: reason.into(),
            },
        }
    }

    fn plugin_hook(name: &str, stage: HookStage, plugin_id: &str) -> HookDef {
        HookDef {
            name: name.into(),
            stage,
            enabled: Some(true),
            priority: None,
            matcher: None,
            action: HookAction::Plugin {
                plugin_id: plugin_id.into(),
                required: false,
            },
        }
    }

    fn required_plugin_hook(name: &str, stage: HookStage, plugin_id: &str) -> HookDef {
        HookDef {
            name: name.into(),
            stage,
            enabled: Some(true),
            priority: None,
            matcher: None,
            action: HookAction::Plugin {
                plugin_id: plugin_id.into(),
                required: true,
            },
        }
    }

    /// Counting test invoker — records every invoke call so we can
    /// assert the dispatcher hit the plugin path exactly once.
    struct CountingInvoker {
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl PluginInvoker for CountingInvoker {
        fn invoke(&self, plugin_id: &str) -> Result<()> {
            self.calls.lock().unwrap().push(plugin_id.to_string());
            Ok(())
        }
    }

    /// Failing test invoker — returns Err on every call so we can
    /// assert the stage continues past a plugin error.
    struct FailingInvoker;

    impl PluginInvoker for FailingInvoker {
        fn invoke(&self, _plugin_id: &str) -> Result<()> {
            anyhow::bail!("simulated plugin failure")
        }
    }

    #[test]
    fn plugin_action_fires_invoker_and_records_hit() {
        // Pick #34 hook-engine integration (2026-05-20): a hook
        // whose action is Plugin{ plugin_id } MUST call
        // invoker.invoke + record the hook name in StageOutcome.hits.
        let invoker = CountingInvoker {
            calls: std::sync::Mutex::new(Vec::new()),
        };
        let hooks = vec![plugin_hook(
            "audit-plugin",
            HookStage::PreProviderCall,
            "hello",
        )];
        let outcome = run_stage_with_plugins(
            HookStage::PreProviderCall,
            "operator body",
            &hooks,
            Some(&invoker),
        )
        .unwrap();
        match outcome {
            StageOutcome::Continue { body, hits } => {
                assert_eq!(body, "operator body", "Plugin actions do not mutate body");
                assert_eq!(hits, vec!["audit-plugin".to_string()]);
            }
            other => panic!("expected Continue, got {other:?}"),
        }
        let calls = invoker.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], "hello");
    }

    #[test]
    fn plugin_action_degrades_to_allow_without_invoker() {
        // When the daemon's bootstrap didn't wire a PluginInvoker
        // (slim build / test path / pre-plugin-host startup), a
        // Plugin hook still counts as a hit + the body passes
        // through unchanged. The dispatcher logs a warn that the
        // operator's audit grep can pick up.
        let hooks = vec![plugin_hook("audit-plugin", HookStage::PreProviderCall, "x")];
        let outcome = run_stage(HookStage::PreProviderCall, "body", &hooks).unwrap();
        match outcome {
            StageOutcome::Continue { body, hits } => {
                assert_eq!(body, "body");
                assert_eq!(hits, vec!["audit-plugin".to_string()]);
            }
            other => panic!("expected Continue, got {other:?}"),
        }
    }

    #[test]
    fn plugin_action_continues_when_invoker_errors() {
        // A misbehaving plugin must NOT block the operator's turn —
        // the dispatcher records the hit + warns + continues. Pin
        // this so a regression doesn't accidentally let plugins
        // gate the operator pipeline.
        let hooks = vec![plugin_hook("flaky-plugin", HookStage::PreProviderCall, "x")];
        let outcome = run_stage_with_plugins(
            HookStage::PreProviderCall,
            "body",
            &hooks,
            Some(&FailingInvoker),
        )
        .unwrap();
        assert!(matches!(outcome, StageOutcome::Continue { .. }));
    }

    #[test]
    fn no_hooks_returns_continue_with_unchanged_body() {
        let out = run_stage(HookStage::PreProviderCall, "hi", &[]).unwrap();
        match out {
            StageOutcome::Continue { body, hits } => {
                assert_eq!(body, "hi");
                assert!(hits.is_empty());
            }
            _ => panic!("expected Continue"),
        }
    }

    #[test]
    fn only_hooks_at_matching_stage_run() {
        let hooks = vec![
            allow_hook("a", HookStage::PreProviderCall),
            allow_hook("b", HookStage::PostProviderCall),
        ];
        let out = run_stage(HookStage::PreProviderCall, "x", &hooks).unwrap();
        match out {
            StageOutcome::Continue { hits, .. } => assert_eq!(hits, vec!["a"]),
            _ => panic!("expected Continue"),
        }
    }

    #[test]
    fn replace_hook_mutates_body() {
        let hooks = vec![replace_hook(
            "redact",
            HookStage::PreProviderCall,
            r"secret=\S+",
            "[X]",
        )];
        let out = run_stage(HookStage::PreProviderCall, "hello secret=abc world", &hooks).unwrap();
        match out {
            StageOutcome::Continue { body, hits } => {
                assert_eq!(body, "hello [X] world");
                assert_eq!(hits, vec!["redact"]);
            }
            _ => panic!("expected Continue"),
        }
    }

    #[test]
    fn replace_without_matcher_replaces_entire_body() {
        let hooks = vec![HookDef {
            name: "wipe".into(),
            stage: HookStage::PreProviderCall,
            enabled: Some(true),
            priority: None,
            matcher: None,
            action: HookAction::Replace {
                template: "n/a".into(),
            },
        }];
        let out = run_stage(HookStage::PreProviderCall, "anything", &hooks).unwrap();
        match out {
            StageOutcome::Continue { body, .. } => assert_eq!(body, "n/a"),
            _ => panic!("expected Continue"),
        }
    }

    #[test]
    fn block_hook_short_circuits_later_hooks() {
        let hooks = vec![
            block_hook("nope", HookStage::PreProviderCall, "no"),
            allow_hook("never", HookStage::PreProviderCall),
        ];
        let out = run_stage(HookStage::PreProviderCall, "x", &hooks).unwrap();
        match out {
            StageOutcome::Block { name, reason } => {
                assert_eq!(name, "nope");
                assert_eq!(reason, "no");
            }
            _ => panic!("expected Block"),
        }
    }

    #[test]
    fn bad_regex_hook_is_skipped_not_fatal() {
        let bad = HookDef {
            name: "bad".into(),
            stage: HookStage::PreProviderCall,
            enabled: Some(true),
            priority: None,
            matcher: Some(HookMatcher {
                pattern: "[invalid".into(),
            }),
            action: HookAction::Block { reason: "x".into() },
        };
        let good = allow_hook("good", HookStage::PreProviderCall);
        let out = run_stage(HookStage::PreProviderCall, "x", &[bad, good]).unwrap();
        match out {
            StageOutcome::Continue { hits, .. } => assert_eq!(hits, vec!["good"]),
            _ => panic!("bad-regex hook must skip, good hook must run"),
        }
    }

    #[test]
    fn chained_replaces_compound() {
        let hooks = vec![
            replace_hook("step1", HookStage::PreProviderCall, "foo", "bar"),
            replace_hook("step2", HookStage::PreProviderCall, "bar", "baz"),
        ];
        let out = run_stage(HookStage::PreProviderCall, "foo", &hooks).unwrap();
        match out {
            StageOutcome::Continue { body, hits } => {
                assert_eq!(body, "baz");
                assert_eq!(hits, vec!["step1", "step2"]);
            }
            _ => panic!("expected Continue"),
        }
    }

    #[test]
    fn disabled_hook_is_skipped() {
        let mut h = allow_hook("off", HookStage::PreProviderCall);
        h.enabled = Some(false);
        let out = run_stage(HookStage::PreProviderCall, "x", &[h]).unwrap();
        match out {
            StageOutcome::Continue { hits, .. } => assert!(hits.is_empty()),
            _ => panic!("expected Continue"),
        }
    }

    // ── R2-P0-3 required Plugin hook tests ──────────────────────────────

    #[test]
    fn r2_p0_3_required_plugin_blocks_when_invoker_missing() {
        // The reviewer-flagged failure mode: operator wrote a Plugin
        // hook at PreProviderCall expecting it to act as a safety
        // gate, but the daemon's invoker registration didn't run
        // (slim build / compile failure / discovery skip). Pre-fix:
        // silent Allow. Post-fix: Block with explicit reason so the
        // operator's audit sees the policy gap fire instead of
        // falsely-green telemetry.
        let hooks = vec![required_plugin_hook(
            "safety-gate",
            HookStage::PreProviderCall,
            "missing-plugin",
        )];
        let out = run_stage(HookStage::PreProviderCall, "operator body", &hooks).unwrap();
        match out {
            StageOutcome::Block { name, reason } => {
                assert_eq!(name, "safety-gate");
                assert!(reason.contains("missing-plugin"));
                assert!(
                    reason.contains("no invoker") || reason.contains("unavailable"),
                    "block reason must name the unavailable-invoker cause: {reason}"
                );
            }
            other => panic!("required plugin without invoker must Block, got: {other:?}"),
        }
    }

    #[test]
    fn r2_p0_3_required_plugin_blocks_when_invoker_errors() {
        // Same failure-closed contract, different failure mode: the
        // invoker IS registered but the plugin invocation itself
        // failed (wasm trap / panic / load error). Required = true
        // must escalate to Block.
        let hooks = vec![required_plugin_hook(
            "safety-gate",
            HookStage::PreProviderCall,
            "broken-plugin",
        )];
        let out = run_stage_with_plugins(
            HookStage::PreProviderCall,
            "operator body",
            &hooks,
            Some(&FailingInvoker),
        )
        .unwrap();
        match out {
            StageOutcome::Block { name, reason } => {
                assert_eq!(name, "safety-gate");
                assert!(reason.contains("broken-plugin"));
                assert!(reason.contains("simulated plugin failure") || reason.contains("failed"));
            }
            other => panic!("required plugin error must Block, got: {other:?}"),
        }
    }

    #[test]
    fn r2_p0_3_optional_plugin_keeps_legacy_fail_open_semantics() {
        // Operators who haven't opted into required-mode keep the
        // pre-2026-05-22 behaviour: invoker-missing degrades to Allow
        // + warn log. Pin so we don't accidentally break telemetry
        // hooks that the field defaulting to false should leave alone.
        let hooks = vec![plugin_hook(
            "telemetry-only",
            HookStage::PreProviderCall,
            "metrics-emitter",
        )];
        let out = run_stage(HookStage::PreProviderCall, "operator body", &hooks).unwrap();
        match out {
            StageOutcome::Continue { body, hits } => {
                assert_eq!(body, "operator body");
                assert_eq!(hits, vec!["telemetry-only"]);
            }
            other => panic!("optional plugin without invoker must Continue, got: {other:?}"),
        }
    }

    #[test]
    fn r2_p0_3_required_plugin_continues_when_invoker_succeeds() {
        // Happy path: invoker present + invocation succeeds. Even
        // required = true continues through the stage.
        let invoker = CountingInvoker {
            calls: std::sync::Mutex::new(Vec::new()),
        };
        let hooks = vec![required_plugin_hook(
            "safety-gate",
            HookStage::PreProviderCall,
            "policy-checker",
        )];
        let out = run_stage_with_plugins(
            HookStage::PreProviderCall,
            "operator body",
            &hooks,
            Some(&invoker),
        )
        .unwrap();
        match out {
            StageOutcome::Continue { body, hits } => {
                assert_eq!(body, "operator body");
                assert_eq!(hits, vec!["safety-gate"]);
            }
            other => panic!("happy-path required plugin must Continue, got: {other:?}"),
        }
        assert_eq!(invoker.calls.lock().unwrap().len(), 1);
    }

    // ── AR-03 (Session 24) per-stage fail_fast escalation ─────────────

    #[test]
    fn ar_03_fail_fast_false_keeps_legacy_skip_on_bad_regex() {
        // Back-compat pin: fail_fast=false (default) preserves the
        // pre-AR-03 behaviour — bad regex skips the hook + continues.
        let bad = HookDef {
            name: "bad".into(),
            stage: HookStage::PreProviderCall,
            enabled: Some(true),
            priority: None,
            matcher: Some(HookMatcher {
                pattern: "[invalid".into(),
            }),
            action: HookAction::Block {
                reason: "should-not-fire".into(),
            },
        };
        let good = allow_hook("good", HookStage::PreProviderCall);
        let out = run_stage_with_config(
            HookStage::PreProviderCall,
            "x",
            &[bad, good],
            None,
            false,
        )
        .unwrap();
        match out {
            StageOutcome::Continue { hits, .. } => assert_eq!(hits, vec!["good"]),
            other => panic!("fail_fast=false must skip bad hook, got {other:?}"),
        }
    }

    #[test]
    fn ar_03_fail_fast_true_escalates_bad_regex_to_block() {
        // AR-03 — operator opted this stage into strict mode. The bad
        // regex must Block the stage instead of silently being skipped.
        let bad = HookDef {
            name: "typo-matcher".into(),
            stage: HookStage::PreProviderCall,
            enabled: Some(true),
            priority: None,
            matcher: Some(HookMatcher {
                pattern: "[invalid".into(),
            }),
            action: HookAction::Allow,
        };
        let later = allow_hook("never-runs", HookStage::PreProviderCall);
        let out = run_stage_with_config(
            HookStage::PreProviderCall,
            "x",
            &[bad, later],
            None,
            true,
        )
        .unwrap();
        match out {
            StageOutcome::Block { name, reason } => {
                assert_eq!(name, "typo-matcher");
                assert!(
                    reason.contains("fail_fast")
                        && reason.contains("regex compile failed")
                        && reason.contains("typo-matcher"),
                    "block reason must surface the cause: {reason}",
                );
            }
            other => panic!("fail_fast=true must Block on bad regex, got {other:?}"),
        }
    }

    #[test]
    fn ar_03_fail_fast_does_not_affect_well_formed_hooks() {
        // Sanity: a stage opted into fail_fast still runs every
        // happy-path hook to completion. fail_fast is about errors,
        // not strictness in general.
        let h1 = allow_hook("a", HookStage::PreProviderCall);
        let h2 = replace_hook("b", HookStage::PreProviderCall, "foo", "bar");
        let out = run_stage_with_config(
            HookStage::PreProviderCall,
            "foo",
            &[h1, h2],
            None,
            true,
        )
        .unwrap();
        match out {
            StageOutcome::Continue { body, hits } => {
                assert_eq!(body, "bar");
                assert_eq!(hits, vec!["a", "b"]);
            }
            other => panic!("fail_fast must not block well-formed chain: {other:?}"),
        }
    }
}
