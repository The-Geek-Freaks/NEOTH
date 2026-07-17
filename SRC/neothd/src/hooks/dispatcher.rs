//! Run hooks at a given stage — Phase 29 R-15 H-3.
//!
//! The dispatcher takes the loaded hook set, walks the subset that matches
//! the current stage, applies each in order, and returns a [`StageOutcome`]
//! that the caller folds into its own dispatch logic.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::Result;
use regex::Regex;

use super::block_filter::{FilteredBlock, apply_block_filter};
use super::schema::{HookAction, HookDef};
use super::stages::HookStage;

/// Compile `pattern` to a [`Regex`], memoised process-wide by pattern string.
///
/// GOLD-ARCH-10: a hook matcher was compiled TWICE per dispatch (the `fires`
/// check + the `Replace` action) and re-compiled on every stage run. Hook
/// patterns come from the operator's config — practically bounded by the number
/// of distinct patterns an operator ever writes — so caching each successful
/// compile and cloning it out (cheap — `Regex` is `Arc`-backed) removes both the
/// double-compile and the per-dispatch recompile. GR-083 — the cache is NOT a
/// truly static set (patterns are loaded dynamically via `hooks::load_all`), so
/// it is hard-capped at [`MAX_CACHED_PATTERNS`] to stay bounded even if a future
/// path ever generated patterns programmatically. Compile ERRORS are
/// deliberately NOT cached: they are bad-config edge cases (rare) and skipping
/// the cache there keeps the `fail_fast` error path byte-identical to a direct
/// `Regex::new`.
fn compile_cached(pattern: &str) -> Result<Regex, regex::Error> {
    /// GR-083 — far above any realistic operator hook set; only a runaway
    /// dynamic-pattern path could approach it, and there the cache simply stops
    /// growing (compile-and-return without memoising).
    const MAX_CACHED_PATTERNS: usize = 512;
    static CACHE: OnceLock<Mutex<HashMap<String, Regex>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    {
        let guard = cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(re) = guard.get(pattern) {
            return Ok(re.clone());
        }
    }
    let re = Regex::new(pattern)?;
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    if guard.len() < MAX_CACHED_PATTERNS {
        guard.insert(pattern.to_string(), re.clone());
    }
    Ok(re)
}

/// Resettable process-wide invoker slot. The static proxy below never owns the
/// concrete invoker; the daemon-scoped [`GlobalInvokerRegistration`] does.
#[derive(Default)]
struct PluginInvokerRegistry {
    current: Mutex<Option<Arc<dyn PluginInvoker>>>,
}

impl PluginInvokerRegistry {
    fn register(&self, invoker: Arc<dyn PluginInvoker>) -> bool {
        let mut current = self.current.lock().unwrap_or_else(|e| e.into_inner());
        if current.is_some() {
            return false;
        }
        *current = Some(invoker);
        true
    }

    fn current(&self) -> Option<Arc<dyn PluginInvoker>> {
        self.current
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn clear_if(&self, expected: &Arc<dyn PluginInvoker>) {
        let removed = {
            let mut current = self.current.lock().unwrap_or_else(|e| e.into_inner());
            if current
                .as_ref()
                .is_some_and(|registered| Arc::ptr_eq(registered, expected))
            {
                current.take()
            } else {
                None
            }
        };
        drop(removed);
    }
}

static GLOBAL_INVOKER: OnceLock<Arc<PluginInvokerRegistry>> = OnceLock::new();
static GLOBAL_INVOKER_PROXY: OnceLock<Arc<dyn PluginInvoker>> = OnceLock::new();

fn global_invoker_registry() -> &'static Arc<PluginInvokerRegistry> {
    GLOBAL_INVOKER.get_or_init(|| Arc::new(PluginInvokerRegistry::default()))
}

/// Daemon-scoped ownership of one global invoker registration.
///
/// Dropping this guard unregisters only the exact invoker it installed. This
/// releases the plugin's WAL sender before the daemon waits for the writer task
/// and also makes a later daemon instance in the same process registerable.
pub struct GlobalInvokerRegistration {
    registry: Arc<PluginInvokerRegistry>,
    invoker: Arc<dyn PluginInvoker>,
}

impl Drop for GlobalInvokerRegistration {
    fn drop(&mut self) {
        self.registry.clear_if(&self.invoker);
    }
}

struct GlobalInvokerProxy;

impl PluginInvoker for GlobalInvokerProxy {
    fn invoke(&self, plugin_id: &str) -> Result<()> {
        let invoker = global_invoker_registry()
            .current()
            .ok_or_else(|| anyhow::anyhow!("no global PluginInvoker is currently registered"))?;
        invoker.invoke(plugin_id)
    }
}

/// Register the process-wide PluginInvoker and return its ownership guard.
/// A live registration is never overwritten.
pub fn register_global_invoker(
    invoker: Arc<dyn PluginInvoker>,
) -> Option<GlobalInvokerRegistration> {
    let registry = Arc::clone(global_invoker_registry());
    if !registry.register(Arc::clone(&invoker)) {
        return None;
    }
    Some(GlobalInvokerRegistration { registry, invoker })
}

/// Read the current process-wide invoker through a non-owning static proxy.
/// `None` before registration and after its guard is dropped.
pub fn current_global_invoker() -> Option<&'static Arc<dyn PluginInvoker>> {
    global_invoker_registry().current()?;
    Some(GLOBAL_INVOKER_PROXY.get_or_init(|| {
        let proxy: Arc<dyn PluginInvoker> = Arc::new(GlobalInvokerProxy);
        proxy
    }))
}

/// What the dispatcher decided after running every applicable hook.
///
/// ## Exit-code semantics (logical analogues — NEOTH has no shell-exec action)
///
/// | Analogue | Variant / path | Meaning |
/// |----------|----------------|---------|
/// | Exit 0   | `Continue`     | Pipeline proceeds. Covers the fully-normal case (no hooks matched, Allow hooks matched, Replace hooks rewrote the body). |
/// | Exit 1   | `Continue` (warn path) | Warn-and-continue. Optional-plugin-failure (`required = false`) and bad-regex-skip (`fail_fast = false`) both produce a `Continue` after emitting a `warn` log. They are non-blocking — the operator's turn is NOT dropped. |
/// | Exit 2   | `Block`        | Pipeline stops. Produced by `HookAction::Block`, a required-Plugin failure (missing or erroring invoker), or a bad-regex with `fail_fast = true`. Callers **must** abort the current turn (bail the `enforce_preflight` gate or the post-reply pipeline). |
///
/// Note: `HookAction::Command` (shell-out) does NOT exist in NEOTH. That
/// workload is routed through `HookAction::Plugin { plugin_id }` which
/// dispatches to a sandboxed WASM plugin via the daemon's registered
/// `PluginInvoker`. Exit-code semantics therefore apply at the Rust enum
/// level, not at a child-process level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StageOutcome {
    /// **Exit-0 equivalent** — pipeline proceeds. `body` is the (possibly
    /// replaced) text; `hits` names every hook that ran and matched.
    ///
    /// Warn-and-continue paths (optional-plugin-failure with `required=false`,
    /// bad-regex-skip with `fail_fast=false`) also resolve to this variant —
    /// they are the **exit-1 analogue**: logged at `warn` level but
    /// never blocking.
    Continue { body: String, hits: Vec<String> },
    /// **Exit-2 equivalent** — pipeline stops. `reason` is the
    /// operator-visible explanation; `name` is the hook that triggered the
    /// block. Callers **must** abort the current turn (drop the WAL writer,
    /// await the join, then `anyhow::bail!`).
    ///
    /// Produced by:
    /// - `HookAction::Block { reason }` (explicit operator block)
    /// - required-Plugin failure: invoker missing **or** invoker returned `Err`
    /// - bad-regex with `fail_fast = true` (AR-03 strict-mode escalation)
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
    let (outcome, _blocks) =
        run_stage_with_config_returning_blocks(stage, body, hooks, invoker, fail_fast)?;
    Ok(outcome)
}

/// GOLD-ADAPT-SKILL-09 — variant of [`run_stage_with_config`] that also
/// returns any [`FilteredBlock`]s accumulated by `BlockFilter` actions.
///
/// The `Vec<FilteredBlock>` is non-empty only when at least one
/// `HookAction::BlockFilter` fired at this stage. Callers that need the
/// restore data (i.e. the `PreProviderCall` stage in `run_hook_stage` in
/// `cli/chat.rs`) use this form; all other callers use [`run_stage_with_config`]
/// and discard the blocks (backward-compatible, zero-cost when no BlockFilter
/// hooks are configured).
pub fn run_stage_with_config_returning_blocks(
    stage: HookStage,
    body: &str,
    hooks: &[HookDef],
    invoker: Option<&dyn PluginInvoker>,
    fail_fast: bool,
) -> Result<(StageOutcome, Vec<FilteredBlock>)> {
    let mut current = body.to_string();
    let mut hits = Vec::new();
    // GOLD-ADAPT-SKILL-09: accumulated across all BlockFilter actions in
    // this stage run. Kept in insertion order so restore_blocks replaces
    // placeholders left-to-right (matching the order they appear in body).
    let mut accumulated_blocks: Vec<FilteredBlock> = Vec::new();

    for hook in hooks.iter().filter(|h| h.stage == stage && h.is_enabled()) {
        let fires = match &hook.matcher {
            None => true,
            Some(m) => match compile_cached(&m.pattern) {
                Ok(re) => re.is_match(&current),
                Err(e) => {
                    // BUG-W2-P1-HOOK-FAILFAST: block when the stage-level
                    // `fail_fast` param (from `HookChainConfig`) OR the
                    // per-hook `hook.fail_fast` field is true. Either flag
                    // opts into strict mode; both default to `false`.
                    if fail_fast || hook.fail_fast {
                        // AR-03 / per-hook fail-fast — a typo'd matcher
                        // escalates to Block so a safety hook can't
                        // silently fail open.
                        tracing::error!(
                            hook = %hook.name,
                            pattern = %m.pattern,
                            error = %e,
                            "fail_fast: bad regex in hook matcher — blocking stage",
                        );
                        return Ok((
                            StageOutcome::Block {
                                name: hook.name.clone(),
                                reason: format!(
                                    "fail_fast: regex compile failed for hook `{name}`: {e}",
                                    name = hook.name,
                                ),
                            },
                            Vec::new(),
                        ));
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
                if let Some(m) = &hook.matcher
                    && let Ok(re) = compile_cached(&m.pattern)
                {
                    current = re.replace_all(&current, template.as_str()).into_owned();
                    continue;
                }
                // No matcher → replace the entire body.
                current = template.clone();
            }
            HookAction::Block { reason } => {
                return Ok((
                    StageOutcome::Block {
                        name: hook.name.clone(),
                        reason: reason.clone(),
                    },
                    Vec::new(),
                ));
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
                                return Ok((
                                    StageOutcome::Block {
                                        name: hook.name.clone(),
                                        reason: format!(
                                            "required plugin `{plugin_id}` failed: {e}"
                                        ),
                                    },
                                    Vec::new(),
                                ));
                            }
                            // BUG-W2-P1-HOOK-FAILFAST: per-hook fail-fast
                            // escalates an optional-plugin failure to Block.
                            if hook.fail_fast {
                                tracing::error!(
                                    hook = %hook.name,
                                    plugin_id = %plugin_id,
                                    error = %e,
                                    "fail_fast: optional plugin invocation failed — blocking stage"
                                );
                                return Ok((
                                    StageOutcome::Block {
                                        name: hook.name.clone(),
                                        reason: format!(
                                            "fail_fast: plugin `{plugin_id}` invocation failed: {e}"
                                        ),
                                    },
                                    Vec::new(),
                                ));
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
                            return Ok((
                                StageOutcome::Block {
                                    name: hook.name.clone(),
                                    reason: format!(
                                        "required plugin `{plugin_id}` unavailable — no invoker registered"
                                    ),
                                },
                                Vec::new(),
                            ));
                        }
                        // BUG-W2-P1-HOOK-FAILFAST: per-hook fail-fast
                        // escalates a missing-invoker gap to Block even
                        // when required = false.
                        if hook.fail_fast {
                            tracing::error!(
                                hook = %hook.name,
                                plugin_id = %plugin_id,
                                "fail_fast: optional plugin hook has no PluginInvoker — \
                                 blocking stage"
                            );
                            return Ok((
                                StageOutcome::Block {
                                    name: hook.name.clone(),
                                    reason: format!(
                                        "fail_fast: plugin `{plugin_id}` unavailable — no invoker registered"
                                    ),
                                },
                                Vec::new(),
                            ));
                        }
                        tracing::warn!(
                            hook = %hook.name,
                            plugin_id = %plugin_id,
                            "no PluginInvoker wired — optional Plugin action degrades to Allow"
                        );
                    }
                }
            }
            // GOLD-ADAPT-SKILL-09 — block-filter: redact annotated regions
            // from the body before the LLM sees it. The FilteredBlocks are
            // threaded out so the PostProviderCall stage can restore them.
            HookAction::BlockFilter {
                start_marker,
                end_marker,
                placeholder,
            } => {
                hits.push(hook.name.clone());
                let (filtered, blocks) =
                    apply_block_filter(&current, start_marker, end_marker, placeholder);
                tracing::debug!(
                    hook = %hook.name,
                    redacted_regions = blocks.len(),
                    "block_filter: redacted {} ignore region(s)",
                    blocks.len(),
                );
                current = filtered;
                accumulated_blocks.extend(blocks);
            }
        }
    }

    Ok((
        StageOutcome::Continue {
            body: current,
            hits,
        },
        accumulated_blocks,
    ))
}

// ── BUG-W2-P1-HOOK-ONCE-PARITY ──────────────────────────────────────────────

/// Session-scoped once-gate for atomic claim-before-effect in the dispatcher.
///
/// Wraps `Arc<Mutex<HashSet<String>>>` so the dispatcher can, for each
/// `once = true` hook:
/// 1. Lock the set.
/// 2. Check whether the hook's name is already claimed.
/// 3. If not → insert the name (claim) **before** the effect executes.
/// 4. Drop the lock, then run the action.
///
/// This eliminates the TOCTOU window that existed in each caller
/// (`cli/chat.rs`, `serve_pipeline.rs`, `cron/runner.rs`) where
/// `session_fired_once.contains()` was checked without holding the lock
/// across the effect, allowing two concurrent channel turns or scheduler
/// ticks to both see the name absent and both fire.
///
/// **Usage:** create one `SessionOnceGuard` per logical session and share
/// it (cheaply cloned via `Arc`) across all concurrent stage invocations
/// for that session. The inner `Mutex` is `std::sync` (not `tokio`): the
/// dispatcher is synchronous and never holds the lock across an await point,
/// so there is no deadlock risk even when callers are async.
///
/// **Wiring (per caller — do not edit callers here; document only):**
/// - `cli/chat.rs`: replace `let mut session_fired_once: HashSet<String>` at
///   line ~5040 with `let once_guard = SessionOnceGuard::new();` and change
///   the `run_hook_stage` signature from `&mut HashSet<String>` to
///   `&SessionOnceGuard`. Inside `run_hook_stage`, replace
///   `run_stage_with_config_returning_blocks` with `run_stage_with_once_guard`
///   and use `result.skipped_once` for WAL HOOK_SKIPPED_ONCE writes; remove
///   the manual pre-filter loop and post-insert.
/// - `cli/serve_pipeline.rs`: change line ~816 from
///   `Arc<tokio::sync::Mutex<HashSet<String>>>` to `Arc<SessionOnceGuard>`
///   (or just `SessionOnceGuard`). At each `crate::hooks::run_stage(...)` call
///   for PreChannelIngress (line ~1047), PreEgress (line ~620), and
///   PreProviderCall (line ~2320) switch to `run_stage_with_once_guard`. For
///   the PreProviderCall call, keep `result.filtered_blocks` and after the LLM
///   replies call `crate::hooks::block_filter::restore_blocks(llm_body,
///   &filtered_blocks)` — that is the missing PostProviderCall restoration path.
///   Remove the manual `fired.contains` / `fired.insert` blocks (the guard
///   owns that now).
/// - `cron/runner.rs`: create a `SessionOnceGuard::new()` per job invocation
///   where `crate::hooks::run_stage` is currently passed as a function pointer;
///   wrap the call in a closure that captures the guard and calls
///   `run_stage_with_once_guard`, mapping the `StageOnceResult` back to
///   `StageOutcome` via `result.outcome` (no once-hooks in cron today, but the
///   single code path parity is required).
pub struct SessionOnceGuard(Arc<Mutex<HashSet<String>>>);

impl SessionOnceGuard {
    /// Create a fresh, empty guard for a new session.
    pub fn new() -> Self {
        SessionOnceGuard(Arc::new(Mutex::new(HashSet::new())))
    }
}

impl Clone for SessionOnceGuard {
    /// Cheap clone — shares the underlying `Arc`; same session, same set.
    fn clone(&self) -> Self {
        SessionOnceGuard(Arc::clone(&self.0))
    }
}

impl Default for SessionOnceGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// BUG-W2-P1-HOOK-ONCE-PARITY — result of a once-aware stage dispatch.
///
/// Extends `(StageOutcome, Vec<FilteredBlock>)` (the pair returned by
/// [`run_stage_with_config_returning_blocks`]) with `skipped_once`: the names
/// of `once = true` hooks that were suppressed because the
/// [`SessionOnceGuard`] already held a claim on them.
///
/// Callers are responsible for writing one `HOOK_SKIPPED_ONCE` (0x8B) WAL
/// frame per name in `skipped_once`. The dispatcher surfaces names only;
/// it does not write WAL (it has no WAL handle).
#[derive(Debug)]
pub struct StageOnceResult {
    /// Outcome of the stage, identical to [`StageOutcome`] semantics.
    pub outcome: StageOutcome,
    /// Blocks accumulated by `BlockFilter` actions at this stage. Non-empty
    /// only when a `HookAction::BlockFilter` fired. Callers at
    /// `PreProviderCall` keep these and call `restore_blocks` on the LLM
    /// response at `PostProviderCall`.
    pub filtered_blocks: Vec<FilteredBlock>,
    /// Names of `once = true` hooks skipped because the session-once guard
    /// already held a claim. One `HOOK_SKIPPED_ONCE` (0x8B) WAL frame per
    /// entry is the caller's responsibility.
    pub skipped_once: Vec<String>,
}

/// BUG-W2-P1-HOOK-ONCE-PARITY — dispatcher entry-point that enforces `once`
/// atomically via `once_guard`.
///
/// ## Ordering guarantee
///
/// For every enabled hook whose matcher fires at `stage`, if `hook.once = true`:
///
/// 1. Lock `once_guard` (std::sync::Mutex, never held across an await).
/// 2. If the hook's name is already in the claimed set →
///    push to `StageOnceResult::skipped_once`, drop the lock, **continue to
///    the next hook** (effect never runs).
/// 3. Otherwise → insert the name into the claimed set **before** executing
///    the action, drop the lock, then run the action.
///
/// Because the claim (step 3) happens while the mutex is held, and the
/// second concurrent caller acquires the same mutex and therefore sees the
/// name already present (step 2), it is impossible for both callers to
/// proceed to the action. The TOCTOU window (check without holding the lock
/// across the effect) that existed in every prior caller is eliminated.
///
/// ## Preserved semantics
///
/// All existing behaviors are reproduced exactly:
/// - `fail_fast` (stage-level and per-hook)
/// - `required` plugins
/// - `Block` actions short-circuit the stage and carry `skipped_once` in the result
/// - `FilteredBlock` accumulation — non-empty when `BlockFilter` actions fire
///
/// ## Shared entry-point for CLI / channels / cron
///
/// CLI (`run_hook_stage`), channels (`build_pipeline_handler`), and cron
/// (`runner`) all call this function with their session's `SessionOnceGuard`.
/// See the wiring notes on [`SessionOnceGuard`] for the exact per-file changes.
pub fn run_stage_with_once_guard(
    stage: HookStage,
    body: &str,
    hooks: &[HookDef],
    invoker: Option<&dyn PluginInvoker>,
    fail_fast: bool,
    once_guard: &SessionOnceGuard,
) -> Result<StageOnceResult> {
    let mut current = body.to_string();
    let mut hits: Vec<String> = Vec::new();
    let mut accumulated_blocks: Vec<FilteredBlock> = Vec::new();
    let mut skipped_once: Vec<String> = Vec::new();

    for hook in hooks.iter().filter(|h| h.stage == stage && h.is_enabled()) {
        // ── Step 1: evaluate matcher — no side effects ───────────────────
        let fires = match &hook.matcher {
            None => true,
            Some(m) => match compile_cached(&m.pattern) {
                Ok(re) => re.is_match(&current),
                Err(e) => {
                    if fail_fast || hook.fail_fast {
                        tracing::error!(
                            hook = %hook.name,
                            pattern = %m.pattern,
                            error = %e,
                            "fail_fast: bad regex in hook matcher — blocking stage",
                        );
                        return Ok(StageOnceResult {
                            outcome: StageOutcome::Block {
                                name: hook.name.clone(),
                                reason: format!(
                                    "fail_fast: regex compile failed for hook `{name}`: {e}",
                                    name = hook.name,
                                ),
                            },
                            filtered_blocks: Vec::new(),
                            skipped_once,
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

        // ── Step 2: atomic claim-before-effect for once=true hooks ───────
        // The lock is acquired, the claim check + optional insert happen
        // under the lock, and the lock is dropped BEFORE any effect runs.
        // Two concurrent callers sharing this guard cannot both proceed
        // past this gate for the same hook name.
        if hook.once() {
            let already_claimed = {
                let mut set = once_guard.0.lock().unwrap_or_else(|e| e.into_inner());
                if set.contains(&hook.name) {
                    // Already claimed by an earlier (possibly concurrent) call.
                    // Signal the caller to emit HOOK_SKIPPED_ONCE.
                    skipped_once.push(hook.name.clone());
                    true
                } else {
                    // Claim BEFORE the effect. The lock is still held here,
                    // so no concurrent caller can insert in parallel.
                    set.insert(hook.name.clone());
                    false
                }
                // Mutex guard drops here — effect runs outside the lock.
            };
            if already_claimed {
                continue;
            }
        }

        // ── Step 3: execute effect ───────────────────────────────────────
        match &hook.action {
            HookAction::Allow => {
                hits.push(hook.name.clone());
            }
            HookAction::Replace { template } => {
                hits.push(hook.name.clone());
                if let Some(m) = &hook.matcher
                    && let Ok(re) = compile_cached(&m.pattern)
                {
                    current = re.replace_all(&current, template.as_str()).into_owned();
                    continue;
                }
                // No matcher → replace the entire body.
                current = template.clone();
            }
            HookAction::Block { reason } => {
                return Ok(StageOnceResult {
                    outcome: StageOutcome::Block {
                        name: hook.name.clone(),
                        reason: reason.clone(),
                    },
                    filtered_blocks: Vec::new(),
                    skipped_once,
                });
            }
            HookAction::Plugin { plugin_id, required } => {
                hits.push(hook.name.clone());
                match invoker {
                    Some(inv) => {
                        if let Err(e) = inv.invoke(plugin_id) {
                            if *required {
                                tracing::error!(
                                    hook = %hook.name,
                                    plugin_id = %plugin_id,
                                    error = %e,
                                    "required plugin invocation failed — blocking stage"
                                );
                                return Ok(StageOnceResult {
                                    outcome: StageOutcome::Block {
                                        name: hook.name.clone(),
                                        reason: format!(
                                            "required plugin `{plugin_id}` failed: {e}"
                                        ),
                                    },
                                    filtered_blocks: Vec::new(),
                                    skipped_once,
                                });
                            }
                            if hook.fail_fast {
                                tracing::error!(
                                    hook = %hook.name,
                                    plugin_id = %plugin_id,
                                    error = %e,
                                    "fail_fast: optional plugin invocation failed — blocking stage"
                                );
                                return Ok(StageOnceResult {
                                    outcome: StageOutcome::Block {
                                        name: hook.name.clone(),
                                        reason: format!(
                                            "fail_fast: plugin `{plugin_id}` invocation failed: {e}"
                                        ),
                                    },
                                    filtered_blocks: Vec::new(),
                                    skipped_once,
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
                            tracing::error!(
                                hook = %hook.name,
                                plugin_id = %plugin_id,
                                "required plugin hook has no PluginInvoker — \
                                 blocking stage (safety contract violation)"
                            );
                            return Ok(StageOnceResult {
                                outcome: StageOutcome::Block {
                                    name: hook.name.clone(),
                                    reason: format!(
                                        "required plugin `{plugin_id}` unavailable — no invoker registered"
                                    ),
                                },
                                filtered_blocks: Vec::new(),
                                skipped_once,
                            });
                        }
                        if hook.fail_fast {
                            tracing::error!(
                                hook = %hook.name,
                                plugin_id = %plugin_id,
                                "fail_fast: optional plugin hook has no PluginInvoker — \
                                 blocking stage"
                            );
                            return Ok(StageOnceResult {
                                outcome: StageOutcome::Block {
                                    name: hook.name.clone(),
                                    reason: format!(
                                        "fail_fast: plugin `{plugin_id}` unavailable — no invoker registered"
                                    ),
                                },
                                filtered_blocks: Vec::new(),
                                skipped_once,
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
            HookAction::BlockFilter { start_marker, end_marker, placeholder } => {
                hits.push(hook.name.clone());
                let (filtered, blocks) =
                    apply_block_filter(&current, start_marker, end_marker, placeholder);
                tracing::debug!(
                    hook = %hook.name,
                    redacted_regions = blocks.len(),
                    "block_filter: redacted {} ignore region(s)",
                    blocks.len(),
                );
                current = filtered;
                accumulated_blocks.extend(blocks);
            }
        }
    }

    Ok(StageOnceResult {
        outcome: StageOutcome::Continue { body: current, hits },
        filtered_blocks: accumulated_blocks,
        skipped_once,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::schema::{HookAction, HookMatcher};

    struct DropTrackingInvoker(Arc<std::sync::atomic::AtomicUsize>);

    impl Drop for DropTrackingInvoker {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl PluginInvoker for DropTrackingInvoker {
        fn invoke(&self, _plugin_id: &str) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn plugin_invoker_registry_releases_and_accepts_replacement() {
        let registry = Arc::new(PluginInvokerRegistry::default());
        let first_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let first: Arc<dyn PluginInvoker> = Arc::new(DropTrackingInvoker(Arc::clone(&first_drops)));

        assert!(registry.register(Arc::clone(&first)));
        let registration = GlobalInvokerRegistration {
            registry: Arc::clone(&registry),
            invoker: Arc::clone(&first),
        };
        drop(first);
        drop(registration);
        assert_eq!(first_drops.load(std::sync::atomic::Ordering::SeqCst), 1);

        let replacement: Arc<dyn PluginInvoker> = Arc::new(CountingInvoker {
            calls: std::sync::Mutex::new(Vec::new()),
        });
        assert!(registry.register(Arc::clone(&replacement)));
        assert!(!registry.register(replacement));
    }

    #[test]
    fn compile_cached_returns_equivalent_regex_and_caches_by_pattern() {
        // First compile populates the cache; second returns the cached clone.
        // Both must behave identically to a direct `Regex::new` (GOLD-ARCH-10
        // is perf-only — zero behaviour change).
        let a = compile_cached(r"\bsecret\b").expect("valid pattern compiles");
        let b = compile_cached(r"\bsecret\b").expect("repeat compile served from cache");
        assert!(a.is_match("a secret here"));
        assert!(b.is_match("a secret here"));
        assert!(!a.is_match("secretive"));
        assert!(!b.is_match("secretive"));
        // A genuinely invalid pattern still surfaces the compile error (the
        // error path is NOT cached so fail_fast stays byte-identical).
        assert!(compile_cached(r"(unclosed").is_err());
    }

    fn allow_hook(name: &str, stage: HookStage) -> HookDef {
        HookDef {
            name: name.into(),
            stage,
            enabled: Some(true),
            priority: None,
            matcher: None,
            action: HookAction::Allow,
            status_message: None,
            once: false,
            fail_fast: false,
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
            status_message: None,
            once: false,
            fail_fast: false,
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
            status_message: None,
            once: false,
            fail_fast: false,
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
            status_message: None,
            once: false,
            fail_fast: false,
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
            status_message: None,
            once: false,
            fail_fast: false,
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
            status_message: None,
            once: false,
            fail_fast: false,
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
            status_message: None,
            once: false,
            fail_fast: false,
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
            status_message: None,
            once: false,
            fail_fast: false,
        };
        let good = allow_hook("good", HookStage::PreProviderCall);
        let out = run_stage_with_config(HookStage::PreProviderCall, "x", &[bad, good], None, false)
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
            status_message: None,
            once: false,
            fail_fast: false,
        };
        let later = allow_hook("never-runs", HookStage::PreProviderCall);
        let out = run_stage_with_config(HookStage::PreProviderCall, "x", &[bad, later], None, true)
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
        let out = run_stage_with_config(HookStage::PreProviderCall, "foo", &[h1, h2], None, true)
            .unwrap();
        match out {
            StageOutcome::Continue { body, hits } => {
                assert_eq!(body, "bar");
                assert_eq!(hits, vec!["a", "b"]);
            }
            other => panic!("fail_fast must not block well-formed chain: {other:?}"),
        }
    }

    // ── CCPARITY-EXIT-CODE: pin exit-code 0/1/2 semantics ───────────────

    #[test]
    fn exit_code_1_analogue_optional_plugin_failure_does_not_block() {
        // EXIT-1 ANALOGUE — an optional-plugin failure (required=false)
        // must produce StageOutcome::Continue, NOT Block. This pins the
        // "warn-and-continue" contract: the stage is degraded but the
        // operator's turn is NOT aborted. Any regression that accidentally
        // promotes the warn path to Block would break this test.
        //
        // Stage: PreProviderCall (the pre-tool-call gate, omc's PreToolUse).
        // Invoker: FailingInvoker — returns Err on every call.
        // Hook: optional (required=false), so failure = exit-1 analogue.
        let hooks = vec![plugin_hook(
            "optional-audit",
            HookStage::PreProviderCall,
            "unreliable-plugin",
        )];
        let out = run_stage_with_plugins(
            HookStage::PreProviderCall,
            "tool input text",
            &hooks,
            Some(&FailingInvoker),
        )
        .unwrap();
        match out {
            StageOutcome::Continue { body, hits } => {
                assert_eq!(
                    body, "tool input text",
                    "optional plugin failure must not mutate body"
                );
                assert_eq!(
                    hits,
                    vec!["optional-audit".to_string()],
                    "hit must be recorded even when plugin errors"
                );
            }
            StageOutcome::Block { name, reason } => {
                panic!(
                    "exit-1 analogue (optional plugin failure) must NOT block \
                     — got Block {{ name: {name:?}, reason: {reason:?} }}"
                );
            }
        }
    }

    #[test]
    fn exit_code_2_analogue_block_action_aborts_pre_tool_call() {
        // EXIT-2 ANALOGUE — a HookAction::Block at PreProviderCall (the
        // pre-tool-call gate) must produce StageOutcome::Block. This pins
        // that an operator-written deny hook actually aborts the tool call
        // before it reaches the provider, matching the "exit-2 = abort turn"
        // contract documented on StageOutcome::Block.
        //
        // Stage: PreProviderCall (omc's PreToolUse — the ONLY pre-tool gate).
        // Action: HookAction::Block { reason: "not allowed" }.
        let hooks = vec![block_hook(
            "deny",
            HookStage::PreProviderCall,
            "not allowed",
        )];
        let out = run_stage(HookStage::PreProviderCall, "tool input text", &hooks).unwrap();
        match out {
            StageOutcome::Block { name, reason } => {
                assert_eq!(name, "deny", "block must name the hook that triggered it");
                assert_eq!(
                    reason, "not allowed",
                    "block reason must be the operator's deny message"
                );
            }
            StageOutcome::Continue { .. } => {
                panic!(
                    "exit-2 analogue (Block action at PreProviderCall) must NOT \
                     Continue — the tool call must be aborted"
                );
            }
        }
    }

    // ── BUG-W2-P1-HOOK-FAILFAST: per-hook fail_fast stop/continue tests ─

    #[test]
    fn hook_fail_fast_true_blocks_bad_regex_at_pre_provider_call() {
        // Per-hook fail_fast=true at PreProviderCall: a regex compile error
        // on the hook's matcher must immediately Block the stage (no
        // stage-level fail_fast param needed). The hook after it must not run.
        let strict = HookDef {
            name: "strict-safety".into(),
            stage: HookStage::PreProviderCall,
            enabled: Some(true),
            priority: None,
            matcher: Some(HookMatcher {
                pattern: "[bad-regex".into(),
            }),
            action: HookAction::Allow,
            status_message: None,
            once: false,
            fail_fast: true,
        };
        let later = allow_hook("never-runs", HookStage::PreProviderCall);
        // stage-level fail_fast=false — only the per-hook flag is active.
        let out =
            run_stage_with_config(HookStage::PreProviderCall, "body", &[strict, later], None, false)
                .unwrap();
        match out {
            StageOutcome::Block { name, reason } => {
                assert_eq!(name, "strict-safety");
                assert!(
                    reason.contains("fail_fast") && reason.contains("strict-safety"),
                    "block reason must identify fail_fast and the hook: {reason}"
                );
            }
            other => panic!(
                "per-hook fail_fast=true must Block on bad regex, got {other:?}"
            ),
        }
    }

    #[test]
    fn hook_fail_fast_true_blocks_optional_plugin_failure_at_post_provider_call() {
        // Per-hook fail_fast=true at PostProviderCall: an optional-plugin
        // failure (required=false) must still escalate to Block when the
        // hook opts in via fail_fast=true. The stage-level param stays false.
        let strict = HookDef {
            name: "strict-plugin".into(),
            stage: HookStage::PostProviderCall,
            enabled: Some(true),
            priority: None,
            matcher: None,
            action: HookAction::Plugin {
                plugin_id: "broken-plugin".into(),
                required: false,
            },
            status_message: None,
            once: false,
            fail_fast: true,
        };
        let later = allow_hook("never-runs", HookStage::PostProviderCall);
        let out = run_stage_with_config(
            HookStage::PostProviderCall,
            "body",
            &[strict, later],
            Some(&FailingInvoker),
            false,
        )
        .unwrap();
        match out {
            StageOutcome::Block { name, reason } => {
                assert_eq!(name, "strict-plugin");
                assert!(
                    reason.contains("fail_fast") && reason.contains("broken-plugin"),
                    "block reason must surface fail_fast and plugin id: {reason}"
                );
            }
            other => panic!(
                "fail_fast=true on optional plugin must Block on invoker failure, got {other:?}"
            ),
        }
    }

    #[test]
    fn hook_fail_fast_false_continues_on_bad_regex_at_post_provider_call() {
        // Pin: per-hook fail_fast=false (default) at PostProviderCall keeps
        // the skip-and-continue behavior for regex errors. The good hook
        // after it must still run.
        let lenient = HookDef {
            name: "lenient-bad-regex".into(),
            stage: HookStage::PostProviderCall,
            enabled: Some(true),
            priority: None,
            matcher: Some(HookMatcher {
                pattern: "[bad".into(),
            }),
            action: HookAction::Block {
                reason: "should-not-fire".into(),
            },
            status_message: None,
            once: false,
            fail_fast: false,
        };
        let good = allow_hook("good-after", HookStage::PostProviderCall);
        let out = run_stage_with_config(
            HookStage::PostProviderCall,
            "text",
            &[lenient, good],
            None,
            false,
        )
        .unwrap();
        match out {
            StageOutcome::Continue { hits, .. } => {
                assert_eq!(
                    hits,
                    vec!["good-after".to_string()],
                    "bad-regex hook with fail_fast=false must skip; good hook must run"
                );
            }
            other => panic!(
                "fail_fast=false must skip bad regex and continue, got {other:?}"
            ),
        }
    }

    #[test]
    fn hook_fail_fast_false_continues_on_optional_plugin_failure_at_pre_provider_call() {
        // Pin: per-hook fail_fast=false (default) at PreProviderCall keeps
        // the warn-and-continue path for optional-plugin failures.
        // The hook after it must still run (exit-1 analogue preserved).
        let lenient = HookDef {
            name: "lenient-plugin".into(),
            stage: HookStage::PreProviderCall,
            enabled: Some(true),
            priority: None,
            matcher: None,
            action: HookAction::Plugin {
                plugin_id: "unreliable".into(),
                required: false,
            },
            status_message: None,
            once: false,
            fail_fast: false,
        };
        let after = allow_hook("runs-after", HookStage::PreProviderCall);
        let out = run_stage_with_config(
            HookStage::PreProviderCall,
            "body",
            &[lenient, after],
            Some(&FailingInvoker),
            false,
        )
        .unwrap();
        match out {
            StageOutcome::Continue { hits, .. } => {
                // Both hooks contribute hits: lenient-plugin records a hit
                // before the invoker is called; runs-after fires normally.
                assert!(
                    hits.contains(&"lenient-plugin".to_string()),
                    "lenient-plugin hit must be recorded even on failure: {hits:?}"
                );
                assert!(
                    hits.contains(&"runs-after".to_string()),
                    "runs-after hook must run because fail_fast=false continues: {hits:?}"
                );
            }
            other => panic!(
                "fail_fast=false must continue on optional plugin failure, got {other:?}"
            ),
        }
    }

    // ── BUG-W2-P1-HOOK-ONCE-PARITY tests ────────────────────────────────────

    fn once_allow_hook(name: &str, stage: HookStage) -> HookDef {
        HookDef {
            name: name.into(),
            stage,
            enabled: Some(true),
            priority: None,
            matcher: None,
            action: HookAction::Allow,
            status_message: None,
            once: true,
            fail_fast: false,
        }
    }

    /// (a) Two concurrent threads sharing one [`SessionOnceGuard`] and calling
    /// `run_stage_with_once_guard` with the same `once = true` hook must result
    /// in exactly one fire and exactly one HOOK_SKIPPED_ONCE signal.
    ///
    /// This is the core concurrency proof: the claim (name inserted into the set)
    /// happens atomically before the effect, so the thread that loses the mutex
    /// race always finds the name present and skips.
    #[test]
    fn once_guard_concurrent_claims_allow_exactly_one_fire() {
        let guard = Arc::new(SessionOnceGuard::new());
        let hook = once_allow_hook("startup-banner", HookStage::PreProviderCall);
        let hooks = vec![hook];

        let guard2 = Arc::clone(&guard);
        let hooks2 = hooks.clone();

        // Spawn two threads; neither is sequenced relative to the other.
        let t1 = std::thread::spawn(move || {
            run_stage_with_once_guard(
                HookStage::PreProviderCall,
                "body",
                &hooks,
                None,
                false,
                &guard,
            )
            .expect("t1 dispatch must not error")
        });
        let t2 = std::thread::spawn(move || {
            run_stage_with_once_guard(
                HookStage::PreProviderCall,
                "body",
                &hooks2,
                None,
                false,
                &guard2,
            )
            .expect("t2 dispatch must not error")
        });

        let r1 = t1.join().expect("t1 panicked");
        let r2 = t2.join().expect("t2 panicked");

        // Collect hits and skipped_once across both results.
        let fires: Vec<_> = (match &r1.outcome {
            StageOutcome::Continue { hits, .. } => hits.as_slice(),
            _ => &[],
        })
        .iter()
        .chain(
            (match &r2.outcome {
                StageOutcome::Continue { hits, .. } => hits.as_slice(),
                _ => &[],
            })
            .iter(),
        )
        .cloned()
        .collect();

        let skips: Vec<_> = r1
            .skipped_once
            .iter()
            .chain(r2.skipped_once.iter())
            .cloned()
            .collect();

        assert_eq!(
            fires.len(),
            1,
            "exactly one thread must fire the once-hook; fires={fires:?}"
        );
        assert_eq!(
            fires[0], "startup-banner",
            "fired hook name must be 'startup-banner'"
        );
        assert_eq!(
            skips.len(),
            1,
            "exactly one HOOK_SKIPPED_ONCE must be signalled; skips={skips:?}"
        );
        assert_eq!(
            skips[0], "startup-banner",
            "skipped hook name must be 'startup-banner'"
        );
    }

    /// (a-repeat) Repeated sequential calls with the same guard must also
    /// enforce once semantics — the second call sees the name already claimed.
    #[test]
    fn once_guard_sequential_second_call_is_skipped() {
        let guard = SessionOnceGuard::new();
        let hooks = vec![once_allow_hook("init-hook", HookStage::PreProviderCall)];

        let r1 = run_stage_with_once_guard(
            HookStage::PreProviderCall,
            "body",
            &hooks,
            None,
            false,
            &guard,
        )
        .unwrap();
        assert!(r1.skipped_once.is_empty(), "first call must not skip");
        match &r1.outcome {
            StageOutcome::Continue { hits, .. } => {
                assert_eq!(hits, &["init-hook"], "first call must fire the hook");
            }
            other => panic!("first call must Continue, got {other:?}"),
        }

        let r2 = run_stage_with_once_guard(
            HookStage::PreProviderCall,
            "body",
            &hooks,
            None,
            false,
            &guard,
        )
        .unwrap();
        assert_eq!(
            r2.skipped_once,
            vec!["init-hook".to_string()],
            "second call must signal HOOK_SKIPPED_ONCE"
        );
        match &r2.outcome {
            StageOutcome::Continue { hits, .. } => {
                assert!(hits.is_empty(), "second call must NOT fire the hook");
            }
            other => panic!("second call must still Continue, got {other:?}"),
        }
    }

    /// (b) PostProviderCall + restoration: the same [`SessionOnceGuard`] is
    /// shared across `PreProviderCall` (where a `BlockFilter` hook redacts
    /// content) and `PostProviderCall` (where a once-hook fires). Proves that
    /// both stages share one dispatcher code path and that `FilteredBlock`s
    /// returned from `PreProviderCall` restore correctly at `PostProviderCall`.
    #[test]
    fn post_provider_call_with_once_guard_and_block_filter_restoration() {
        use super::super::block_filter::restore_blocks;

        let guard = SessionOnceGuard::new();

        // A BlockFilter hook at PreProviderCall redacts annotated regions.
        let pre_hook = HookDef {
            name: "code-simplification".into(),
            stage: HookStage::PreProviderCall,
            enabled: Some(true),
            priority: None,
            matcher: None,
            action: HookAction::BlockFilter {
                start_marker: "// neoth-ignore-start".into(),
                end_marker: "// neoth-ignore-end".into(),
                placeholder: "/* neoth-ignore: {lines} lines (offset {offset}) */\n".into(),
            },
            status_message: None,
            once: true,
            fail_fast: false,
        };
        // A once-Allow hook at PostProviderCall fires on the first response.
        let post_hook = once_allow_hook("post-restore-audit", HookStage::PostProviderCall);

        let all_hooks = vec![pre_hook, post_hook];
        let body =
            "before\n// neoth-ignore-start\nkept complex code\n// neoth-ignore-end\nafter\n";

        // ── PreProviderCall ── redact the ignore region.
        let pre = run_stage_with_once_guard(
            HookStage::PreProviderCall,
            body,
            &all_hooks,
            None,
            false,
            &guard,
        )
        .unwrap();
        assert!(pre.skipped_once.is_empty(), "pre first call must not skip");
        let redacted = match &pre.outcome {
            StageOutcome::Continue { body, hits } => {
                assert!(
                    hits.contains(&"code-simplification".to_string()),
                    "block-filter hook must appear in hits: {hits:?}"
                );
                body.clone()
            }
            other => panic!("pre must Continue, got {other:?}"),
        };
        assert!(
            !redacted.contains("kept complex code"),
            "redacted body must not expose the ignored region"
        );
        let pending_blocks = pre.filtered_blocks;
        assert_eq!(pending_blocks.len(), 1, "one FilteredBlock must be returned");

        // ── PostProviderCall ── once-hook fires; same guard, first time.
        let post1 = run_stage_with_once_guard(
            HookStage::PostProviderCall,
            &redacted,
            &all_hooks,
            None,
            false,
            &guard,
        )
        .unwrap();
        assert!(post1.skipped_once.is_empty(), "first post call must not skip");
        match &post1.outcome {
            StageOutcome::Continue { hits, .. } => {
                assert!(
                    hits.contains(&"post-restore-audit".to_string()),
                    "post-hook must appear in hits on first post call: {hits:?}"
                );
            }
            other => panic!("first post call must Continue, got {other:?}"),
        }

        // ── Restoration ── caller replaces placeholders with originals.
        let restored = restore_blocks(&redacted, &pending_blocks);
        assert!(
            restored.contains("kept complex code"),
            "restored body must contain the original ignored region"
        );
        assert_eq!(
            restored, body,
            "restore_blocks must be a perfect inverse of the BlockFilter action"
        );

        // ── Second PostProviderCall ── once-hook already claimed, must skip.
        let post2 = run_stage_with_once_guard(
            HookStage::PostProviderCall,
            &redacted,
            &all_hooks,
            None,
            false,
            &guard,
        )
        .unwrap();
        assert_eq!(
            post2.skipped_once,
            vec!["post-restore-audit".to_string()],
            "second post call must emit HOOK_SKIPPED_ONCE for the once-hook"
        );
        match &post2.outcome {
            StageOutcome::Continue { hits, .. } => {
                assert!(
                    !hits.contains(&"post-restore-audit".to_string()),
                    "skipped hook must NOT appear in hits on second post call"
                );
            }
            other => panic!("second post call must still Continue, got {other:?}"),
        }

        // ── PreProviderCall second call ── BlockFilter hook also claimed; must skip.
        let pre2 = run_stage_with_once_guard(
            HookStage::PreProviderCall,
            body,
            &all_hooks,
            None,
            false,
            &guard,
        )
        .unwrap();
        assert_eq!(
            pre2.skipped_once,
            vec!["code-simplification".to_string()],
            "second pre call must emit HOOK_SKIPPED_ONCE for the block-filter hook"
        );
        assert!(
            pre2.filtered_blocks.is_empty(),
            "skipped hook must produce no FilteredBlocks"
        );
    }
}
