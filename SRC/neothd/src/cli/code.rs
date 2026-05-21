//! `neoth code <prompt>` — end-to-end V11 coding workflow entry point.
//!
//! Pick #5b per `PLAN/SPEC_coding_workflow.md` build order. Closes
//! the v1.0 ship-blocker chain — operator types one command and gets
//! a decomposed, classified, kanban-tracked session.
//!
//! Flow per the Twitter image's stage diagram:
//!
//! 1. Open session row in `idx_kanban_session` (status=planning).
//! 2. Resolve the Cerebellum hemisphere provider from
//!    `InferenceTopology` + wrap in `CerebellumDecomposer`.
//! 3. Hand off to `coding::decomposer::decompose` — produces tasks,
//!    inserts them via store CRUD, returns ids + complexity rollup.
//! 4. Run heuristic classifier (`coding::classifier::classify_heuristic`)
//!    on each inserted task; persist Left/Right assignment via
//!    `store::patch_task_hemisphere`. Ambiguous tasks stay
//!    `Unassigned` for now — Pick #9 will add LLM second-opinion.
//! 5. Flip session status from `Planning` to `Running`.
//! 6. Print the operator-facing summary (task ids + assignments +
//!    clarifying question if the LLM asked one).

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::Args;
use rusqlite::Connection;

use crate::cli::OutputFormat;
use crate::coding::cerebellum_provider::CerebellumDecomposer;
use crate::coding::classifier::{Complexity, classify_heuristic};
use crate::coding::decomposer::{DecompositionResult, decompose};
use crate::coding::store;
use crate::coding::types::{Hemisphere, KanbanSessionId, KanbanTaskId, SessionStatus};
use crate::config::FreedomConfig;
use crate::config::inference::HemisphereRole;
use crate::memory::store as memstore;
use crate::providers;

#[derive(Args, Debug, Clone)]
pub struct CodeArgs {
    /// Free-text coding request. Wrapped in `<operator_request>` by
    /// the decomposer prompt — no further escaping needed.
    pub prompt: String,
    /// Override `views.db` path. Defaults to `~/.neoth/views.db`.
    #[arg(long, value_name = "PATH")]
    pub db: Option<PathBuf>,
    /// Source channel label for the kanban session (`cli` / `chat` /
    /// `telegram` / `discord` / ...). Defaults to `cli`.
    #[arg(long, default_value = "cli")]
    pub source_channel: String,
    /// Skip the auto-classify + auto-assign step. Useful for
    /// operator-in-loop review of the decomposition before any
    /// hemisphere binding.
    #[arg(long)]
    pub no_assign: bool,
    /// Pick #6 Phase 3 (2026-05-20): after decomposition + assign,
    /// actually run the workers. Without this flag the command stops
    /// at "decomposed into N tasks" and the operator drives dispatch
    /// manually (`neoth kanban move …`). With `--dispatch`, we build
    /// a `HemisphereWorkerSet` from the freedom.yaml provider
    /// bindings and call `dispatch_session()` once. Q1 patch-safety
    /// placeholder applies — workers store patches, do not apply.
    #[arg(long)]
    pub dispatch: bool,
    /// Pick #6 Phase 4 (2026-05-21): also APPLY each worker-
    /// produced patch inside a task-scoped git worktree per the
    /// Chorus verdict (Strategy B). Requires `--dispatch`. The
    /// value is the operator's repo root; the worktree lands at
    /// `<repo_parent>/.neoth-task-<task_id>/` and is left in
    /// place on success so the operator can inspect /
    /// cherry-pick. Without this flag the dispatcher only
    /// stores patches (Phase-3 behaviour preserved).
    #[arg(long, value_name = "REPO_ROOT", requires = "dispatch")]
    pub apply: Option<PathBuf>,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_code(args: CodeArgs) -> Result<()> {
    if args.prompt.trim().is_empty() {
        anyhow::bail!("neoth code: prompt is empty — nothing to decompose");
    }

    let cfg = FreedomConfig::load_from_default_path()
        .context("load freedom.yaml — run `neoth init` first")?;

    let db_path = args.db.clone().unwrap_or_else(memstore::default_path);
    let conn = memstore::open(&db_path).context("open views.db")?;
    store::ensure_schema(&conn).context("ensure kanban schema")?;

    let now_ns = now_unix_ns();
    let prompt_hash = format!(
        "{:016x}",
        xxhash_rust::xxh3::xxh3_64(args.prompt.as_bytes())
    );
    let session_id = store::insert_session(
        &conn,
        now_ns,
        &args.prompt,
        &prompt_hash,
        &args.source_channel,
        cfg.operator_id.as_deref(),
    )
    .context("insert kanban session row")?;

    println!(
        "session #{} opened (channel={})",
        session_id.raw(),
        args.source_channel
    );

    let provider = providers::from_config_for_role(&cfg, HemisphereRole::Cerebellum)
        .await
        .context("resolve cerebellum hemisphere provider")?;
    let llm = CerebellumDecomposer::new(provider);
    println!("cerebellum bound to: {}", llm.provider_name());
    println!("decomposing prompt …");

    let result = decompose(&llm, &conn, session_id, &args.prompt, None, now_ns)
        .await
        .context("decompose prompt via cerebellum")?;

    if result.input_truncated {
        eprintln!("⚠  input was truncated to fit the 12k-token budget");
    }
    if let Some(q) = result.clarifying_question.as_ref() {
        eprintln!("⚠  cerebellum asked a clarifying question:");
        eprintln!("   {q}");
    }

    if result.task_ids.is_empty() {
        // Decomposer surfaced only a clarifying question — flip
        // session to Abandoned so it doesn't sit in Planning forever
        // unless the operator re-runs. Their next `neoth code "..."`
        // opens a fresh session.
        store::archive_session(
            &conn,
            session_id,
            SessionStatus::Abandoned,
            result
                .clarifying_question
                .as_deref()
                .or(Some("decomposer produced no tasks")),
            None,
        )
        .ok();
        println!(
            "(no tasks created — session #{} abandoned)",
            session_id.raw()
        );
        return Ok(());
    }

    println!("decomposed into {} task(s):", result.task_ids.len());

    if !args.no_assign {
        auto_classify_and_assign(&conn, &result)?;
    }

    print_decomposition_summary(&conn, &result)?;

    if args.dispatch {
        run_dispatch_phase(&conn, &cfg, session_id, args.apply.clone()).await?;
    }

    // Session moves out of Planning now that work exists. Pick #6
    // (dispatcher) flips to Running once it actually starts firing
    // workers — for now, we land in Review-equivalent state by
    // leaving the status alone. Operators ALSO see this via
    // `neoth kanban show <session>`.
    Ok(())
}

/// Pick #6 Phase 3 (2026-05-20): build a HemisphereWorkerSet from
/// freedom.yaml provider bindings and run dispatch_session against
/// the just-decomposed kanban session.
///
/// Per-hemisphere provider lookup:
///   Left       -> `from_config_for_role(cfg, HemisphereRole::Left)`
///   Right      -> `from_config_for_role(cfg, HemisphereRole::Right)`
///   Cerebellum -> already-resolved during decompose; we re-resolve
///                 here so the binding is independent of the
///                 decomposer's call site
///   Unassigned -> no worker bound; dispatch_session blocks tasks
///
/// Patch root defaults to the operator's WAL dir parent (~/.neoth).
async fn run_dispatch_phase(
    conn: &Connection,
    cfg: &FreedomConfig,
    session_id: crate::coding::types::KanbanSessionId,
    apply_repo: Option<PathBuf>,
) -> Result<()> {
    use std::sync::Arc;
    use crate::coding::dispatcher::{
        dispatch_session, dispatch_session_with_apply, DispatchApplyConfig, DispatchBudget,
        HemisphereWorkerSet,
    };
    use crate::coding::provider_worker::ProviderWorker;
    use crate::coding::types::Hemisphere;

    let runtime = tokio::runtime::Handle::current();
    let patch_root = FreedomConfig::default_neoth_home();

    let mut workers = HemisphereWorkerSet::new();

    // Left + Right bindings come from the operator's per-hemisphere
    // provider config. Each may legitimately fail (operator only
    // bound one side) — the dispatcher blocks unassigned tasks
    // cleanly. We log the resolution outcome for transparency.
    for (role, hemi, name) in [
        (HemisphereRole::Left, Hemisphere::Left, "left"),
        (HemisphereRole::Right, Hemisphere::Right, "right"),
        (HemisphereRole::Cerebellum, Hemisphere::Cerebellum, "cerebellum"),
    ] {
        match providers::from_config_for_role(cfg, role).await {
            Ok(p) => {
                let provider_name = p.name();
                // Leak a `String` to get `&'static str` for the Worker
                // name. One-off per dispatch invocation — cost is
                // bounded and the audit trail benefits from the
                // hemisphere/provider pair surfaced verbatim.
                let label: &'static str =
                    Box::leak(format!("{name}/{provider_name}").into_boxed_str());
                let worker = ProviderWorker::new(
                    label,
                    Arc::from(p),
                    patch_root.clone(),
                    runtime.clone(),
                );
                workers.bind(hemi, Box::new(worker));
                println!("dispatch: {hemi:?} bound to {label}", hemi = hemi.as_str());
            }
            Err(e) => {
                eprintln!(
                    "⚠  dispatch: {hemi} unbound — {e}. Tasks on this hemisphere \
                     will block.",
                    hemi = hemi.as_str()
                );
            }
        }
    }

    if !workers.has_any() {
        eprintln!("dispatch: no hemisphere has a worker bound — skipping");
        return Ok(());
    }

    // Pick #6 Phase 4: route through the apply-aware variant
    // when the operator passed `--apply <repo>`. Without the
    // flag, legacy semantics (patch stored, never applied).
    let outcome = if let Some(repo) = apply_repo.as_ref() {
        let apply_cfg = DispatchApplyConfig::new(repo);
        println!(
            "dispatch: --apply set; patches will land in <{}>/.neoth-task-<id>/",
            repo.parent().unwrap_or(repo).display()
        );
        dispatch_session_with_apply(
            conn,
            session_id,
            &workers,
            DispatchBudget::default(),
            Some(&apply_cfg),
        )
        .context("dispatch_session_with_apply run")?
    } else {
        dispatch_session(conn, session_id, &workers, DispatchBudget::default())
            .context("dispatch_session run")?
    };

    println!(
        "dispatch: attempted={} completed={} blocked={} unassigned={}{}",
        outcome.tasks_attempted,
        outcome.tasks_completed,
        outcome.tasks_blocked,
        outcome.tasks_unassigned,
        if outcome.budget_exhausted {
            "  (budget exhausted)"
        } else {
            ""
        }
    );
    Ok(())
}

/// Classify every inserted task heuristically + persist the hemisphere
/// assignment. Tasks the heuristic marks `Ambiguous` stay
/// `Unassigned` — Pick #9 will add the LLM second-opinion step.
fn auto_classify_and_assign(conn: &Connection, result: &DecompositionResult) -> Result<()> {
    let tasks = collect_tasks(conn, &result.task_ids)?;
    let mut assigned = 0usize;
    let mut ambiguous = 0usize;
    for task in &tasks {
        let complexity = classify_heuristic(task);
        match complexity {
            Complexity::Fast | Complexity::Deep => {
                let hemi = complexity.to_hemisphere();
                store::patch_task_hemisphere(conn, task.task_id, hemi, None, None).with_context(
                    || {
                        format!(
                            "patch hemisphere on task #{} → {}",
                            task.task_id.raw(),
                            hemi.as_str(),
                        )
                    },
                )?;
                assigned += 1;
            }
            Complexity::Ambiguous => {
                ambiguous += 1;
            }
        }
    }
    if assigned + ambiguous > 0 {
        println!(
            "classified: {assigned} assigned (heuristic), {ambiguous} ambiguous \
             (deferred to LLM second-opinion — Pick #9)"
        );
    }
    Ok(())
}

/// Load each inserted task by id (in insertion order). Pulls one
/// roundtrip per task — fine for the typical 1-10 task batch a
/// decomposition produces. Larger sessions would benefit from a
/// batched WHERE-IN; punt that until profiling demands it.
fn collect_tasks(
    conn: &Connection,
    task_ids: &[KanbanTaskId],
) -> Result<Vec<crate::coding::types::KanbanTask>> {
    if task_ids.is_empty() {
        return Ok(Vec::new());
    }
    // Resolve via session_id from the first task — same approach as
    // `neoth kanban show`. All tasks in a `decompose` batch share
    // one session by construction.
    let first = task_ids[0];
    let session_id: i64 = conn
        .query_row(
            "SELECT session_id FROM idx_kanban_task WHERE task_id = ?1",
            [first.raw()],
            |row| row.get(0),
        )
        .with_context(|| format!("look up session for task #{}", first.raw()))?;
    let tasks = store::list_tasks_for_session(conn, KanbanSessionId(session_id))
        .context("list tasks in session")?;
    // Filter to just the newly-inserted ids (existing tasks in the
    // session, if any, are NOT re-classified by this call).
    let want: std::collections::HashSet<i64> = task_ids.iter().map(|t| t.raw()).collect();
    Ok(tasks
        .into_iter()
        .filter(|t| want.contains(&t.task_id.raw()))
        .collect())
}

/// Print operator-readable line per task. Mirrors the format used by
/// `neoth kanban show` so muscle memory carries across commands.
fn print_decomposition_summary(conn: &Connection, result: &DecompositionResult) -> Result<()> {
    let tasks = collect_tasks(conn, &result.task_ids)?;
    if tasks.is_empty() {
        return Err(anyhow!(
            "no tasks found for ids {:?} — store/insert inconsistency",
            result.task_ids
        ));
    }
    for t in &tasks {
        let hemi_label = match t.hemisphere {
            Hemisphere::Left => "→ LEFT  (fast)",
            Hemisphere::Right => "→ RIGHT (deep)",
            Hemisphere::Cerebellum => "→ CEREBELLUM",
            Hemisphere::Unassigned => "  unassigned",
        };
        println!(
            "  #{:>4}  [{:>8}]  {}  {}",
            t.task_id.raw(),
            t.task_type,
            hemi_label,
            t.title,
        );
    }
    println!();
    println!(
        "estimated complexity: {}",
        result.session_complexity.as_str()
    );
    println!(
        "next: `neoth kanban show {}` to inspect, `neoth kanban watch` for the activity feed",
        tasks[0].session_id.raw(),
    );
    Ok(())
}

fn now_unix_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fresh_db() -> (tempfile::TempDir, Connection) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("views.db");
        let conn = memstore::open(&path).expect("open");
        store::ensure_schema(&conn).expect("schema");
        (dir, conn)
    }

    #[test]
    fn collect_tasks_returns_only_requested_ids_in_order() {
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let t1 = store::insert_task(&conn, s, 10, "first", None, "ui", None).unwrap();
        let t2 = store::insert_task(&conn, s, 11, "second", None, "store", None).unwrap();
        // A third task in the same session that we should NOT pick up.
        let _t3 = store::insert_task(&conn, s, 12, "stale", None, "tests", None).unwrap();

        let tasks = collect_tasks(&conn, &[t1, t2]).expect("collect");
        let ids: Vec<i64> = tasks.iter().map(|t| t.task_id.raw()).collect();
        assert!(ids.contains(&t1.raw()));
        assert!(ids.contains(&t2.raw()));
        assert!(
            !ids.contains(&_t3.raw()),
            "stale task must NOT be re-classified"
        );
        assert_eq!(tasks.len(), 2);
    }

    #[test]
    fn collect_tasks_empty_input_yields_empty_output() {
        let (_dir, conn) = fresh_db();
        let tasks = collect_tasks(&conn, &[]).expect("empty");
        assert!(tasks.is_empty());
    }

    #[test]
    fn auto_classify_assigns_fast_signal_to_left() {
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let t = store::insert_task(&conn, s, 10, "Add toggle UI in settings", None, "ui", None)
            .unwrap();
        let result = DecompositionResult {
            task_ids: vec![t],
            clarifying_question: None,
            session_complexity: crate::coding::decomposer::SessionComplexity::Fast,
            input_truncated: false,
        };
        auto_classify_and_assign(&conn, &result).expect("classify ok");

        let tasks = store::list_tasks_for_session(&conn, s).unwrap();
        let fetched = tasks.into_iter().find(|x| x.task_id == t).unwrap();
        assert_eq!(fetched.hemisphere, Hemisphere::Left);
    }

    #[test]
    fn auto_classify_assigns_deep_signal_to_right() {
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        let t = store::insert_task(
            &conn,
            s,
            10,
            "Architecture review for the auth flow",
            None,
            "refactor",
            None,
        )
        .unwrap();
        let result = DecompositionResult {
            task_ids: vec![t],
            clarifying_question: None,
            session_complexity: crate::coding::decomposer::SessionComplexity::Deep,
            input_truncated: false,
        };
        auto_classify_and_assign(&conn, &result).expect("classify ok");

        let tasks = store::list_tasks_for_session(&conn, s).unwrap();
        let fetched = tasks.into_iter().find(|x| x.task_id == t).unwrap();
        assert_eq!(fetched.hemisphere, Hemisphere::Right);
    }

    #[test]
    fn auto_classify_leaves_ambiguous_unassigned() {
        let (_dir, conn) = fresh_db();
        let s = store::insert_session(&conn, 1, "p", "h", "cli", None).unwrap();
        // "Implement the foo widget" — neither FAST nor DEEP signal
        // hits, so the classifier returns Ambiguous.
        let t = store::insert_task(
            &conn,
            s,
            10,
            "Implement the foo widget",
            None,
            "refactor",
            None,
        )
        .unwrap();
        let result = DecompositionResult {
            task_ids: vec![t],
            clarifying_question: None,
            session_complexity: crate::coding::decomposer::SessionComplexity::Mixed,
            input_truncated: false,
        };
        auto_classify_and_assign(&conn, &result).expect("classify ok");

        let tasks = store::list_tasks_for_session(&conn, s).unwrap();
        let fetched = tasks.into_iter().find(|x| x.task_id == t).unwrap();
        assert_eq!(
            fetched.hemisphere,
            Hemisphere::Unassigned,
            "ambiguous tasks must stay unassigned — Pick #9 escalates to LLM"
        );
    }
}
