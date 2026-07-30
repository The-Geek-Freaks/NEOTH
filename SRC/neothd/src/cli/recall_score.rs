//! `neoth recall-score` — ARCH-05/SPEC-08 recall-parity gate runner.
//!
//! The operator-facing entry to the legacy-AI→NEOTH migration gate. Loads the
//! grader sheets (NEOTH + reference, scored offline by the 4-grader protocol),
//! computes the inter-rater kappa + kappa-adjusted weighted-harmonic parity +
//! per-query CRITICAL divergences, prints the report, emits a WAL
//! `0x3E EVAL_CRITICAL_DIVERGENCE` per flagged query (durable abort evidence),
//! and **exits non-zero if the gate fails** so a cutover script can gate on it.
//!
//! 100% offline: it scores grade FILES — no live legacy-AI, no LLM, no grading
//! here (the grading is the operator's run; the file format is the contract).

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;

use crate::cli::OutputFormat;
use crate::recall::goldset::{GraderGrade, load_goldset, load_grades};
use crate::recall::parity_run::{ParityRunResult, compute_parity_run};

#[derive(Args, Debug, Clone)]
pub struct RecallScoreArgs {
    /// Grader-sheet JSONL file(s) (each line a GraderGrade: query_id, grader_id,
    /// system, 5×Likert). Pass one per grader; all are merged. Need ≥ 2 graders.
    #[arg(long = "grades", required = true, num_args = 1..)]
    pub grades: Vec<PathBuf>,
    /// Optional goldset JSONL — validated + its query count reported (the
    /// scoring runs off the grades, not the goldset).
    #[arg(long)]
    pub goldset: Option<PathBuf>,
    /// Don't emit `0x3E` WAL frames (dry scoring; the report still prints).
    #[arg(long)]
    pub no_audit: bool,
    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_recall_score(args: RecallScoreArgs) -> Result<()> {
    let mut all_grades: Vec<GraderGrade> = Vec::new();
    for path in &args.grades {
        let g = load_grades(path).with_context(|| format!("load grades {}", path.display()))?;
        all_grades.extend(g);
    }

    // Goldset coverage gate (fail-closed): if a goldset is supplied, EVERY one
    // of its queries must be graded for BOTH systems — otherwise the gate would
    // silently score a subset and a missing-coverage hole could mask a failing
    // query (review HIGH). No goldset ⇒ score whatever grades cover.
    if let Some(gs) = &args.goldset {
        let entries = load_goldset(gs).with_context(|| "load --goldset")?;
        let graded: std::collections::BTreeSet<(&str, bool)> = all_grades
            .iter()
            .map(|g| {
                (
                    g.query_id.as_str(),
                    matches!(g.system, crate::recall::goldset::GradedSystem::Neoth),
                )
            })
            .collect();
        let missing: Vec<&str> = entries
            .iter()
            .filter(|e| {
                !graded.contains(&(e.query_id.as_str(), true))
                    || !graded.contains(&(e.query_id.as_str(), false))
            })
            .map(|e| e.query_id.as_str())
            .collect();
        if !missing.is_empty() {
            anyhow::bail!(
                "goldset coverage incomplete: {} of {} queries lack grades for both systems (e.g. {}). \
                 The gate refuses to score a subset.",
                missing.len(),
                entries.len(),
                missing
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if matches!(args.output, OutputFormat::Table) {
            println!("# goldset: {} queries, full coverage", entries.len());
        }
    }

    let result = compute_parity_run(&all_grades).context("compute parity run")?;

    let mut audit_incomplete = false;
    if !args.no_audit && !result.critical_queries.is_empty() {
        audit_incomplete = !emit_critical_divergences(&result).await;
    }

    render(&result, &args.output);

    if audit_incomplete {
        // The CRITICAL audit (0x3E) could not be fully written — surface it
        // loudly. The gate verdict below still holds, but the durable evidence
        // is incomplete, which the operator must know before any cutover call.
        tracing::error!(
            "recall-score: one or more 0x3E CRITICAL audit frames FAILED to write — \
             the durable abort evidence is INCOMPLETE; do not cut over on this run"
        );
    }

    // The gate is the contract: a failed run is a non-zero exit so a cutover
    // script + CI hard-gate on it. The reason names WHICH gate failed.
    if !result.verdict.passed {
        anyhow::bail!(
            "recall-parity gate FAILED — aggregate {:.4} (>= {:.2}? {}), absolute floors met? {}, \
             mean kappa {:.4} (>= 0.60? {}), {} CRITICAL divergence(s)",
            result.verdict.aggregate,
            result.verdict.threshold,
            result.verdict.aggregate >= result.verdict.threshold,
            result.verdict.absolute_floors_met,
            result.mean_kappa,
            result.verdict.kappa_gate_met,
            result.verdict.critical_count,
        );
    }
    Ok(())
}

fn render(r: &ParityRunResult, output: &OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let body = serde_json::json!({
                "aggregate": r.aggregate,
                "threshold": r.verdict.threshold,
                "mean_kappa": r.mean_kappa,
                "passed": r.verdict.passed,
                "critical_count": r.verdict.critical_count,
                "dimension_kappas": r.dimension_kappas.iter()
                    .map(|(d, k)| serde_json::json!({ "dimension": d.as_str(), "kappa": k }))
                    .collect::<Vec<_>>(),
                "dimension_parity_kappa": r.dimension_parity_kappa.iter()
                    .map(|(d, p)| serde_json::json!({ "dimension": d.as_str(), "parity_kappa": p }))
                    .collect::<Vec<_>>(),
                "absolute_floors": r.absolute_floors.iter()
                    .map(|(d, mean)| serde_json::json!({
                        "dimension": d.as_str(), "mean_neoth_score": mean, "floor": d.absolute_floor()
                    }))
                    .collect::<Vec<_>>(),
                "absolute_floors_met": r.verdict.absolute_floors_met,
                "kappa_gate_met": r.verdict.kappa_gate_met,
                "min_pairwise_kappa": r.min_pairwise_kappa,
                "critical_queries": r.critical_queries.iter()
                    .map(|c| serde_json::json!({
                        "query_id": c.query_id, "reason": format!("{:?}", c.reason),
                        "factual_parity_kappa": c.factual_parity_kappa,
                        "usefulness_parity_kappa": c.usefulness_parity_kappa,
                    }))
                    .collect::<Vec<_>>(),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&body)
                    .expect("recall score report is infallible JSON")
            );
        }
        OutputFormat::Table => {
            println!("# Recall-parity gate (ARCH-05 / SPEC-08)");
            println!(
                "  verdict       : {}",
                if r.verdict.passed { "PASS" } else { "FAIL" }
            );
            println!(
                "  aggregate     : {:.4}  (>= {:.2})",
                r.aggregate, r.verdict.threshold
            );
            println!(
                "  mean kappa    : {:.4}  (>= 0.60 reliability: {})",
                r.mean_kappa, r.verdict.kappa_gate_met
            );
            println!("  absolute floors met: {}", r.verdict.absolute_floors_met);
            println!("  CRITICAL      : {}", r.verdict.critical_count);
            println!("  per dimension :");
            for ((d, k), (_, pk)) in r
                .dimension_kappas
                .iter()
                .zip(r.dimension_parity_kappa.iter())
            {
                println!(
                    "    {:<13} kappa={:.3}  parity_kappa={:.3}",
                    d.as_str(),
                    k,
                    pk
                );
            }
            println!("  absolute floors (mean NEOTH score vs floor):");
            for (d, mean) in &r.absolute_floors {
                let ok = if *mean >= d.absolute_floor() {
                    "ok"
                } else {
                    "FAIL"
                };
                println!(
                    "    {:<13} {:.2} / {:.1}  {ok}",
                    d.as_str(),
                    mean,
                    d.absolute_floor()
                );
            }
            if !r.critical_queries.is_empty() {
                println!("  CRITICAL queries (a single one aborts cutover):");
                for c in &r.critical_queries {
                    println!("    {}: {:?}", c.query_id, c.reason);
                }
            }
        }
    }
}

/// Emit one `0x3E EVAL_CRITICAL_DIVERGENCE` per CRITICAL query (HF-01 one-shot
/// pattern: skip if `neothd serve` owns the WAL; else open one writer for the
/// batch). Returns `true` when EVERY frame was durably enqueued — `false` if
/// any local append/flush failed, the writer couldn't open, or the live daemon
/// did not acknowledge an audit-RPC frame (the caller surfaces that the abort
/// evidence is incomplete).
async fn emit_critical_divergences(r: &ParityRunResult) -> bool {
    let now = now_unix();
    let home = crate::config::FreedomConfig::default_neoth_home();
    let pidfile = home.join("neothd.pid");
    let daemon_live = match crate::daemon::pidfile::live_daemon_pid(&pidfile) {
        Ok(pid) => pid.is_some(),
        Err(e) => {
            tracing::warn!(
                error = %e,
                pidfile = %pidfile.display(),
                "recall-score: audit ownership is uncertain; refusing a local WAL writer"
            );
            return false;
        }
    };
    if daemon_live {
        // AUDIT-RPC-01: daemon owns the WAL → forward each 0x3E frame over the
        // same-user OS channel instead of silently skipping.
        let mut all_ok = true;
        for c in &r.critical_queries {
            let payload = serde_json::json!({
                "query_id": c.query_id,
                "reason": format!("{:?}", c.reason),
                "factual_parity_kappa": c.factual_parity_kappa,
                "usefulness_parity_kappa": c.usefulness_parity_kappa,
                "ts_unix": now,
            })
            .to_string()
            .into_bytes();
            if let Err(e) = crate::daemon::audit_rpc::try_post_audit_frame(
                &home,
                crate::wal::events::EVENT_TYPE_EVAL_CRITICAL_DIVERGENCE,
                &payload,
            )
            .await
            {
                tracing::debug!(error = %e, "recall-score: 0x3E forward skipped (daemon listener unreachable)");
                all_ok = false;
            }
        }
        return all_ok;
    }
    let wal_dir = home.join("wal");
    if let Err(e) = std::fs::create_dir_all(&wal_dir) {
        tracing::warn!(
            error = %e,
            wal_dir = %wal_dir.display(),
            "recall-score: could not create WAL directory for 0x3E"
        );
        return false;
    }
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "recall-critical");
    let mut all_ok = true;
    match crate::wal::writer::spawn_for_home_with_completion(segment, home) {
        Ok((writer, completion)) => {
            for c in &r.critical_queries {
                let payload = serde_json::json!({
                    "query_id": c.query_id,
                    "reason": format!("{:?}", c.reason),
                    "factual_parity_kappa": c.factual_parity_kappa,
                    "usefulness_parity_kappa": c.usefulness_parity_kappa,
                    "ts_unix": now,
                })
                .to_string()
                .into_bytes();
                let header = crate::wal::HeaderBuilder::new(
                    crate::wal::events::EVENT_TYPE_EVAL_CRITICAL_DIVERGENCE,
                    &payload,
                )
                .build();
                if let Err(e) = writer.append(header, payload).await {
                    tracing::warn!(error = %e, "recall-score: 0x3E append failed");
                    all_ok = false;
                }
            }
            drop(writer);
            if let Err(e) = completion.wait().await {
                tracing::warn!(error = %e, "recall-score: 0x3E WAL writer finalization failed");
                all_ok = false;
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "recall-score: could not open WAL writer for 0x3E");
            all_ok = false;
        }
    }
    all_ok
}

fn now_unix() -> i64 {
    crate::time::now_unix_i64()
}
