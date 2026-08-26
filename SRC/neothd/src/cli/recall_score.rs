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

use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::recall::goldset::{
    GoldsetEntry, GraderGrade, load_goldset, load_grader_config, load_grades,
};
use crate::recall::parity_run::{ParityRunResult, compute_parity_run};
use crate::recall::{
    goldset::{MAX_GOLDSET_BYTES, MAX_GRADER_CONFIG_BYTES},
    parity_harness::{
        build_report, ingest_offline_grades, ingest_operator_anchor_evidence, plan_four_grader_batch,
        plan_run, read_offline_input, validate_attested_four_grader_batch_results,
        ingest_attested_four_grader_batch_results,
    },
    parity_anchor::{
        MAX_OPERATOR_ANCHOR_EVIDENCE_LINK_BYTES, load_operator_anchor_bytes,
        summarize_operator_anchor,
    },
    parity_candidate_evidence::{load_imported_candidate_evidence, summarize_candidate_evidence},
    parity_import_receipt::{MAX_PARITY_IMPORT_RECEIPT_BYTES, parse_signed_parity_import_receipt},
    parity_batch_plan::{MAX_FOUR_GRADER_BATCH_BYTES, parse_signed_four_grader_batch_result_receipt},
};

#[derive(Args, Debug, Clone)]
pub struct RecallScoreArgs {
    /// Grader-sheet JSONL file(s) (each line a GraderGrade: query_id, grader_id,
    /// system, 5×Likert). Supply no more files than configured graders; all
    /// records are merged. Every configured grader must cover every query/system.
    #[arg(long = "grades", required = true, num_args = 1..)]
    pub grades: Vec<PathBuf>,
    /// Versioned grader roster JSON. Required: binds submitted grader IDs to
    /// validated provider/family/model metadata and requires an independent
    /// external family. This is metadata only, not provenance evidence.
    #[arg(long, required = true, value_name = "PATH")]
    pub grader_config: PathBuf,
    /// Goldset JSONL. Required: exactly 100 unique canonical query IDs must
    /// match submitted grade query IDs; partial or extra grading fails.
    #[arg(long, required = true, value_name = "PATH")]
    pub goldset: PathBuf,
    /// Don't emit `0x3E` WAL frames (dry scoring; the report still prints).
    #[arg(long)]
    pub no_audit: bool,
    #[arg(skip)]
    pub output: OutputFormat,
}

/// GOLD-LF-P1-08 — fully offline evaluation-run evidence pipeline. Every
/// operation requires explicit local inputs; it has no provider, network, or
/// WAL authority, and its derived report cannot replace `recall-score`'s gate.
#[derive(Args, Debug, Clone)]
pub struct RecallParityHarnessArgs {
    #[command(subcommand)]
    pub operation: RecallParityHarnessOperation,
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum RecallParityHarnessOperation {
    /// Bind a fresh run directory to exact validated config/goldset bytes.
    Plan {
        #[arg(long, value_name = "DIR")]
        run_dir: PathBuf,
        #[arg(long, value_name = "PATH")]
        grader_config: PathBuf,
        #[arg(long, value_name = "PATH")]
        goldset: PathBuf,
    },
    /// Ingest one complete, explicit, offline grade sheet for exactly one grader.
    Ingest {
        #[arg(long, value_name = "DIR")]
        run_dir: PathBuf,
        #[arg(long, value_name = "PATH")]
        grader_config: PathBuf,
        #[arg(long, value_name = "PATH")]
        goldset: PathBuf,
        #[arg(long, value_name = "PATH")]
        grades: PathBuf,
    },
    /// Compute the deterministic family-bias report once all graders are imported.
    Report {
        #[arg(long, value_name = "DIR")]
        run_dir: PathBuf,
        #[arg(long, value_name = "PATH")]
        grader_config: PathBuf,
        #[arg(long, value_name = "PATH")]
        goldset: PathBuf,
        /// Externally held signed receipt binding the complete import vector.
        #[arg(long = "import-receipt", value_name = "PATH")]
        import_receipt: PathBuf,
        /// Out-of-band Ed25519 receipt public key (base64); never read from run state.
        #[arg(long = "expected-receipt-pubkey", value_name = "BASE64")]
        expected_receipt_pubkey: String,
    },
    /// Recompute and render a run from trusted config/goldset inputs. The
    /// operation remains offline and never changes the established gate.
    Show {
        #[arg(long, value_name = "DIR")]
        run_dir: PathBuf,
        #[arg(long, value_name = "PATH")]
        grader_config: PathBuf,
        #[arg(long, value_name = "PATH")]
        goldset: PathBuf,
        /// Externally held signed receipt binding the complete import vector.
        #[arg(long = "import-receipt", value_name = "PATH")]
        import_receipt: PathBuf,
        /// Out-of-band Ed25519 receipt public key (base64); never read from run state.
        #[arg(long = "expected-receipt-pubkey", value_name = "BASE64")]
        expected_receipt_pubkey: String,
    },
    /// Validate the operator's 20-query × two-system calibration labels before
    /// they can be used for a later anchored family-bias correction.
    AnchorValidate {
        #[arg(long, value_name = "PATH")]
        grader_config: PathBuf,
        #[arg(long, value_name = "PATH")]
        goldset: PathBuf,
        #[arg(long = "operator-anchor", value_name = "PATH")]
        operator_anchor: PathBuf,
    },
    /// Verify a bounded imported transcript/WAL candidate-evidence bundle and
    /// render only its redacted provenance receipt. Candidates remain in the
    /// operator-labeling queue and cannot enter a parity gate from this command.
    CandidateEvidenceValidate {
        #[arg(long = "evidence-dir", value_name = "DIR")]
        evidence_dir: PathBuf,
        /// Out-of-band Ed25519 public key for the immutable candidate-evidence
        /// receipt. The key is never accepted from the mutable evidence bundle.
        #[arg(long = "expected-evidence-receipt-pubkey", value_name = "BASE64")]
        expected_evidence_receipt_pubkey: String,
    },
    /// Bind one complete 20-query × two-system operator-anchor label set to a
    /// previously signature-verified candidate-evidence bundle. The resulting
    /// run artifact remains non-gate-eligible and contains no raw source text.
    AnchorIngest {
        #[arg(long, value_name = "DIR")]
        run_dir: PathBuf,
        #[arg(long, value_name = "PATH")]
        grader_config: PathBuf,
        #[arg(long, value_name = "PATH")]
        goldset: PathBuf,
        #[arg(long = "evidence-dir", value_name = "DIR")]
        evidence_dir: PathBuf,
        #[arg(long = "expected-evidence-receipt-pubkey", value_name = "BASE64")]
        expected_evidence_receipt_pubkey: String,
        #[arg(long = "operator-anchor", value_name = "PATH")]
        operator_anchor: PathBuf,
        #[arg(long = "operator-anchor-link", value_name = "PATH")]
        operator_anchor_link: PathBuf,
    },
    /// Persist an offline-only execution plan for exactly four validated
    /// graders. It exports hashes, never prompts, credentials, or provider work.
    BatchPlan {
        #[arg(long, value_name = "DIR")]
        run_dir: PathBuf,
        #[arg(long, value_name = "PATH")]
        grader_config: PathBuf,
        #[arg(long, value_name = "PATH")]
        goldset: PathBuf,
        #[arg(long = "batch-input-digests", value_name = "PATH")]
        batch_input_digests: PathBuf,
    },
    /// Verify four externally produced grade files against an immutable batch
    /// plan and a detached out-of-band Ed25519 result receipt. This command
    /// does not dispatch providers, ingest grades, or change a gate.
    BatchResultsVerify {
        #[arg(long, value_name = "DIR")]
        run_dir: PathBuf,
        #[arg(long, value_name = "PATH")]
        grader_config: PathBuf,
        #[arg(long, value_name = "PATH")]
        goldset: PathBuf,
        #[arg(long = "batch-result-receipt", value_name = "PATH")]
        batch_result_receipt: PathBuf,
        #[arg(long = "expected-batch-result-pubkey", value_name = "BASE64")]
        expected_batch_result_pubkey: String,
        #[arg(long = "result", required = true, num_args = 4, value_name = "PATH")]
        results: Vec<PathBuf>,
    },
    /// Persist four externally attested offline grade matrices into an
    /// existing batch-planned run. No provider is invoked by this transition.
    BatchResultsIngest {
        #[arg(long, value_name = "DIR")]
        run_dir: PathBuf,
        #[arg(long, value_name = "PATH")]
        grader_config: PathBuf,
        #[arg(long, value_name = "PATH")]
        goldset: PathBuf,
        #[arg(long = "batch-result-receipt", value_name = "PATH")]
        batch_result_receipt: PathBuf,
        #[arg(long = "expected-batch-result-pubkey", value_name = "BASE64")]
        expected_batch_result_pubkey: String,
        #[arg(long = "result", required = true, num_args = 4, value_name = "PATH")]
        results: Vec<PathBuf>,
    },
}

pub async fn run_recall_parity_harness(args: RecallParityHarnessArgs) -> Result<()> {
    let output = args.output;
    let operation = args.operation;
    if let RecallParityHarnessOperation::CandidateEvidenceValidate {
        evidence_dir,
        expected_evidence_receipt_pubkey,
    } = &operation {
        let evidence = load_imported_candidate_evidence(evidence_dir, expected_evidence_receipt_pubkey)?;
        render_harness_json(&summarize_candidate_evidence(&evidence), &output)?;
        return Ok(());
    }
    let (grader_config, goldset) = match &operation {
        RecallParityHarnessOperation::Plan { grader_config, goldset, .. }
        | RecallParityHarnessOperation::Ingest { grader_config, goldset, .. }
        | RecallParityHarnessOperation::Report { grader_config, goldset, .. }
        | RecallParityHarnessOperation::Show { grader_config, goldset, .. }
        | RecallParityHarnessOperation::AnchorValidate { grader_config, goldset, .. }
        | RecallParityHarnessOperation::AnchorIngest { grader_config, goldset, .. }
        | RecallParityHarnessOperation::BatchPlan { grader_config, goldset, .. }
        | RecallParityHarnessOperation::BatchResultsVerify { grader_config, goldset, .. }
        | RecallParityHarnessOperation::BatchResultsIngest { grader_config, goldset, .. } => {
            (grader_config, goldset)
        }
        RecallParityHarnessOperation::CandidateEvidenceValidate { .. } => {
            unreachable!("candidate evidence returns before config/goldset input loading")
        }
    };
            let config_bytes = read_offline_input(grader_config, MAX_GRADER_CONFIG_BYTES, "grader config")?;
            let goldset_bytes = read_offline_input(goldset, MAX_GOLDSET_BYTES, "goldset")?;
            let config = crate::recall::goldset::load_grader_config_bytes(&config_bytes, "harness --grader-config")?;
            let entries = crate::recall::goldset::load_goldset_bytes(&goldset_bytes, "harness --goldset")?;
            match operation {
                RecallParityHarnessOperation::Plan { run_dir, .. } => {
                    let manifest = plan_run(&run_dir, &config, &config_bytes, &entries, &goldset_bytes)?;
                    render_harness_json(&manifest, &output)?;
                }
                RecallParityHarnessOperation::Ingest { run_dir, grades, .. } => {
                    let grade_bytes = read_offline_input(&grades, crate::recall::goldset::MAX_GRADES_BYTES, "grade sheet")?;
                    let state = ingest_offline_grades(&run_dir, &config, &config_bytes, &entries, &goldset_bytes, &grade_bytes)?;
                    render_harness_json(&state, &output)?;
                }
                RecallParityHarnessOperation::Report { run_dir, import_receipt, expected_receipt_pubkey, .. } => {
                    let receipt_bytes = read_offline_input(&import_receipt, MAX_PARITY_IMPORT_RECEIPT_BYTES as u64, "signed parity import receipt")?;
                    let signed_receipt = parse_signed_parity_import_receipt(&receipt_bytes)?;
                    let report = build_report(&run_dir, &config, &config_bytes, &entries, &goldset_bytes, &signed_receipt, &expected_receipt_pubkey)?;
                    render_harness_json(&report, &output)?;
                }
                RecallParityHarnessOperation::Show { run_dir, import_receipt, expected_receipt_pubkey, .. } => {
                    // Do not treat a mutable run-directory checksum as a trust
                    // anchor. Rebuilding binds the displayed evidence to the
                    // explicitly supplied, freshly validated config/goldset.
                    let receipt_bytes = read_offline_input(&import_receipt, MAX_PARITY_IMPORT_RECEIPT_BYTES as u64, "signed parity import receipt")?;
                    let signed_receipt = parse_signed_parity_import_receipt(&receipt_bytes)?;
                    let report = build_report(&run_dir, &config, &config_bytes, &entries, &goldset_bytes, &signed_receipt, &expected_receipt_pubkey)?;
                    render_harness_json(&report, &output)?;
                }
                RecallParityHarnessOperation::AnchorValidate { operator_anchor, .. } => {
                    let anchor_bytes = read_offline_input(
                        &operator_anchor,
                        crate::recall::goldset::MAX_GRADES_BYTES,
                        "operator anchor labels",
                    )?;
                    let anchor = load_operator_anchor_bytes(
                        &anchor_bytes,
                        "harness --operator-anchor",
                        &entries,
                        &config,
                    )?;
                    render_harness_json(&summarize_operator_anchor(&anchor, &anchor_bytes), &output)?;
                }
                RecallParityHarnessOperation::AnchorIngest {
                    run_dir,
                    evidence_dir,
                    expected_evidence_receipt_pubkey,
                    operator_anchor,
                    operator_anchor_link,
                    ..
                } => {
                    let candidate_evidence = load_imported_candidate_evidence(
                        &evidence_dir,
                        &expected_evidence_receipt_pubkey,
                    )?;
                    let anchor_bytes = read_offline_input(
                        &operator_anchor,
                        crate::recall::goldset::MAX_GRADES_BYTES,
                        "operator anchor labels",
                    )?;
                    let link_bytes = read_offline_input(
                        &operator_anchor_link,
                        MAX_OPERATOR_ANCHOR_EVIDENCE_LINK_BYTES as u64,
                        "operator anchor evidence link",
                    )?;
                    let binding = ingest_operator_anchor_evidence(
                        &run_dir,
                        &config,
                        &config_bytes,
                        &entries,
                        &goldset_bytes,
                        &candidate_evidence,
                        &anchor_bytes,
                        &link_bytes,
                    )?;
                    render_harness_json(&binding, &output)?;
                }
                RecallParityHarnessOperation::BatchPlan {
                    run_dir, batch_input_digests, ..
                } => {
                    let input_bytes = read_offline_input(
                        &batch_input_digests,
                        MAX_FOUR_GRADER_BATCH_BYTES as u64,
                        "four-grader batch input digests",
                    )?;
                    let plan = plan_four_grader_batch(
                        &run_dir, &config, &config_bytes, &entries, &goldset_bytes, &input_bytes,
                    )?;
                    render_harness_json(&plan.export()?, &output)?;
                }
                RecallParityHarnessOperation::BatchResultsVerify {
                    run_dir, batch_result_receipt, expected_batch_result_pubkey, results, ..
                } => {
                    let receipt_bytes = read_offline_input(
                        &batch_result_receipt,
                        MAX_FOUR_GRADER_BATCH_BYTES as u64,
                        "signed four-grader batch result receipt",
                    )?;
                    let receipt = parse_signed_four_grader_batch_result_receipt(&receipt_bytes)?;
                    let result_bytes = results.iter().map(|path| read_offline_input(
                        path, crate::recall::goldset::MAX_GRADES_BYTES, "attested four-grader result",
                    )).collect::<Result<Vec<_>>>()?;
                    let summary = validate_attested_four_grader_batch_results(
                        &run_dir, &config, &config_bytes, &entries, &goldset_bytes,
                        &receipt, &expected_batch_result_pubkey, &result_bytes,
                    )?;
                    render_harness_json(&summary, &output)?;
                }
                RecallParityHarnessOperation::BatchResultsIngest {
                    run_dir, batch_result_receipt, expected_batch_result_pubkey, results, ..
                } => {
                    let receipt_bytes = read_offline_input(
                        &batch_result_receipt,
                        MAX_FOUR_GRADER_BATCH_BYTES as u64,
                        "signed four-grader batch result receipt",
                    )?;
                    let receipt = parse_signed_four_grader_batch_result_receipt(&receipt_bytes)?;
                    let result_bytes = results.iter().map(|path| read_offline_input(
                        path, crate::recall::goldset::MAX_GRADES_BYTES, "attested four-grader result",
                    )).collect::<Result<Vec<_>>>()?;
                    let binding = ingest_attested_four_grader_batch_results(
                        &run_dir, &config, &config_bytes, &entries, &goldset_bytes,
                        &receipt, &expected_batch_result_pubkey, &result_bytes,
                    )?;
                    render_harness_json(&binding, &output)?;
                }
                RecallParityHarnessOperation::CandidateEvidenceValidate { .. } => {
                    unreachable!("candidate evidence returns before config/goldset input loading")
                }
            }
    Ok(())
}

fn render_harness_json<T: serde::Serialize>(value: &T, output: &OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(value).context("serialize harness JSON output")?);
        }
        OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string(value).context("serialize harness JSONL output")?);
        }
        OutputFormat::Table => {
            let fields = serde_json::to_value(value).context("serialize harness table output")?;
            let object = fields.as_object().context("harness output must serialize as an object")?;
            println!("# Recall-parity harness");
            for (field, field_value) in object {
                let rendered = serde_json::to_string(field_value)
                    .context("serialize harness table field")?;
                println!("  {field}: {rendered}");
            }
        }
    }
    Ok(())
}

pub async fn run_recall_score(args: RecallScoreArgs) -> Result<()> {
    let grader_config = load_grader_config(&args.grader_config)
        .with_context(|| format!("load --grader-config {}", args.grader_config.display()))?;
    let goldset_entries = load_goldset(&args.goldset)
        .with_context(|| format!("load --goldset {}", args.goldset.display()))?;
    validate_goldset_query_ids(&goldset_entries)?;

    if args.grades.len() > grader_config.graders().len() {
        anyhow::bail!(
            "received {} --grades file(s), but the validated grader roster has only {} grader(s)",
            args.grades.len(),
            grader_config.graders().len(),
        );
    }
    let expected_observations = goldset_entries
        .len()
        .checked_mul(grader_config.graders().len())
        .and_then(|count| count.checked_mul(2))
        .context("goldset/roster observation count overflow")?;

    let mut all_grades: Vec<GraderGrade> = Vec::new();
    for path in &args.grades {
        let g = load_grades(path).with_context(|| format!("load grades {}", path.display()))?;
        let aggregate_count = all_grades
            .len()
            .checked_add(g.len())
            .context("grade observation count overflow")?;
        if aggregate_count > expected_observations {
            anyhow::bail!(
                "grade observations exceed the exact goldset/roster matrix: {} received, {} maximum",
                aggregate_count,
                expected_observations,
            );
        }
        all_grades.extend(g);
    }

    // The scorer repeats this identity binding as a defense-in-depth invariant;
    // retain it at the CLI boundary too, so malformed inputs cannot arrive at
    // the scoring implementation under a different caller in the future.
    validate_goldset_query_binding(&goldset_entries, &all_grades)?;
    if matches!(args.output, OutputFormat::Table) {
        println!(
            "# goldset: {} queries, exact grade-query binding",
            goldset_entries.len()
        );
    }

    let result = compute_parity_run(&grader_config, &goldset_entries, &all_grades)
        .context("compute parity run")?;

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

/// Bind the mandatory canonical goldset to the grade corpus without silently
/// widening or shrinking the query set. Grade-observation uniqueness and
/// per-grader/system completeness are separate scorer invariants; this helper
/// owns only the supplied-goldset query identity contract.
fn validate_goldset_query_binding(entries: &[GoldsetEntry], grades: &[GraderGrade]) -> Result<()> {
    let goldset_query_ids = validate_goldset_query_ids(entries)?;
    let grade_query_ids: BTreeSet<&str> =
        grades.iter().map(|grade| grade.query_id.as_str()).collect();
    if grade_query_ids
        .iter()
        .any(|query_id| query_id.trim().is_empty())
    {
        anyhow::bail!("grades contain an empty query_id; exact goldset binding is impossible");
    }

    let missing_count = goldset_query_ids.difference(&grade_query_ids).count();
    let missing: Vec<&str> = goldset_query_ids
        .difference(&grade_query_ids)
        .take(5)
        .copied()
        .collect();
    let extra_count = grade_query_ids.difference(&goldset_query_ids).count();
    let extra: Vec<&str> = grade_query_ids
        .difference(&goldset_query_ids)
        .take(5)
        .copied()
        .collect();
    if !missing.is_empty() || !extra.is_empty() {
        anyhow::bail!(
            "goldset/grade query IDs differ: {} goldset query(s) missing from grades (e.g. {}); \
             {} grade query(s) absent from goldset (e.g. {}). The gate refuses partial or widened \
             corpora.",
            missing_count,
            display_query_examples(&missing),
            extra_count,
            display_query_examples(&extra),
        );
    }
    Ok(())
}

/// Validate the mandatory goldset's own identity set before it defines the
/// expected grade-matrix size. A duplicate would make the declared corpus and
/// its exact cardinality ambiguous even before any grade file is read.
fn validate_goldset_query_ids(entries: &[GoldsetEntry]) -> Result<BTreeSet<&str>> {
    let mut goldset_query_ids = BTreeSet::new();
    for entry in entries {
        if entry.query_id.trim().is_empty() {
            anyhow::bail!("goldset contains an empty query_id; exact binding is impossible");
        }
        if !goldset_query_ids.insert(entry.query_id.as_str()) {
            anyhow::bail!(
                "goldset contains duplicate query_id {:?}; exact binding is ambiguous",
                entry.query_id
            );
        }
    }
    Ok(goldset_query_ids)
}

fn display_query_examples(query_ids: &[&str]) -> String {
    if query_ids.is_empty() {
        "none".to_owned()
    } else {
        query_ids.join(", ")
    }
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
                "independent_external_family_gate_met": r.independent_external_family_gate_met,
                "participating_graders": r.participating_graders.iter()
                    .map(|grader| serde_json::json!({
                        "grader_id": grader.grader_id.as_str(),
                        "provider": grader.provider,
                        "family": grader.family,
                        "model_id": grader.model_id.as_str(),
                    }))
                    .collect::<Vec<_>>(),
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
            println!(
                "  independent external family gate: {}",
                r.independent_external_family_gate_met
            );
            println!("  participating graders (validated metadata):");
            for grader in &r.participating_graders {
                println!(
                    "    id={} provider={:?} family={:?} model={}",
                    grader.grader_id, grader.provider, grader.family, grader.model_id
                );
            }
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

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, Commands};
    use crate::recall::goldset::GoldsetCategory;

    fn entry(query_id: &str) -> GoldsetEntry {
        GoldsetEntry {
            query_id: query_id.to_owned(),
            query_text: "fixture".to_owned(),
            category: GoldsetCategory::Recall,
            expected_sources: Vec::new(),
            expected_response: String::new(),
        }
    }

    fn grade(query_id: &str) -> GraderGrade {
        GraderGrade {
            query_id: query_id.to_owned(),
            grader_id: "A".to_owned(),
            system: crate::recall::goldset::GradedSystem::Neoth,
            factual: 5,
            completeness: 5,
            on_tone: 5,
            usefulness: 5,
            brevity: 5,
        }
    }

    #[test]
    fn supplied_goldset_requires_exact_grade_query_ids() {
        let entries = vec![entry("q1"), entry("q2")];
        assert!(validate_goldset_query_binding(&entries, &[grade("q1"), grade("q2")]).is_ok());
        assert!(validate_goldset_query_binding(&entries, &[grade("q1")]).is_err());
        assert!(
            validate_goldset_query_binding(&entries, &[grade("q1"), grade("q2"), grade("q3")])
                .is_err()
        );
    }

    #[test]
    fn supplied_goldset_rejects_duplicate_or_empty_query_ids() {
        assert!(
            validate_goldset_query_binding(&[entry("q1"), entry("q1")], &[grade("q1")]).is_err()
        );
        assert!(validate_goldset_query_binding(&[entry(" ")], &[grade("q1")]).is_err());
        assert!(validate_goldset_query_binding(&[entry("q1")], &[grade(" ")]).is_err());
    }

    #[test]
    fn recall_score_requires_grader_config_at_clap_boundary() {
        assert!(
            Cli::try_parse_from([
                "neoth",
                "recall-score",
                "--goldset",
                "eval/goldset.jsonl",
                "--grades",
                "a.jsonl",
            ])
            .is_err()
        );
    }

    #[test]
    fn recall_score_requires_goldset_at_clap_boundary() {
        assert!(
            Cli::try_parse_from([
                "neoth",
                "recall-score",
                "--grader-config",
                "eval/grader-config.json",
                "--grades",
                "a.jsonl",
            ])
            .is_err()
        );
    }

    #[test]
    fn recall_score_parses_valid_mixed_input_paths() {
        let cli = Cli::try_parse_from([
            "neoth",
            "recall-score",
            "--grader-config",
            "eval/grader-config.json",
            "--goldset",
            "eval/goldset.jsonl",
            "--grades",
            "eval/grades-a.jsonl",
            "--grades",
            "eval/grades-d.jsonl",
        ])
        .expect("P1-07 recall-score surface must parse complete inputs");
        let Commands::RecallScore(args) = cli.command else {
            panic!("expected recall-score command");
        };
        assert_eq!(args.grader_config, PathBuf::from("eval/grader-config.json"));
        assert_eq!(args.goldset, PathBuf::from("eval/goldset.jsonl"));
        assert_eq!(
            args.grades,
            vec![
                PathBuf::from("eval/grades-a.jsonl"),
                PathBuf::from("eval/grades-d.jsonl"),
            ]
        );
    }
}
