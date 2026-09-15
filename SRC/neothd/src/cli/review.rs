//! W50 commit-only OCR impact-context bridge (WORK proposal).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use clap::Args;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::cli::OutputFormat;
use crate::installers::ocr;

const MAX_REVIEW_BACKGROUND_BYTES: usize = 32 * 1024;
const MAX_REVIEW_RECEIPT_BYTES: usize = 16 * 1024;
const GIT_SHA1_HEX_BYTES: usize = 40;

#[derive(Args, Debug, Clone)]
pub struct ReviewArgs {
    #[arg(long)]
    pub from: Option<String>,
    #[arg(long)]
    pub to: Option<String>,
    #[arg(long, short = 'c', value_name = "SHA")]
    pub commit: Option<String>,
    #[arg(long, short = 'b', value_name = "TEXT")]
    pub background: Option<String>,
    #[arg(long, short = 'p')]
    pub preview: bool,
    #[arg(long)]
    pub agent: bool,
    #[arg(long, value_name = "DIR")]
    pub repo: Option<PathBuf>,
    /// Attach W43/W48 evidence only to one immutable, non-merge commit review.
    #[arg(long)]
    pub impact_context: bool,
    #[arg(skip)]
    pub output: OutputFormat,
}

fn build_ocr_argv(a: &ReviewArgs) -> Vec<String> {
    let mut v = vec!["review".into()];
    if let Some(vv) = &a.from {
        v.extend(["--from".into(), vv.clone()]);
    }
    if let Some(vv) = &a.to {
        v.extend(["--to".into(), vv.clone()]);
    }
    if let Some(vv) = &a.commit {
        v.extend(["--commit".into(), vv.clone()]);
    }
    if let Some(vv) = &a.background {
        v.extend(["--background".into(), vv.clone()]);
    }
    if a.preview {
        v.push("--preview".into());
    }
    if a.agent {
        v.extend(["--audience".into(), "agent".into()]);
    }
    if let Some(vv) = &a.repo {
        v.extend(["--repo".into(), vv.display().to_string()]);
    }
    if matches!(a.output, OutputFormat::Json | OutputFormat::Jsonl) {
        v.extend(["--format".into(), "json".into()]);
    }
    v
}

fn impact_commit(args: &ReviewArgs) -> Result<&str> {
    ensure!(
        args.from.is_none() && args.to.is_none(),
        "--impact-context rejects branch selectors"
    );
    args.commit
        .as_deref()
        .context("--impact-context requires --commit")
}

fn git_bounded_output(root: &Path, args: &[String]) -> Result<String> {
    let mut command = vec!["-C".to_owned(), root.to_string_lossy().into_owned()];
    command.extend(args.iter().cloned());
    crate::code_map::diff_git::run_git_bounded(&command)
        .context("resolve immutable review commit with bounded git")
}

fn git_revision_with<F>(args: &[String], invoke: &mut F) -> Result<String>
where
    F: FnMut(&[String]) -> Result<String>,
{
    let text = invoke(args)?;
    let text = text.trim();
    ensure!(
        text.len() == GIT_SHA1_HEX_BYTES
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase()),
        "git did not return lowercase immutable SHA-1"
    );
    Ok(text.to_owned())
}

fn exact_non_merge_pair_with<F>(requested: &str, mut invoke: F) -> Result<(String, String)>
where
    F: FnMut(&[String]) -> Result<String>,
{
    crate::code_map::diff_git::validate_git_ref(requested)?;
    let target = git_revision_with(
        &[
            "rev-parse".to_owned(),
            "--verify".to_owned(),
            "--end-of-options".to_owned(),
            format!("{requested}^{{commit}}"),
        ],
        &mut invoke,
    )?;
    let base = git_revision_with(
        &[
            "rev-parse".to_owned(),
            "--verify".to_owned(),
            "--end-of-options".to_owned(),
            format!("{target}^1"),
        ],
        &mut invoke,
    )?;
    let parents = invoke(&[
        "rev-list".to_owned(),
        "--parents".to_owned(),
        "-n".to_owned(),
        "1".to_owned(),
        "--end-of-options".to_owned(),
        target.clone(),
    ])?;
    ensure!(
        parents.split_whitespace().count() == 2,
        "--impact-context rejects merge commits until an explicit parent policy exists"
    );
    Ok((base, target))
}

fn exact_non_merge_pair(root: &Path, requested: &str) -> Result<(String, String)> {
    exact_non_merge_pair_with(requested, |args| git_bounded_output(root, args))
}

fn build_impact_argv(
    args: &ReviewArgs,
    canonical_root: &Path,
    resolved_target: &str,
    background: &Path,
) -> Vec<String> {
    let mut safe = args.clone();
    safe.from = None;
    safe.to = None;
    safe.commit = Some(resolved_target.to_owned());
    safe.repo = Some(canonical_root.to_owned());
    let mut argv = build_ocr_argv(&safe);
    argv.extend(["--background-file".into(), background.display().to_string()]);
    argv
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReviewExecution {
    pub(crate) exit_code: Option<i32>,
    pub(crate) succeeded: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct ReviewReceipt {
    state: String,
    root: String,
    root_identity: String,
    base: String,
    target: String,
    ocr_version: Option<String>,
    argv_sha256: String,
    background_sha256: String,
    diff_sha256: String,
    impact_digest: String,
    index_generation: i64,
    graph_generation: i64,
    exit_code: Option<i32>,
}

fn write_receipt(path: &Path, row: &ReviewReceipt) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(row)?;
    ensure!(
        bytes.len() <= MAX_REVIEW_RECEIPT_BYTES,
        "review receipt too large"
    );
    std::fs::create_dir_all(path.parent().context("receipt parent")?)?;
    crate::util::atomic_write::atomic_write_private(path, &bytes)?;
    Ok(())
}

struct TemporaryBackground {
    file: tempfile::NamedTempFile,
}
impl TemporaryBackground {
    fn path(&self) -> &Path {
        self.file.path()
    }
    fn remove(self) -> Result<()> {
        self.file
            .close()
            .context("remove private review background")
    }
}
fn temporary_background(text: &str) -> Result<TemporaryBackground> {
    ensure!(
        text.len() <= MAX_REVIEW_BACKGROUND_BYTES,
        "review background too large"
    );
    // Project primitive creates private-before-write files: Unix 0600 and the
    // Windows current-TokenUser-only DACL, with collision-resistant UUID names.
    let mut file = crate::util::private_temp::named_file(".neoth-review-impact-", ".md")
        .context("allocate private review background")?;
    use std::io::Write as _;
    file.write_all(text.as_bytes())?;
    file.as_file().sync_all()?;
    Ok(TemporaryBackground { file })
}

async fn invoke_with<F, Fut>(argv: Vec<String>, runner: F) -> Result<ReviewExecution>
where
    F: FnOnce(Vec<String>) -> Fut,
    Fut: std::future::Future<Output = Result<ReviewExecution>>,
{
    runner(argv).await
}

#[cfg(test)]
async fn run_impact_context_with<F, Fut>(
    args: ReviewArgs,
    canonical_root: PathBuf,
    base: String,
    target: String,
    citation: crate::coding::code_map_receipt::DiffImpactCitation,
    receipt_path: PathBuf,
    runner: F,
) -> Result<()>
where
    F: FnOnce(Vec<String>) -> Fut,
    Fut: std::future::Future<Output = Result<ReviewExecution>>,
{
    run_impact_context_with_version(
        args,
        canonical_root,
        base,
        target,
        citation,
        receipt_path,
        None,
        runner,
    )
    .await
}

async fn run_impact_context_with_version<F, Fut>(
    args: ReviewArgs,
    canonical_root: PathBuf,
    base: String,
    target: String,
    citation: crate::coding::code_map_receipt::DiffImpactCitation,
    receipt_path: PathBuf,
    ocr_version: Option<String>,
    runner: F,
) -> Result<()>
where
    F: FnOnce(Vec<String>) -> Fut,
    Fut: std::future::Future<Output = Result<ReviewExecution>>,
{
    run_impact_context_with_writer_and_cleanup(
        args,
        canonical_root,
        base,
        target,
        citation,
        receipt_path,
        ocr_version,
        runner,
        &write_receipt,
        TemporaryBackground::remove,
    )
    .await
}

#[cfg(test)]
async fn run_impact_context_with_writer<F, Fut, W>(
    args: ReviewArgs,
    canonical_root: PathBuf,
    base: String,
    target: String,
    citation: crate::coding::code_map_receipt::DiffImpactCitation,
    receipt_path: PathBuf,
    runner: F,
    writer: &W,
) -> Result<()>
where
    F: FnOnce(Vec<String>) -> Fut,
    Fut: std::future::Future<Output = Result<ReviewExecution>>,
    W: Fn(&Path, &ReviewReceipt) -> Result<()>,
{
    run_impact_context_with_writer_and_cleanup(
        args,
        canonical_root,
        base,
        target,
        citation,
        receipt_path,
        None,
        runner,
        writer,
        TemporaryBackground::remove,
    )
    .await
}

#[allow(clippy::too_many_arguments)] // Explicit review inputs and persistence/cleanup boundaries are independently testable.
async fn run_impact_context_with_writer_and_cleanup<F, Fut, W, C>(
    args: ReviewArgs,
    canonical_root: PathBuf,
    base: String,
    target: String,
    citation: crate::coding::code_map_receipt::DiffImpactCitation,
    receipt_path: PathBuf,
    ocr_version: Option<String>,
    runner: F,
    writer: &W,
    cleanup: C,
) -> Result<()>
where
    F: FnOnce(Vec<String>) -> Fut,
    Fut: std::future::Future<Output = Result<ReviewExecution>>,
    W: Fn(&Path, &ReviewReceipt) -> Result<()>,
    C: FnOnce(TemporaryBackground) -> Result<()>,
{
    let background = citation.render_prompt_projection();
    let mut hash = Sha256::new();
    hash.update(background.as_bytes());
    let background_sha256 = hex::encode(hash.finalize());
    let temp = temporary_background(&background)?;
    let argv = build_impact_argv(&args, &canonical_root, &target, temp.path());
    let mut argv_hash = Sha256::new();
    for item in &argv {
        argv_hash.update(item.as_bytes());
        argv_hash.update([0]);
    }
    let mut receipt = ReviewReceipt {
        state: "prepared".into(),
        root: canonical_root.display().to_string(),
        root_identity: citation
            .impact_test_gap
            .as_ref()
            .map(|gap| gap.root_identity.clone())
            .unwrap_or_default(),
        base,
        target,
        // Direct test helpers pass None; production retains the version from
        // the successful availability probe without inventing an unknown one.
        ocr_version,
        argv_sha256: hex::encode(argv_hash.finalize()),
        background_sha256,
        diff_sha256: citation.diff_sha256.clone(),
        impact_digest: citation.impact_digest.clone(),
        index_generation: citation
            .impact_test_gap
            .as_ref()
            .map(|gap| gap.index_generation)
            .unwrap_or(0),
        graph_generation: citation
            .impact_test_gap
            .as_ref()
            .map(|gap| gap.graph_generation)
            .unwrap_or(0),
        exit_code: None,
    };
    writer(&receipt_path, &receipt)?;
    let execution = invoke_with(argv, runner).await;
    match execution {
        Ok(execution) => {
            receipt.exit_code = execution.exit_code;
            receipt.state = if execution.succeeded {
                "completed".into()
            } else {
                "exited_nonzero".into()
            };
            let marker = receipt_path.with_extension("terminal.json");
            let marker_error = writer(&marker, &receipt).err();
            let persist = writer(&receipt_path, &receipt);
            let cleanup = cleanup(temp);
            retain_terminal_failures(persist, marker_error, cleanup, None, &receipt_path, &marker)?;
            ensure!(execution.succeeded, "ocr exited {:?}", execution.exit_code);
            Ok(())
        }
        Err(error) => {
            receipt.state = "spawn_or_wait_failed".into();
            let marker = receipt_path.with_extension("terminal.json");
            let marker_error = writer(&marker, &receipt).err();
            let persist = writer(&receipt_path, &receipt);
            let cleanup = cleanup(temp);
            retain_terminal_failures(
                persist,
                marker_error,
                cleanup,
                Some(&format!("{error:#}")),
                &receipt_path,
                &marker,
            )?;
            Err(error)
        }
    }
}

/// Every terminal operation is attempted before return. If independent
/// persistence and cleanup failures coincide, retain each diagnostic so an
/// operator can find both the receipt state and a remaining private file.
fn retain_terminal_failures(
    primary: Result<()>,
    marker: Option<anyhow::Error>,
    cleanup: Result<()>,
    runner: Option<&str>,
    receipt_path: &Path,
    marker_path: &Path,
) -> Result<()> {
    let mut failures = Vec::new();
    if let Some(runner) = runner {
        failures.push(format!("runner failed: {runner}"));
    }
    if let Err(error) = primary {
        failures.push(format!(
            "terminal primary persistence failed at {}: {error:#}",
            receipt_path.display()
        ));
    }
    if let Some(error) = marker {
        failures.push(format!(
            "terminal marker persistence failed at {}: {error:#}",
            marker_path.display()
        ));
    }
    if let Err(error) = cleanup {
        failures.push(format!("private background cleanup failed: {error:#}"));
    }
    ensure!(failures.is_empty(), "{}", failures.join("; "));
    Ok(())
}

pub async fn run_review(args: ReviewArgs) -> Result<()> {
    if !args.impact_context {
        ocr::check_available().await.context("`ocr` is not installed; install with npm install -g @alibaba-group/open-code-review, then run ocr config")?;
        return ocr::run(&build_ocr_argv(&args)).await;
    }
    let version = ocr::check_available_without_update().await.context("`ocr` is not installed; install with npm install -g @alibaba-group/open-code-review, then run ocr config")?;
    let requested = impact_commit(&args)?;
    let root = std::fs::canonicalize(args.repo.clone().unwrap_or(std::env::current_dir()?))?;
    let db = crate::code_map::persist::default_path();
    let (base, target, citation) = prepare_impact_context(&root, requested, &db)?;
    let home = crate::config::FreedomConfig::default_neoth_home();
    let name = format!(
        "{}-{}.json",
        uuid::Uuid::new_v4(),
        &citation.impact_digest[..16]
    );
    let receipt = home.join("review-receipts").join(name);
    run_impact_context_with_version(
        args,
        root,
        base,
        target,
        citation,
        receipt,
        Some(version),
        |argv| async move { ocr::run_without_update_status(argv).await },
    )
    .await
}

/// Prepare only read-only review evidence before the provider runner is
/// constructed. In particular, an absent advisory DB fails before any
/// directory, SQLite sidecar, migration, receipt, or OCR invocation occurs.
fn prepare_impact_context(
    root: &Path,
    requested: &str,
    database: &Path,
) -> Result<(
    String,
    String,
    crate::coding::code_map_receipt::DiffImpactCitation,
)> {
    let (base, target) = exact_non_merge_pair(root, requested)?;
    let conn = crate::code_map::persist::open_read_only(database)?;
    let citation = produce_impact_citation(&conn, root, base.clone(), target.clone())?;
    Ok((base, target, citation))
}

fn produce_impact_citation(
    conn: &rusqlite::Connection,
    root: &Path,
    base: String,
    target: String,
) -> Result<crate::coding::code_map_receipt::DiffImpactCitation> {
    let diff = crate::code_map::analyze_diff_impact(
        conn,
        &crate::code_map::DiffImpactRequest {
            repo_root: root.to_path_buf(),
            input: crate::code_map::DiffImpactInput::committed(base.clone(), target.clone()),
            options: crate::code_map::ImpactOptions::default(),
        },
    )?;
    diff.require_prompt_admissible()?;
    let (mut citation, _) =
        crate::coding::code_map_receipt::DiffImpactCitation::from_receipt(&diff)?;
    let gaps = crate::code_map::test_coverage::test_gap_for_impact(
        conn,
        &diff.impact,
        Default::default(),
    )?;
    citation.impact_test_gap = Some(
        crate::coding::code_map_receipt::ImpactTestGapCitation::from_result(
            &citation,
            diff.snapshot().root.identity().as_str(),
            &gaps,
        )?,
    );
    Ok(citation)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> ReviewArgs {
        ReviewArgs {
            from: None,
            to: None,
            commit: Some("moving-ref".into()),
            background: None,
            preview: false,
            agent: false,
            repo: None,
            impact_context: true,
            output: OutputFormat::Table,
        }
    }
    #[test]
    fn ordinary_argv_stays_plain() {
        let mut a = args();
        a.impact_context = false;
        assert_eq!(build_ocr_argv(&a), vec!["review", "--commit", "moving-ref"]);
    }
    #[test]
    fn immutable_spawn_argv_replaces_moving_ref_and_root() {
        let dir = PathBuf::from("C:/canonical/repo");
        let argv = build_impact_argv(&args(), &dir, "a".repeat(40).as_str(), Path::new("x.md"));
        assert!(
            argv.windows(2)
                .any(|p| p == ["--commit", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"])
        );
        assert!(
            argv.windows(2)
                .any(|p| p == ["--repo", "C:/canonical/repo"])
        );
        assert!(!argv.contains(&"moving-ref".to_string()));
    }
    #[tokio::test]
    async fn owned_argv_fake_runner_needs_no_ocr() {
        let expected = vec!["review".into(), "--commit".into(), "a".repeat(40)];
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let copy = seen.clone();
        let outcome = invoke_with(expected.clone(), move |argv| async move {
            *copy.lock().unwrap() = argv;
            Ok(ReviewExecution {
                exit_code: Some(0),
                succeeded: true,
            })
        })
        .await
        .unwrap();
        assert!(outcome.succeeded);
        assert_eq!(*seen.lock().unwrap(), expected);
    }
    #[test]
    fn temporary_names_do_not_collide() {
        let a = temporary_background("x").unwrap();
        let b = temporary_background("x").unwrap();
        assert_ne!(a.path(), b.path());
        a.remove().unwrap();
        b.remove().unwrap();
    }

    #[test]
    fn exact_pair_rejects_untrusted_selectors_before_any_git_process() {
        let oversized = "x".repeat(1025);
        for requested in ["--upload-pack=unexpected", oversized.as_str()] {
            let calls = std::cell::Cell::new(0usize);
            let error = exact_non_merge_pair_with(requested, |_| {
                calls.set(calls.get() + 1);
                anyhow::bail!("must not run")
            })
            .unwrap_err();
            assert!(error.to_string().contains("invalid explicit Git ref"));
            assert_eq!(calls.get(), 0);
        }
    }

    #[test]
    fn exact_pair_retains_end_of_options_and_stops_on_bounded_git_failure() {
        let calls = std::cell::Cell::new(0usize);
        let error = exact_non_merge_pair_with(&"a".repeat(40), |argv| {
            calls.set(calls.get() + 1);
            assert_eq!(argv[0], "rev-parse");
            assert!(argv.iter().any(|arg| arg == "--end-of-options"));
            anyhow::bail!("git diff exceeded 15 second timeout")
        })
        .unwrap_err();
        assert_eq!(calls.get(), 1);
        assert!(error.to_string().contains("15 second timeout"));
    }

    fn citation() -> crate::coding::code_map_receipt::DiffImpactCitation {
        use crate::coding::code_map_receipt::{
            CodeMapSelectedFile, DiffImpactAffectedIdentity, DiffImpactCitation,
        };
        DiffImpactCitation {
            source: crate::code_map::diff_impact::DiffImpactSourceDescriptor::Committed {
                base: "a".repeat(40),
                target: "b".repeat(40),
            },
            diff_sha256: "c".repeat(64),
            impact_digest: "d".repeat(64),
            exact_symbol_seeds: vec![CodeMapSelectedFile {
                path: "src/lib.rs".into(),
                symbols: vec!["changed".into()],
            }],
            file_fallback_seeds: Vec::new(),
            affected_identities: vec![DiffImpactAffectedIdentity {
                path: "src/lib.rs".into(),
                symbol: "changed".into(),
                line: 1,
                kind: "function".into(),
            }],
            affected_identities_truncated: false,
            unresolved_seed_count: 0,
            unresolved_edge_count: 0,
            impact_truncated: false,
            budget_truncated: false,
            evidence_truncated: false,
            root_snapshot_complete: true,
            allow_stale: false,
            impact_test_gap: None,
        }
    }

    #[tokio::test]
    async fn core_path_persists_prepared_before_fake_spawn_and_finalizes_success() {
        let home = tempfile::tempdir().unwrap();
        let receipt = home.path().join("one.json");
        let root = std::fs::canonicalize(home.path()).unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let copy = seen.clone();
        let callback_receipt = receipt.clone();
        run_impact_context_with(
            args(),
            root.clone(),
            "a".repeat(40),
            "b".repeat(40),
            citation(),
            receipt.clone(),
            move |argv| async move {
                let prepared: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&callback_receipt).unwrap()).unwrap();
                assert_eq!(prepared["state"], "prepared");
                *copy.lock().unwrap() = argv;
                Ok(ReviewExecution {
                    exit_code: Some(0),
                    succeeded: true,
                })
            },
        )
        .await
        .unwrap();
        let final_row: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
        assert_eq!(final_row["state"], "completed");
        assert_eq!(final_row["exit_code"], 0);
        let argv = seen.lock().unwrap();
        assert!(
            argv.windows(2)
                .any(|p| p == ["--commit", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"])
        );
        assert!(
            argv.windows(2)
                .any(|p| p[0] == "--repo" && p[1] == root.display().to_string())
        );
        assert!(receipt.with_extension("terminal.json").is_file());
    }

    #[tokio::test]
    async fn core_path_records_nonzero_and_runner_failure() {
        for (name, failure) in [("nonzero", false), ("spawn", true)] {
            let home = tempfile::tempdir().unwrap();
            let receipt = home.path().join(format!("{name}.json"));
            let root = std::fs::canonicalize(home.path()).unwrap();
            let result = run_impact_context_with(
                args(),
                root,
                "a".repeat(40),
                "b".repeat(40),
                citation(),
                receipt.clone(),
                move |_| async move {
                    if failure {
                        anyhow::bail!("synthetic spawn failure")
                    } else {
                        Ok(ReviewExecution {
                            exit_code: Some(9),
                            succeeded: false,
                        })
                    }
                },
            )
            .await;
            assert!(result.is_err());
            let row: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
            assert_eq!(
                row["state"],
                if failure {
                    "spawn_or_wait_failed"
                } else {
                    "exited_nonzero"
                }
            );
            assert!(receipt.with_extension("terminal.json").is_file());
        }
    }

    #[tokio::test]
    async fn terminal_marker_survives_injected_postwrite_failure_after_runner_exit() {
        let home = tempfile::tempdir().unwrap();
        let receipt = home.path().join("postwrite.json");
        let root = std::fs::canonicalize(home.path()).unwrap();
        let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = writes.clone();
        let error = run_impact_context_with_writer(
            args(),
            root,
            "a".repeat(40),
            "b".repeat(40),
            citation(),
            receipt.clone(),
            |_| async {
                Ok(ReviewExecution {
                    exit_code: Some(7),
                    succeeded: false,
                })
            },
            &move |path, row| {
                let nth = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if nth == 3 {
                    anyhow::bail!("injected terminal primary write failure")
                }
                write_receipt(path, row)
            },
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("terminal primary persistence failed")
        );
        let marker: serde_json::Value = serde_json::from_slice(
            &std::fs::read(receipt.with_extension("terminal.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(marker["state"], "exited_nonzero");
        assert_eq!(marker["exit_code"], 7);
    }

    #[tokio::test]
    async fn marker_write_failure_still_persists_terminal_primary_and_cleans_background() {
        let home = tempfile::tempdir().unwrap();
        let receipt = home.path().join("marker-failure.json");
        let root = std::fs::canonicalize(home.path()).unwrap();
        let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = writes.clone();
        let background = std::sync::Arc::new(std::sync::Mutex::new(None));
        let observed = background.clone();
        let error = run_impact_context_with_writer(
            args(),
            root,
            "a".repeat(40),
            "b".repeat(40),
            citation(),
            receipt.clone(),
            move |argv| async move {
                let path = argv
                    .windows(2)
                    .find(|p| p[0] == "--background-file")
                    .unwrap()[1]
                    .clone();
                *observed.lock().unwrap() = Some(PathBuf::from(path));
                Ok(ReviewExecution {
                    exit_code: Some(0),
                    succeeded: true,
                })
            },
            &move |path, row| {
                let nth = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if nth == 2 {
                    anyhow::bail!("injected marker write failure")
                }
                write_receipt(path, row)
            },
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("terminal marker persistence failed")
        );
        let primary: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
        assert_eq!(primary["state"], "completed");
        assert!(!background.lock().unwrap().as_ref().unwrap().exists());
    }

    #[tokio::test]
    async fn primary_persistence_and_cleanup_failures_are_both_retained() {
        let home = tempfile::tempdir().unwrap();
        let receipt = home.path().join("double-failure.json");
        let root = std::fs::canonicalize(home.path()).unwrap();
        let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = writes.clone();
        let error = run_impact_context_with_writer_and_cleanup(
            args(),
            root,
            "a".repeat(40),
            "b".repeat(40),
            citation(),
            receipt,
            None,
            |_| async {
                Ok(ReviewExecution {
                    exit_code: Some(0),
                    succeeded: true,
                })
            },
            &move |path, row| {
                let nth = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if nth == 3 {
                    anyhow::bail!("injected primary failure")
                }
                write_receipt(path, row)
            },
            |_| anyhow::bail!("injected cleanup failure"),
        )
        .await
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("terminal primary persistence failed"));
        assert!(message.contains("private background cleanup failed"));
    }

    #[tokio::test]
    async fn production_version_is_serialized_but_direct_core_keeps_unknown_version() {
        let home = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(home.path()).unwrap();
        let production = home.path().join("version.json");
        run_impact_context_with_version(
            args(),
            root.clone(),
            "a".repeat(40),
            "b".repeat(40),
            citation(),
            production.clone(),
            Some("ocr 1.2.3".into()),
            |_| async {
                Ok(ReviewExecution {
                    exit_code: Some(0),
                    succeeded: true,
                })
            },
        )
        .await
        .unwrap();
        let production_row: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&production).unwrap()).unwrap();
        assert_eq!(production_row["ocr_version"], "ocr 1.2.3");
        let direct = home.path().join("unknown-version.json");
        run_impact_context_with(
            args(),
            root,
            "a".repeat(40),
            "b".repeat(40),
            citation(),
            direct.clone(),
            |_| async {
                Ok(ReviewExecution {
                    exit_code: Some(0),
                    succeeded: true,
                })
            },
        )
        .await
        .unwrap();
        let direct_row: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&direct).unwrap()).unwrap();
        assert!(direct_row["ocr_version"].is_null());
    }

    #[tokio::test]
    async fn local_git_and_sqlite_fixture_keeps_prepared_receipt_before_immutable_runner() {
        let home = tempfile::tempdir().unwrap();
        let repo = home.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(args)
                .status()
                .unwrap();
            assert!(status.success());
        };
        git(&["init"]);
        git(&["config", "user.email", "fixture@example.invalid"]);
        git(&["config", "user.name", "Fixture"]);
        std::fs::create_dir(repo.join("src")).unwrap();
        std::fs::create_dir(repo.join("tests")).unwrap();
        std::fs::write(repo.join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
        std::fs::write(
            repo.join("src/routes.rs"),
            "pub fn handle_request() { changed(); }\n",
        )
        .unwrap();
        std::fs::write(
            repo.join("tests/review.rs"),
            "#[test]\nfn route_is_checked() { crate::handle_request(); }\n",
        )
        .unwrap();
        git(&["add", "src/lib.rs", "src/routes.rs", "tests/review.rs"]);
        git(&["commit", "-m", "base"]);
        std::fs::write(
            repo.join("src/lib.rs"),
            "pub fn changed() { let token = 7; assert_eq!(token, 7); }\n",
        )
        .unwrap();
        git(&["commit", "-am", "target"]);
        git(&["branch", "moving-ref", "HEAD"]);
        let (base, target) = exact_non_merge_pair(&repo, "moving-ref").unwrap();
        git(&["branch", "-f", "moving-ref", &base]);
        let db = home.path().join("code-map.db");
        let canonical = std::fs::canonicalize(&repo).unwrap();
        let indexed = crate::code_map::CanonicalRepoRoot::discover(&canonical).unwrap();
        let rebuilt = crate::code_map::rebuild_snapshot(&indexed, &db, Default::default()).unwrap();
        let conn = crate::code_map::persist::open_read_only(&db).unwrap();
        let citation =
            produce_impact_citation(&conn, &canonical, base.clone(), target.clone()).unwrap();
        match &citation.source {
            crate::code_map::DiffImpactSourceDescriptor::Committed {
                base: cited_base,
                target: cited_target,
            } => {
                assert_eq!(cited_base, &base);
                assert_eq!(cited_target, &target);
            }
            _ => panic!("expected committed immutable pair"),
        }
        assert!(
            citation
                .affected_identities
                .iter()
                .any(|node| node.path == "src/routes.rs" && node.symbol == "handle_request")
        );
        let gap = citation
            .impact_test_gap
            .as_ref()
            .expect("W48 test-gap citation from W43 impact");
        assert_eq!(gap.root_identity, indexed.identity().as_str());
        assert_eq!(gap.index_generation, rebuilt.index_generation);
        assert_eq!(gap.graph_generation, rebuilt.graph_generation);
        let route_gap = gap
            .nodes
            .iter()
            .find(|node| {
                node.impact_node.path == "src/routes.rs"
                    && node.impact_node.symbol == "handle_request"
            })
            .expect("impacted route gap node");
        assert!(
            route_gap
                .observed_tests
                .iter()
                .any(|test| test.path == "tests/review.rs" && test.symbol == "route_is_checked")
        );
        let receipt = home.path().join("receipt.json");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let copy = seen.clone();
        let callback = receipt.clone();
        let expected_root = canonical.clone();
        let expected_identity = indexed.identity().as_str().to_owned();
        let expected_index = rebuilt.index_generation;
        let expected_graph = rebuilt.graph_generation;
        run_impact_context_with(
            args(),
            canonical.clone(),
            base,
            target.clone(),
            citation.clone(),
            receipt.clone(),
            move |argv| async move {
                let prepared: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(callback).unwrap()).unwrap();
                assert_eq!(prepared["state"], "prepared");
                assert_eq!(prepared["root"], expected_root.display().to_string());
                assert_eq!(prepared["root_identity"], expected_identity);
                assert_eq!(prepared["index_generation"].as_i64(), Some(expected_index));
                assert_eq!(prepared["graph_generation"].as_i64(), Some(expected_graph));
                *copy.lock().unwrap() = argv;
                Ok(ReviewExecution {
                    exit_code: Some(0),
                    succeeded: true,
                })
            },
        )
        .await
        .unwrap();
        let prepared: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
        assert_eq!(prepared["impact_digest"], citation.impact_digest);
        let argv = seen.lock().unwrap();
        assert!(argv.windows(2).any(|p| p == ["--commit", target.as_str()]));
        assert!(
            argv.windows(2)
                .any(|p| p[0] == "--repo" && p[1] == canonical.display().to_string())
        );
        let missing = home.path().join("absent-read-only.db");
        assert!(prepare_impact_context(&canonical, &target, &missing).is_err());
        assert!(!missing.exists());
        assert!(!missing.with_extension("db-wal").exists());
        assert!(!missing.with_extension("db-shm").exists());
    }
}
