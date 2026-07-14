//! Deterministic, crash-resumable migration planning for GOLD-R3-08.
//!
//! A dry-run stores an immutable SHA-256-bound plan. Apply recomputes the
//! plan from the live sources and accepts it only when that exact immutable
//! checkpoint already exists. Runtime artifacts from another assistant are
//! never activated: config, cron, agent and skill inputs are staged under a
//! private plan-specific review directory. Credential material is represented
//! only by key/path references, never values. Vector bytes are never copied;
//! extractable sidecars become reviewable re-embedding queue entries.

use std::{
    collections::{BTreeSet, HashSet},
    fs::{File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::readers::{ImportKind, ImportManifest, ImportSource};

const PLAN_SCHEMA_VERSION: u32 = 1;
const MAX_REVIEW_TEXT_BYTES: u64 = 1_048_576;
static PRIVATE_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub schema_version: u32,
    pub manifest_sha256: String,
    pub plan_sha256: String,
    pub acknowledge_unsupported: bool,
    pub sources: Vec<PlannedSource>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedSource {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub source_sha256: String,
    pub artifacts: Vec<PlannedArtifact>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactCategory {
    Markdown,
    Json,
    Sql,
    Config,
    Cron,
    Agent,
    Skill,
    CredentialReference,
    Vector,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactDisposition {
    ImportTransactional,
    StageReview,
    CredentialChecklist,
    QueueReembedding,
    BlockedUnsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedArtifact {
    pub id: String,
    pub source_name: String,
    pub relative_path: String,
    pub path: String,
    pub category: ArtifactCategory,
    pub disposition: ArtifactDisposition,
    pub source_sha256: String,
    pub byte_len: u64,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlanStatus {
    pub state: String,
    pub plan_sha256: Option<String>,
    pub plan_path: Option<String>,
    pub review_path: Option<String>,
    pub artifacts_total: usize,
    pub artifacts_committed: usize,
    pub blocked_unsupported: usize,
    pub acknowledge_unsupported: bool,
    pub memory_committed: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct StageSummary {
    pub staged: usize,
    pub resumed: usize,
    pub acknowledged_unsupported: usize,
    pub review_path: String,
}

#[derive(Serialize)]
struct PlanBody<'a> {
    schema_version: u32,
    manifest_sha256: &'a str,
    acknowledge_unsupported: bool,
    sources: &'a [PlannedSource],
}

#[derive(Serialize)]
struct ManifestBinding<'a> {
    acknowledge_unsupported: bool,
    sources: Vec<ManifestSourceBinding<'a>>,
}

#[derive(Serialize)]
struct ManifestSourceBinding<'a> {
    name: &'a str,
    path: &'a str,
    kind: &'a str,
    hint: Option<&'a str>,
}

pub fn build_plan(
    manifest: &ImportManifest,
    home: &Path,
    target_db: &Path,
) -> Result<MigrationPlan> {
    anyhow::ensure!(
        !manifest.sources.is_empty(),
        "import manifest contains no sources"
    );

    let mut source_refs: Vec<&ImportSource> = manifest.sources.iter().collect();
    source_refs.sort_by(|left, right| {
        (
            left.name.as_str(),
            left.kind.as_str(),
            left.path.as_str(),
            left.hint.as_deref(),
        )
            .cmp(&(
                right.name.as_str(),
                right.kind.as_str(),
                right.path.as_str(),
                right.hint.as_deref(),
            ))
    });
    let mut names = HashSet::new();
    for source in &source_refs {
        anyhow::ensure!(
            !source.name.trim().is_empty(),
            "import source name must not be empty"
        );
        anyhow::ensure!(
            names.insert(source.name.trim()),
            "duplicate import source name '{}'",
            source.name
        );
    }

    let manifest_binding = ManifestBinding {
        acknowledge_unsupported: manifest.acknowledge_unsupported,
        sources: source_refs
            .iter()
            .map(|source| ManifestSourceBinding {
                name: source.name.trim(),
                path: source.path.as_str(),
                kind: source.kind.as_str(),
                hint: source.hint.as_deref(),
            })
            .collect(),
    };
    let manifest_sha256 = sha256_bytes(&serde_json::to_vec(&manifest_binding)?);

    let mut sources = Vec::with_capacity(source_refs.len());
    for source in source_refs {
        sources.push(plan_source(source, home, target_db)?);
    }
    sources.sort_by(|left, right| {
        (&left.name, &left.kind, &left.path).cmp(&(&right.name, &right.kind, &right.path))
    });

    let body = PlanBody {
        schema_version: PLAN_SCHEMA_VERSION,
        manifest_sha256: &manifest_sha256,
        acknowledge_unsupported: manifest.acknowledge_unsupported,
        sources: &sources,
    };
    let plan_sha256 = sha256_bytes(&serde_json::to_vec(&body)?);
    Ok(MigrationPlan {
        schema_version: PLAN_SCHEMA_VERSION,
        manifest_sha256,
        plan_sha256,
        acknowledge_unsupported: manifest.acknowledge_unsupported,
        sources,
    })
}

pub fn checkpoint_plan(home: &Path, plan: &MigrationPlan) -> Result<PathBuf> {
    verify_plan_hash(plan)?;
    let path = plan_path(home, &plan.plan_sha256);
    let bytes = serde_json::to_vec_pretty(plan).context("serialize migration plan")?;
    write_immutable_private(&path, &bytes)?;
    Ok(path)
}

pub fn require_checkpoint(home: &Path, current: &MigrationPlan) -> Result<PathBuf> {
    verify_plan_hash(current)?;
    let path = plan_path(home, &current.plan_sha256);
    anyhow::ensure!(
        path.is_file(),
        "source state has no reviewed plan checkpoint (computed {}). Run `neoth-migrate dry-run --manifest ...` again; a source may have changed",
        current.plan_sha256
    );
    let body = std::fs::read(&path)
        .with_context(|| format!("read migration plan checkpoint {}", path.display()))?;
    let stored: MigrationPlan = serde_json::from_slice(&body)
        .with_context(|| format!("parse migration plan checkpoint {}", path.display()))?;
    verify_plan_hash(&stored)?;
    anyhow::ensure!(
        &stored == current,
        "migration plan checkpoint {} does not match live deterministic plan; refusing stale apply",
        path.display()
    );
    Ok(path)
}

pub fn transactional_source_names(plan: &MigrationPlan) -> HashSet<&str> {
    plan.sources
        .iter()
        .filter(|source| {
            source
                .artifacts
                .iter()
                .any(|artifact| artifact.disposition == ArtifactDisposition::ImportTransactional)
        })
        .map(|source| source.name.as_str())
        .collect()
}

pub fn blocked_artifacts(plan: &MigrationPlan) -> Vec<&PlannedArtifact> {
    plan.sources
        .iter()
        .flat_map(|source| &source.artifacts)
        .filter(|artifact| artifact.disposition == ArtifactDisposition::BlockedUnsupported)
        .collect()
}

pub fn memory_already_committed(
    home: &Path,
    plan: &MigrationPlan,
    target_db: &Path,
) -> Result<bool> {
    let path = marker_dir(home, plan).join("memory.done");
    if !path.exists() {
        return Ok(false);
    }
    let expected = target_db_binding(target_db);
    let actual = std::fs::read_to_string(&path)
        .with_context(|| format!("read memory resume marker {}", path.display()))?;
    anyhow::ensure!(
        actual == expected,
        "migration plan {} already committed memory to a different target database; refusing cross-target resume",
        plan.plan_sha256
    );
    Ok(true)
}

pub fn mark_memory_committed(home: &Path, plan: &MigrationPlan, target_db: &Path) -> Result<()> {
    for artifact in plan
        .sources
        .iter()
        .flat_map(|source| &source.artifacts)
        .filter(|artifact| artifact.disposition == ArtifactDisposition::ImportTransactional)
    {
        write_artifact_marker(home, plan, artifact)?;
    }
    write_immutable_private(
        &marker_dir(home, plan).join("memory.done"),
        target_db_binding(target_db).as_bytes(),
    )?;
    Ok(())
}

pub fn stage_review_artifacts(home: &Path, plan: &MigrationPlan) -> Result<StageSummary> {
    let blocked = blocked_artifacts(plan);
    anyhow::ensure!(
        blocked.is_empty() || plan.acknowledge_unsupported,
        "{} unsupported artifact(s) block apply. Review dry-run output, then set `acknowledge_unsupported: true` in the manifest to record an explicit skip",
        blocked.len()
    );

    let review = review_dir(home, plan);
    ensure_private_dir(&review)?;
    write_immutable_private(
        &review.join("plan.json"),
        &serde_json::to_vec_pretty(plan).context("serialize review plan")?,
    )?;

    let mut summary = StageSummary {
        review_path: review.display().to_string(),
        ..StageSummary::default()
    };
    let mut credential_entries = Vec::new();
    let mut reembed_entries = Vec::new();

    for artifact in plan.sources.iter().flat_map(|source| &source.artifacts) {
        if artifact.disposition == ArtifactDisposition::ImportTransactional {
            continue;
        }
        let already_committed = artifact_marker_exists(home, plan, artifact);

        match artifact.disposition {
            ArtifactDisposition::StageReview => {
                if already_committed {
                    summary.resumed += 1;
                    continue;
                }
                verify_artifact_source(artifact)?;
                let (path, body) = render_runtime_artifact(&review, artifact)?;
                // Bind the bytes rendered for review to the same source
                // snapshot; a concurrent source edit cannot slip between the
                // pre-read hash and the immutable review commit.
                verify_artifact_source(artifact)?;
                write_immutable_private(&path, &body)?;
                summary.staged += 1;
            }
            ArtifactDisposition::CredentialChecklist => {
                credential_entries.push(serde_json::json!({
                    "artifact_id": artifact.id,
                    "source": artifact.source_name,
                    "path": artifact.path,
                    "references": artifact.references,
                    "action": "Create the corresponding NEOTH credential entry manually; no secret value was read or copied."
                }));
                if already_committed {
                    summary.resumed += 1;
                    continue;
                }
                verify_artifact_source(artifact)?;
                summary.staged += 1;
            }
            ArtifactDisposition::QueueReembedding => {
                reembed_entries.push(serde_json::json!({
                    "artifact_id": artifact.id,
                    "source": artifact.source_name,
                    "path": artifact.path,
                    "source_sha256": artifact.source_sha256,
                    "byte_len": artifact.byte_len,
                    "action": "review_then_reembed_with_neoth_model",
                    "raw_vectors_copied": false
                }));
                if already_committed {
                    summary.resumed += 1;
                    continue;
                }
                verify_artifact_source(artifact)?;
                summary.staged += 1;
            }
            ArtifactDisposition::BlockedUnsupported => {
                if already_committed {
                    summary.resumed += 1;
                    continue;
                }
                verify_artifact_source(artifact)?;
                let descriptor = serde_json::json!({
                    "artifact": artifact,
                    "status": "explicitly_acknowledged_unsupported",
                    "applied": false
                });
                write_immutable_private(
                    &review
                        .join("unsupported")
                        .join(format!("{}.json", artifact.id)),
                    &serde_json::to_vec_pretty(&descriptor)?,
                )?;
                summary.acknowledged_unsupported += 1;
            }
            ArtifactDisposition::ImportTransactional => unreachable!(),
        }
        write_artifact_marker(home, plan, artifact)?;
    }

    if !credential_entries.is_empty() {
        credential_entries.sort_by_key(|left| left.to_string());
        write_immutable_private(
            &review.join("credential-references.json"),
            &serde_json::to_vec_pretty(&credential_entries)?,
        )?;
    }
    if !reembed_entries.is_empty() {
        reembed_entries.sort_by_key(|left| left.to_string());
        let mut body = Vec::new();
        for entry in reembed_entries {
            serde_json::to_writer(&mut body, &entry)?;
            body.push(b'\n');
        }
        write_immutable_private(&review.join("reembed-queue.jsonl"), &body)?;
    }

    Ok(summary)
}

pub fn mark_complete(home: &Path, plan: &MigrationPlan) -> Result<()> {
    let all_committed = plan
        .sources
        .iter()
        .flat_map(|source| &source.artifacts)
        .all(|artifact| artifact_marker_exists(home, plan, artifact));
    anyhow::ensure!(
        all_committed,
        "cannot complete migration plan {}: one or more artifact markers are missing",
        plan.plan_sha256
    );
    write_immutable_private(
        &marker_dir(home, plan).join("complete.done"),
        plan.plan_sha256.as_bytes(),
    )
}

pub fn load_plan_status(home: &Path) -> Result<PlanStatus> {
    let plans = migration_root(home).join("plans");
    if !plans.is_dir() {
        return Ok(empty_status());
    }
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(&plans)
        .with_context(|| format!("read migration plans directory {}", plans.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let modified = entry.metadata()?.modified().ok();
        candidates.push((modified, path));
    }
    candidates.sort();
    let Some((_, path)) = candidates.pop() else {
        return Ok(empty_status());
    };
    let body = std::fs::read(&path)?;
    let plan: MigrationPlan = serde_json::from_slice(&body)
        .with_context(|| format!("parse migration plan {}", path.display()))?;
    verify_plan_hash(&plan)?;
    let artifacts: Vec<&PlannedArtifact> = plan
        .sources
        .iter()
        .flat_map(|source| &source.artifacts)
        .collect();
    let committed = artifacts
        .iter()
        .filter(|artifact| artifact_marker_exists(home, &plan, artifact))
        .count();
    let markers = marker_dir(home, &plan);
    let complete = markers.join("complete.done").is_file();
    let memory = markers.join("memory.done").is_file();
    let state = if complete {
        "complete"
    } else if memory || committed > 0 {
        "in_progress"
    } else {
        "planned"
    };
    Ok(PlanStatus {
        state: state.to_string(),
        plan_sha256: Some(plan.plan_sha256.clone()),
        plan_path: Some(path.display().to_string()),
        review_path: Some(review_dir(home, &plan).display().to_string()),
        artifacts_total: artifacts.len(),
        artifacts_committed: committed,
        blocked_unsupported: blocked_artifacts(&plan).len(),
        acknowledge_unsupported: plan.acknowledge_unsupported,
        memory_committed: memory,
    })
}

fn empty_status() -> PlanStatus {
    PlanStatus {
        state: "never_planned".to_string(),
        plan_sha256: None,
        plan_path: None,
        review_path: None,
        artifacts_total: 0,
        artifacts_committed: 0,
        blocked_unsupported: 0,
        acknowledge_unsupported: false,
        memory_committed: false,
    }
}

fn plan_source(source: &ImportSource, home: &Path, target_db: &Path) -> Result<PlannedSource> {
    let root = resolve_path(&source.path, home);
    let mut artifacts = Vec::new();
    if !root.exists() {
        artifacts.push(make_virtual_artifact(
            source,
            &root,
            ArtifactCategory::Unsupported,
            ArtifactDisposition::BlockedUnsupported,
            "declared source path does not exist",
        ));
    } else {
        match source.kind {
            ImportKind::AssistantHome => {
                validate_assistant_hint(source)?;
                plan_assistant_home(source, &root, target_db, &mut artifacts)?;
            }
            ImportKind::Markdown | ImportKind::JsonDir => {
                anyhow::ensure!(
                    root.is_dir(),
                    "source '{}' kind '{}' requires a directory",
                    source.name,
                    source.kind.as_str()
                );
                let files = collect_files(&root, &[target_db.to_path_buf()], false)?;
                for path in files {
                    let ext = extension(&path);
                    let category = match (source.kind, ext.as_str()) {
                        (ImportKind::Markdown, "md" | "markdown") => {
                            Some(ArtifactCategory::Markdown)
                        }
                        (ImportKind::JsonDir, "json" | "ajson") => Some(ArtifactCategory::Json),
                        _ => None,
                    };
                    if let Some(category) = category {
                        artifacts.push(make_file_artifact(
                            source,
                            &root,
                            &path,
                            category,
                            ArtifactDisposition::ImportTransactional,
                            "candidate memory import",
                            Vec::new(),
                        )?);
                    }
                }
            }
            ImportKind::MarkdownFile | ImportKind::JsonFile | ImportKind::Sqlite => {
                let category = match source.kind {
                    ImportKind::MarkdownFile => ArtifactCategory::Markdown,
                    ImportKind::JsonFile => ArtifactCategory::Json,
                    ImportKind::Sqlite => ArtifactCategory::Sql,
                    _ => unreachable!(),
                };
                artifacts.push(make_file_artifact(
                    source,
                    root.parent().unwrap_or(home),
                    &root,
                    category,
                    ArtifactDisposition::ImportTransactional,
                    "candidate memory import",
                    Vec::new(),
                )?);
            }
            ImportKind::LanceArrow | ImportKind::FaissFlat => {
                plan_vector_source(source, &root, &mut artifacts)?;
            }
            ImportKind::GitTree => plan_git_source(source, &root, &mut artifacts)?,
        }
    }

    artifacts.sort_by(|left, right| {
        (
            &left.relative_path,
            &left.category,
            &left.disposition,
            &left.id,
        )
            .cmp(&(
                &right.relative_path,
                &right.category,
                &right.disposition,
                &right.id,
            ))
    });
    let source_sha256 = sha256_bytes(&serde_json::to_vec(&artifacts)?);
    Ok(PlannedSource {
        name: source.name.clone(),
        path: root.display().to_string(),
        kind: source.kind.as_str().to_string(),
        source_sha256,
        artifacts,
    })
}

fn plan_assistant_home(
    source: &ImportSource,
    root: &Path,
    target_db: &Path,
    artifacts: &mut Vec<PlannedArtifact>,
) -> Result<()> {
    anyhow::ensure!(
        root.is_dir(),
        "assistant home is not a directory: {}",
        root.display()
    );
    let files = collect_files(root, &[target_db.to_path_buf()], true)?;
    let vector_sidecars: BTreeSet<PathBuf> = files
        .iter()
        .filter(|path| is_vector_tree(path) && is_text_sidecar(path))
        .cloned()
        .collect();

    for path in files {
        let ext = extension(&path);
        if is_sensitive_path(&path) {
            let references = discover_credential_references(&path)?;
            artifacts.push(make_file_artifact(
                source,
                root,
                &path,
                ArtifactCategory::CredentialReference,
                ArtifactDisposition::CredentialChecklist,
                "credential reference only; value bytes are never copied",
                references,
            )?);
            continue;
        }
        if file_name(&path) == "config.toml" {
            artifacts.push(make_file_artifact(
                source,
                root,
                &path,
                ArtifactCategory::Config,
                ArtifactDisposition::StageReview,
                "foreign config staged for operator review; never activated",
                Vec::new(),
            )?);
            let references = discover_credential_references(&path)?
                .into_iter()
                .filter(|reference| reference.starts_with("key:"))
                .collect::<Vec<_>>();
            if !references.is_empty() {
                artifacts.push(make_file_artifact(
                    source,
                    root,
                    &path,
                    ArtifactCategory::CredentialReference,
                    ArtifactDisposition::CredentialChecklist,
                    "credential keys referenced by config; values omitted",
                    references,
                )?);
            }
            continue;
        }
        if is_agent_file(&path) {
            artifacts.push(make_file_artifact(
                source,
                root,
                &path,
                ArtifactCategory::Agent,
                ArtifactDisposition::StageReview,
                "foreign agent staged for review; never activated",
                Vec::new(),
            )?);
            push_credential_keys(source, root, &path, artifacts)?;
            continue;
        }
        if is_skill_file(&path) {
            artifacts.push(make_file_artifact(
                source,
                root,
                &path,
                ArtifactCategory::Skill,
                ArtifactDisposition::StageReview,
                "foreign skill staged for review; never activated",
                Vec::new(),
            )?);
            push_credential_keys(source, root, &path, artifacts)?;
            continue;
        }
        if is_vector_tree(&path) || is_raw_vector(&path) {
            let disposition = if is_text_sidecar(&path)
                || vector_sidecars
                    .iter()
                    .any(|sidecar| same_vector_store(&path, sidecar))
            {
                ArtifactDisposition::QueueReembedding
            } else {
                ArtifactDisposition::BlockedUnsupported
            };
            let detail = if disposition == ArtifactDisposition::QueueReembedding {
                "text/metadata sidecar queued for NEOTH re-embedding; raw vector bytes are not copied"
            } else {
                "raw vectors have no extractable text/metadata sidecar; dimension/model compatibility is unknown"
            };
            artifacts.push(make_file_artifact(
                source,
                root,
                &path,
                ArtifactCategory::Vector,
                disposition,
                detail,
                Vec::new(),
            )?);
            continue;
        }
        if matches!(ext.as_str(), "db" | "sqlite" | "sqlite3") {
            if sqlite_magic(&path) {
                if sqlite_has_table(&path, "cron_jobs")? {
                    artifacts.push(make_file_artifact(
                        source,
                        root,
                        &path,
                        ArtifactCategory::Cron,
                        ArtifactDisposition::StageReview,
                        "OpenHuman cron_jobs exported for review; jobs remain disabled/uninstalled",
                        Vec::new(),
                    )?);
                }
                artifacts.push(make_file_artifact(
                    source,
                    root,
                    &path,
                    ArtifactCategory::Sql,
                    ArtifactDisposition::ImportTransactional,
                    "supported SQLite text memory imported transactionally; runtime tables excluded",
                    Vec::new(),
                )?);
            } else {
                artifacts.push(make_file_artifact(
                    source,
                    root,
                    &path,
                    ArtifactCategory::Unsupported,
                    ArtifactDisposition::BlockedUnsupported,
                    "SQLite extension is present but the file has no valid SQLite header",
                    Vec::new(),
                )?);
            }
            continue;
        }
        let category = match ext.as_str() {
            "md" | "markdown" => Some(ArtifactCategory::Markdown),
            "json" | "ajson" | "jsonl" | "ndjson" => Some(ArtifactCategory::Json),
            _ => None,
        };
        if let Some(category) = category {
            artifacts.push(make_file_artifact(
                source,
                root,
                &path,
                category,
                ArtifactDisposition::ImportTransactional,
                "candidate memory import",
                Vec::new(),
            )?);
        }
    }
    Ok(())
}

fn plan_vector_source(
    source: &ImportSource,
    root: &Path,
    artifacts: &mut Vec<PlannedArtifact>,
) -> Result<()> {
    let files = if root.is_dir() {
        collect_files(root, &[], false)?
    } else {
        vec![root.to_path_buf()]
    };
    let sidecars: Vec<PathBuf> = files
        .iter()
        .filter(|path| is_text_sidecar(path))
        .cloned()
        .collect();
    if files.is_empty() {
        artifacts.push(make_virtual_artifact(
            source,
            root,
            ArtifactCategory::Unsupported,
            ArtifactDisposition::BlockedUnsupported,
            "vector source contains no readable files",
        ));
        return Ok(());
    }
    for path in files {
        let supported = is_text_sidecar(&path) || (!sidecars.is_empty() && is_raw_vector(&path));
        artifacts.push(make_file_artifact(
            source,
            root,
            &path,
            ArtifactCategory::Vector,
            if supported {
                ArtifactDisposition::QueueReembedding
            } else {
                ArtifactDisposition::BlockedUnsupported
            },
            if supported {
                "source has extractable text/metadata for NEOTH re-embedding; raw vectors are not copied"
            } else {
                "raw vector source has no extractable text/metadata; dimension/model compatibility is unknown"
            },
            sidecars
                .iter()
                .map(|sidecar| sidecar.display().to_string())
                .collect(),
        )?);
    }
    Ok(())
}

fn plan_git_source(
    source: &ImportSource,
    root: &Path,
    artifacts: &mut Vec<PlannedArtifact>,
) -> Result<()> {
    let mut heads = Vec::new();
    if root.join(".git/HEAD").is_file() {
        heads.push(root.join(".git/HEAD"));
    }
    if root.is_dir() {
        for entry in std::fs::read_dir(root)? {
            let path = entry?.path().join(".git/HEAD");
            if path.is_file() {
                heads.push(path);
            }
        }
    }
    heads.sort();
    if heads.is_empty() {
        artifacts.push(make_virtual_artifact(
            source,
            root,
            ArtifactCategory::Unsupported,
            ArtifactDisposition::BlockedUnsupported,
            "git inventory contains no repository HEAD",
        ));
    } else {
        for head in heads {
            artifacts.push(make_file_artifact(
                source,
                root,
                &head,
                ArtifactCategory::Unsupported,
                ArtifactDisposition::BlockedUnsupported,
                "git trees are inventoried but not applied by the v1 migrator",
                Vec::new(),
            )?);
        }
    }
    Ok(())
}

fn make_file_artifact(
    source: &ImportSource,
    root: &Path,
    path: &Path,
    category: ArtifactCategory,
    disposition: ArtifactDisposition,
    detail: &str,
    mut references: Vec<String>,
) -> Result<PlannedArtifact> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("read artifact metadata {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "artifact is not a regular file: {}",
        path.display()
    );
    let sqlite_bundle =
        matches!(category, ArtifactCategory::Sql | ArtifactCategory::Cron) && sqlite_magic(path);
    let (source_sha256, byte_len) = if sqlite_bundle {
        sha256_sqlite_bundle(path)?
    } else {
        (sha256_file(path)?, metadata.len())
    };
    references.sort();
    references.dedup();
    let relative_path = normalise_relative(root, path);
    let id_material = serde_json::to_vec(&serde_json::json!({
        "source": &source.name,
        "relative_path": &relative_path,
        "category": &category,
        "disposition": &disposition,
        "source_sha256": &source_sha256,
        "references": &references,
    }))?;
    Ok(PlannedArtifact {
        id: sha256_bytes(&id_material),
        source_name: source.name.clone(),
        relative_path,
        path: path.display().to_string(),
        category,
        disposition,
        source_sha256,
        byte_len,
        detail: detail.to_string(),
        references,
    })
}

fn make_virtual_artifact(
    source: &ImportSource,
    path: &Path,
    category: ArtifactCategory,
    disposition: ArtifactDisposition,
    detail: &str,
) -> PlannedArtifact {
    let material = format!(
        "{}\0{}\0{:?}\0{:?}\0{}",
        source.name,
        path.display(),
        category,
        disposition,
        detail
    );
    PlannedArtifact {
        id: sha256_bytes(material.as_bytes()),
        source_name: source.name.clone(),
        relative_path: ".".to_string(),
        path: path.display().to_string(),
        category,
        disposition,
        source_sha256: sha256_bytes(&[]),
        byte_len: 0,
        detail: detail.to_string(),
        references: Vec::new(),
    }
}

fn push_credential_keys(
    source: &ImportSource,
    root: &Path,
    path: &Path,
    artifacts: &mut Vec<PlannedArtifact>,
) -> Result<()> {
    let references = discover_credential_references(path)?
        .into_iter()
        .filter(|reference| reference.starts_with("key:"))
        .collect::<Vec<_>>();
    if !references.is_empty() {
        artifacts.push(make_file_artifact(
            source,
            root,
            path,
            ArtifactCategory::CredentialReference,
            ArtifactDisposition::CredentialChecklist,
            "credential keys referenced by runtime artifact; values omitted",
            references,
        )?);
    }
    Ok(())
}

fn render_runtime_artifact(
    review: &Path,
    artifact: &PlannedArtifact,
) -> Result<(PathBuf, Vec<u8>)> {
    let category = match artifact.category {
        ArtifactCategory::Config => "config",
        ArtifactCategory::Cron => "cron",
        ArtifactCategory::Agent => "agents",
        ArtifactCategory::Skill => "skills",
        _ => "runtime",
    };
    let dir = review.join(category);
    ensure_private_dir(&dir)?;

    let payload = if artifact.category == ArtifactCategory::Cron {
        extract_openhuman_crons(Path::new(&artifact.path))?
    } else {
        let text = if artifact.byte_len <= MAX_REVIEW_TEXT_BYTES {
            std::fs::read_to_string(&artifact.path)
                .ok()
                .map(|value| sanitise_review_text(&value))
        } else {
            None
        };
        serde_json::json!({
            "artifact": artifact,
            "status": "quarantined_for_review",
            "activated": false,
            "sanitised_text": text,
            "source_too_large_for_inline_review": artifact.byte_len > MAX_REVIEW_TEXT_BYTES
        })
    };
    Ok((
        dir.join(format!("{}.json", artifact.id)),
        serde_json::to_vec_pretty(&payload)?,
    ))
}

fn extract_openhuman_crons(path: &Path) -> Result<serde_json::Value> {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .with_context(|| format!("open OpenHuman cron database {}", path.display()))?;
    let columns: HashSet<String> = {
        let mut statement = connection.prepare("PRAGMA table_info(cron_jobs)")?;
        statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<_>>()?
    };
    let wanted = [
        "id",
        "expression",
        "command",
        "schedule",
        "job_type",
        "prompt",
        "name",
        "session_target",
        "model",
        "enabled",
        "delivery",
        "delete_after_run",
        "agent_id",
    ];
    let selected: Vec<&str> = wanted
        .into_iter()
        .filter(|column| columns.contains(*column))
        .collect();
    anyhow::ensure!(
        !selected.is_empty(),
        "cron_jobs table has no recognised columns"
    );
    let query = format!(
        "SELECT {} FROM cron_jobs ORDER BY id",
        selected
            .iter()
            .map(|column| format!("\"{}\"", column))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let mut statement = connection.prepare(&query)?;
    let rows = statement.query_map([], |row| {
        let mut object = serde_json::Map::new();
        for (index, column) in selected.iter().enumerate() {
            let value = match row.get_ref(index)? {
                rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                rusqlite::types::ValueRef::Integer(value) => value.into(),
                rusqlite::types::ValueRef::Real(value) => value.into(),
                rusqlite::types::ValueRef::Text(value) => {
                    let value = String::from_utf8_lossy(value).into_owned();
                    if sensitive_text(&value) {
                        serde_json::Value::String("[REDACTED: review original source]".to_string())
                    } else {
                        serde_json::Value::String(value)
                    }
                }
                rusqlite::types::ValueRef::Blob(_) => {
                    serde_json::Value::String("[BINARY OMITTED]".to_string())
                }
            };
            object.insert((*column).to_string(), value);
        }
        Ok(serde_json::Value::Object(object))
    })?;
    let jobs = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(serde_json::json!({
        "status": "quarantined_for_review",
        "activated": false,
        "source": path.display().to_string(),
        "jobs": jobs
    }))
}

fn verify_artifact_source(artifact: &PlannedArtifact) -> Result<()> {
    if artifact.byte_len == 0 && artifact.source_sha256 == sha256_bytes(&[]) {
        return Ok(());
    }
    let path = Path::new(&artifact.path);
    anyhow::ensure!(
        path.is_file(),
        "planned artifact disappeared: {}",
        path.display()
    );
    let metadata = std::fs::metadata(path)?;
    let (actual_hash, actual_len) = if matches!(
        artifact.category,
        ArtifactCategory::Sql | ArtifactCategory::Cron
    ) && sqlite_magic(path)
    {
        sha256_sqlite_bundle(path)?
    } else {
        (sha256_file(path)?, metadata.len())
    };
    anyhow::ensure!(
        actual_len == artifact.byte_len && actual_hash == artifact.source_sha256,
        "planned artifact changed after dry-run: {}",
        path.display()
    );
    Ok(())
}

fn verify_plan_hash(plan: &MigrationPlan) -> Result<()> {
    anyhow::ensure!(
        plan.schema_version == PLAN_SCHEMA_VERSION,
        "unsupported migration plan schema {}",
        plan.schema_version
    );
    let body = PlanBody {
        schema_version: plan.schema_version,
        manifest_sha256: &plan.manifest_sha256,
        acknowledge_unsupported: plan.acknowledge_unsupported,
        sources: &plan.sources,
    };
    let actual = sha256_bytes(&serde_json::to_vec(&body)?);
    anyhow::ensure!(
        actual == plan.plan_sha256,
        "migration plan hash mismatch: expected {}, computed {}",
        plan.plan_sha256,
        actual
    );
    Ok(())
}

fn plan_path(home: &Path, hash: &str) -> PathBuf {
    migration_root(home)
        .join("plans")
        .join(format!("{hash}.json"))
}

fn migration_root(home: &Path) -> PathBuf {
    home.join(".neoth").join("migrations")
}

fn review_dir(home: &Path, plan: &MigrationPlan) -> PathBuf {
    migration_root(home).join("review").join(&plan.plan_sha256)
}

fn marker_dir(home: &Path, plan: &MigrationPlan) -> PathBuf {
    migration_root(home).join("state").join(&plan.plan_sha256)
}

fn artifact_marker_exists(home: &Path, plan: &MigrationPlan, artifact: &PlannedArtifact) -> bool {
    marker_dir(home, plan)
        .join(format!("{}.done", artifact.id))
        .is_file()
}

fn write_artifact_marker(
    home: &Path,
    plan: &MigrationPlan,
    artifact: &PlannedArtifact,
) -> Result<()> {
    write_immutable_private(
        &marker_dir(home, plan).join(format!("{}.done", artifact.id)),
        artifact.source_sha256.as_bytes(),
    )
}

fn target_db_binding(path: &Path) -> String {
    format!("{}\n", path.display())
}

fn write_immutable_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("private path has no parent: {}", path.display()))?;
    ensure_private_dir(parent)?;
    if path.exists() {
        let existing = std::fs::read(path)
            .with_context(|| format!("read immutable private file {}", path.display()))?;
        anyhow::ensure!(
            existing == bytes,
            "immutable migration state collision at {}",
            path.display()
        );
        return Ok(());
    }
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("migration-state");
    let sequence = PRIVATE_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(
        ".{file_name}.tmp-{}-{sequence}",
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let write_result = (|| -> Result<()> {
        let mut file = options
            .open(&temp)
            .with_context(|| format!("create private migration temp {}", temp.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write private migration temp {}", temp.display()))?;
        file.sync_all()
            .with_context(|| format!("sync private migration temp {}", temp.display()))?;
        drop(file);
        match std::fs::rename(&temp, path) {
            Ok(()) => sync_parent(parent),
            Err(_error) if path.exists() => {
                let existing = std::fs::read(path).with_context(|| {
                    format!("read raced immutable migration file {}", path.display())
                })?;
                anyhow::ensure!(
                    existing == bytes,
                    "immutable migration state collision at {}",
                    path.display()
                );
                Ok(())
            }
            Err(error) => Err(error)
                .with_context(|| format!("commit private migration file {}", path.display())),
        }
    })();
    if temp.exists() {
        let _ = std::fs::remove_file(&temp);
    }
    write_result
}

fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)
            .with_context(|| format!("open migration directory for sync {}", path.display()))?
            .sync_all()
            .with_context(|| format!("sync migration directory {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("create private migration directory {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 migration directory {}", path.display()))?;
    }
    Ok(())
}

fn collect_files(
    root: &Path,
    exclusions: &[PathBuf],
    assistant_home: bool,
) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    collect_files_inner(root, exclusions, assistant_home, &mut out)?;
    out.sort();
    Ok(out)
}

fn collect_files_inner(
    path: &Path,
    exclusions: &[PathBuf],
    assistant_home: bool,
    out: &mut Vec<PathBuf>,
) -> Result<()> {
    if exclusions
        .iter()
        .any(|excluded| path == excluded || path.starts_with(excluded))
    {
        return Ok(());
    }
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect migration source {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "migration source contains a symlink which cannot be hash-bound safely: {}. Declare its canonical target explicitly",
            path.display()
        );
    }
    if metadata.is_file() {
        out.push(path.to_path_buf());
        return Ok(());
    }
    anyhow::ensure!(
        metadata.is_dir(),
        "unsupported source node: {}",
        path.display()
    );
    if path != Path::new("") && is_noise_dir(path) {
        return Ok(());
    }
    let mut children = Vec::new();
    for entry in std::fs::read_dir(path)
        .with_context(|| format!("read migration source directory {}", path.display()))?
    {
        children.push(entry?.path());
    }
    children.sort();
    for child in children {
        if assistant_home && file_name(&child) == ".neoth" {
            continue;
        }
        collect_files_inner(&child, exclusions, assistant_home, out)?;
    }
    Ok(())
}

fn resolve_path(raw: &str, home: &Path) -> PathBuf {
    if raw == "~" {
        return home.to_path_buf();
    }
    if let Some(rest) = raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")) {
        return home.join(rest);
    }
    PathBuf::from(raw)
}

fn validate_assistant_hint(source: &ImportSource) -> Result<()> {
    let hint = source.hint.as_deref().unwrap_or_default();
    anyhow::ensure!(
        matches!(hint, "openclaw" | "hermes" | "openhuman" | "veronica"),
        "assistant_home source '{}' requires hint: openclaw | hermes | openhuman | veronica",
        source.name
    );
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("open {} for SHA-256", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("hash migration artifact {}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn sha256_sqlite_bundle(path: &Path) -> Result<(String, u64)> {
    let mut files = vec![path.to_path_buf()];
    let path_text = path.as_os_str().to_string_lossy();
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{path_text}{suffix}"));
        if sidecar.is_file() {
            files.push(sidecar);
        }
    }
    files.sort();
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    for file in files {
        let relative_name = file
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        digest.update((relative_name.len() as u64).to_le_bytes());
        digest.update(relative_name.as_bytes());
        let bytes = std::fs::read(&file)
            .with_context(|| format!("read SQLite bundle member {}", file.display()))?;
        total = total.saturating_add(bytes.len() as u64);
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(&bytes);
    }
    Ok((format!("{:x}", digest.finalize()), total))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn normalise_relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            Component::ParentDir => Some("..".to_string()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn path_component(path: &Path, needle: &str) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(needle)
    })
}

fn is_noise_dir(path: &Path) -> bool {
    matches!(
        file_name(path).as_str(),
        ".git" | "node_modules" | "target" | "cache" | "caches" | "logs" | "tmp" | "temp"
    )
}

fn is_agent_file(path: &Path) -> bool {
    path_component(path.parent().unwrap_or(path), "agents") && !path_component(path, "skills")
}

fn is_skill_file(path: &Path) -> bool {
    path_component(path, "skills")
}

fn is_sensitive_path(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component
                .as_os_str()
                .to_string_lossy()
                .to_ascii_lowercase()
                .as_str(),
            "auth"
                | "oauth"
                | "credential"
                | "credentials"
                | "secret"
                | "secrets"
                | "keychain"
                | "cookies"
                | ".ssh"
        )
    }) || {
        let name = file_name(path);
        name == ".env"
            || name.starts_with(".env.")
            || [
                "credential",
                "secret",
                "token",
                "password",
                "api_key",
                "apikey",
                "cookie",
            ]
            .iter()
            .any(|needle| name.contains(needle))
    }
}

fn sensitive_identifier(value: &str) -> bool {
    let compact: String = value
        .to_ascii_lowercase()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect();
    [
        "apikey",
        "secret",
        "token",
        "password",
        "passwd",
        "credential",
        "privatekey",
        "clientsecret",
        "cookie",
        "auth",
    ]
    .iter()
    .any(|needle| compact.contains(needle))
}

fn discover_credential_references(path: &Path) -> Result<Vec<String>> {
    let mut references = BTreeSet::new();
    references.insert(format!("file:{}", path.display()));
    if std::fs::metadata(path)?.len() > MAX_REVIEW_TEXT_BYTES {
        return Ok(references.into_iter().collect());
    }
    let Ok(body) = std::fs::read_to_string(path) else {
        return Ok(references.into_iter().collect());
    };
    let mut section = String::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed.trim_matches(&['[', ']'][..]).trim().to_string();
            continue;
        }
        let key = trimmed
            .split_once('=')
            .or_else(|| trimmed.split_once(':'))
            .map(|(key, _)| key.trim().trim_matches(['"', '\'']))
            .unwrap_or_default();
        if !key.is_empty() && sensitive_identifier(key) {
            references.insert(if section.is_empty() {
                format!("key:{key}")
            } else {
                format!("key:{section}.{key}")
            });
        }
    }
    Ok(references.into_iter().collect())
}

fn sanitise_review_text(body: &str) -> String {
    body.lines()
        .map(|line| {
            let trimmed = line.trim();
            let key = trimmed
                .split_once('=')
                .or_else(|| trimmed.split_once(':'))
                .map(|(key, _)| key.trim().trim_matches(['"', '\'']))
                .unwrap_or_default();
            if (!key.is_empty() && sensitive_identifier(key)) || sensitive_text(trimmed) {
                "[REDACTED: credential-bearing line]".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn sensitive_text(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("bearer ")
        || lower.contains("api_key=")
        || lower.contains("api-key=")
        || lower.contains("token=")
        || lower.contains("password=")
        || lower.contains("secret=")
}

fn is_vector_tree(path: &Path) -> bool {
    path.components().any(|component| {
        let value = component.as_os_str().to_string_lossy().to_ascii_lowercase();
        value.ends_with(".lance")
            || matches!(
                value.as_str(),
                "lancedb" | "vectors" | "vector" | "embeddings" | "faiss"
            )
    })
}

fn same_vector_store(left: &Path, right: &Path) -> bool {
    match (vector_store_root(left), vector_store_root(right)) {
        (Some(left), Some(right)) => left == right,
        _ => left.parent() == right.parent(),
    }
}

fn vector_store_root(path: &Path) -> Option<PathBuf> {
    let mut root = PathBuf::new();
    for component in path.components() {
        root.push(component.as_os_str());
        let value = component.as_os_str().to_string_lossy().to_ascii_lowercase();
        // A .lance directory is one concrete dataset. Generic names such as
        // `vectors/` are often containers for multiple independent indexes;
        // those fall back to same-parent matching in `same_vector_store`.
        if value.ends_with(".lance") {
            return Some(root);
        }
    }
    None
}

fn is_raw_vector(path: &Path) -> bool {
    matches!(
        extension(path).as_str(),
        "bin" | "faiss" | "index" | "npy" | "arrow" | "parquet" | "idx"
    )
}

fn is_text_sidecar(path: &Path) -> bool {
    matches!(
        extension(path).as_str(),
        "md" | "markdown"
            | "txt"
            | "json"
            | "jsonl"
            | "ndjson"
            | "csv"
            | "db"
            | "sqlite"
            | "sqlite3"
    )
}

fn sqlite_magic(path: &Path) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 16];
    file.read_exact(&mut magic).is_ok() && &magic == b"SQLite format 3\0"
}

fn sqlite_has_table(path: &Path, table: &str) -> Result<bool> {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
        [table],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn source(name: &str, path: &Path, kind: ImportKind, hint: Option<&str>) -> ImportSource {
        ImportSource {
            name: name.to_string(),
            path: path.display().to_string(),
            kind,
            hint: hint.map(str::to_string),
        }
    }

    #[test]
    fn plan_order_and_hash_are_deterministic() {
        let temp = tempdir().unwrap();
        let root = temp.path().join(".openhuman");
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        std::fs::write(root.join("workspace/z.md"), "A durable memory statement.").unwrap();
        std::fs::write(
            root.join("workspace/a.json"),
            r#"{"text":"Another durable memory."}"#,
        )
        .unwrap();
        let mut manifest = ImportManifest {
            sources: vec![source(
                "home",
                &root,
                ImportKind::AssistantHome,
                Some("openhuman"),
            )],
            acknowledge_unsupported: false,
        };
        let target = temp.path().join(".neoth/views.db");
        let first = build_plan(&manifest, temp.path(), &target).unwrap();
        manifest.sources.reverse();
        let second = build_plan(&manifest, temp.path(), &target).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.sources[0].artifacts[0].relative_path,
            "workspace/a.json"
        );
    }

    #[test]
    fn changed_source_requires_a_new_reviewed_plan() {
        let temp = tempdir().unwrap();
        let source_path = temp.path().join("notes.md");
        std::fs::write(&source_path, "Initial migration content.").unwrap();
        let manifest = ImportManifest {
            sources: vec![source(
                "notes",
                &source_path,
                ImportKind::MarkdownFile,
                None,
            )],
            acknowledge_unsupported: false,
        };
        let target = temp.path().join(".neoth/views.db");
        let reviewed = build_plan(&manifest, temp.path(), &target).unwrap();
        checkpoint_plan(temp.path(), &reviewed).unwrap();
        std::fs::write(&source_path, "Mutated migration content.").unwrap();
        let current = build_plan(&manifest, temp.path(), &target).unwrap();
        assert_ne!(reviewed.plan_sha256, current.plan_sha256);
        assert!(require_checkpoint(temp.path(), &current).is_err());
    }

    #[test]
    fn openhuman_runtime_discovery_is_complete_and_secret_values_never_enter_plan() {
        let temp = tempdir().unwrap();
        let root = temp.path().join(".openhuman");
        std::fs::create_dir_all(root.join("workspace/agents")).unwrap();
        std::fs::create_dir_all(root.join("workspace/.agents/skills/mail")).unwrap();
        std::fs::write(
            root.join("config.toml"),
            "default_model = \"local\"\napi_key = \"DO_NOT_COPY_ME\"\n",
        )
        .unwrap();
        std::fs::write(
            root.join("workspace/agents/research.toml"),
            "id = \"research\"\nsystem_prompt = \"Investigate carefully\"\napi_key = \"AGENT_SECRET_VALUE\"\n",
        )
        .unwrap();
        std::fs::write(
            root.join("workspace/agents/prompt.md"),
            "Reusable external agent prompt.",
        )
        .unwrap();
        std::fs::write(
            root.join("workspace/.agents/skills/mail/SKILL.md"),
            "---\nname: mail\ndescription: Mail helper\n---\nUse mail safely.",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("workspace/.agents/skills/mail/assets")).unwrap();
        std::fs::write(
            root.join("workspace/.agents/skills/mail/assets/logo.png"),
            [0_u8, 159, 146, 150],
        )
        .unwrap();
        let db = root.join("state.db");
        let connection = rusqlite::Connection::open(&db).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE cron_jobs (id TEXT, expression TEXT, command TEXT, schedule TEXT, job_type TEXT, prompt TEXT, name TEXT, session_target TEXT, model TEXT, enabled INTEGER, delivery TEXT, delete_after_run INTEGER);\n                 INSERT INTO cron_jobs VALUES ('one','0 * * * *','echo ok','{\"kind\":\"cron\",\"expr\":\"0 * * * *\"}','shell',NULL,'hourly','isolated',NULL,1,'{\"mode\":\"none\"}',0);\n                 CREATE TABLE memories (content TEXT);\n                 INSERT INTO memories VALUES ('Imported SQL memory content.');",
            )
            .unwrap();
        drop(connection);
        let manifest = ImportManifest {
            sources: vec![source(
                "home",
                &root,
                ImportKind::AssistantHome,
                Some("openhuman"),
            )],
            acknowledge_unsupported: false,
        };
        let plan =
            build_plan(&manifest, temp.path(), &temp.path().join(".neoth/views.db")).unwrap();
        let categories: BTreeSet<_> = plan.sources[0]
            .artifacts
            .iter()
            .map(|artifact| artifact.category.clone())
            .collect();
        assert!(categories.contains(&ArtifactCategory::Config));
        assert!(categories.contains(&ArtifactCategory::Cron));
        assert!(categories.contains(&ArtifactCategory::Agent));
        assert!(categories.contains(&ArtifactCategory::Skill));
        assert!(categories.contains(&ArtifactCategory::CredentialReference));
        assert!(categories.contains(&ArtifactCategory::Sql));
        let serialised = serde_json::to_string(&plan).unwrap();
        assert!(!serialised.contains("DO_NOT_COPY_ME"));
        assert!(!serialised.contains("AGENT_SECRET_VALUE"));
        assert!(serialised.contains("api_key"));
        assert!(
            plan.sources[0]
                .artifacts
                .iter()
                .any(|artifact| artifact.relative_path.ends_with("agents/prompt.md"))
        );
        assert!(
            plan.sources[0]
                .artifacts
                .iter()
                .any(|artifact| artifact.relative_path.ends_with("assets/logo.png"))
        );

        checkpoint_plan(temp.path(), &plan).unwrap();
        stage_review_artifacts(temp.path(), &plan).unwrap();
        let review_files = collect_files(&review_dir(temp.path(), &plan), &[], false).unwrap();
        let review_body = review_files
            .iter()
            .filter_map(|path| std::fs::read_to_string(path).ok())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !review_body.contains("DO_NOT_COPY_ME"),
            "credential value leaked into private plan/review output"
        );
        assert!(!review_body.contains("AGENT_SECRET_VALUE"));
        assert!(review_body.contains("credential-bearing line"));
        let cron_body = review_files
            .iter()
            .find(|path| path.components().any(|part| part.as_os_str() == "cron"))
            .and_then(|path| std::fs::read_to_string(path).ok())
            .expect("plan-bound cron review export");
        for field in [
            "expression",
            "command",
            "schedule",
            "job_type",
            "prompt",
            "name",
            "session_target",
            "model",
            "enabled",
            "delivery",
            "delete_after_run",
        ] {
            assert!(
                cron_body.contains(field),
                "missing cron review field {field}"
            );
        }
        assert!(cron_body.contains("\"activated\": false"));
    }

    #[test]
    fn vector_disposition_requires_text_or_metadata() {
        let temp = tempdir().unwrap();
        let vector = temp.path().join("vectors");
        std::fs::create_dir_all(&vector).unwrap();
        std::fs::write(vector.join("index.faiss"), [0_u8; 32]).unwrap();
        let mut manifest = ImportManifest {
            sources: vec![source("vector", &vector, ImportKind::FaissFlat, None)],
            acknowledge_unsupported: false,
        };
        let target = temp.path().join(".neoth/views.db");
        let blocked = build_plan(&manifest, temp.path(), &target).unwrap();
        assert_eq!(blocked_artifacts(&blocked).len(), 1);
        std::fs::write(vector.join("metadata.jsonl"), "{\"text\":\"recover me\"}\n").unwrap();
        let supported = build_plan(&manifest, temp.path(), &target).unwrap();
        assert!(blocked_artifacts(&supported).is_empty());
        assert!(
            supported.sources[0]
                .artifacts
                .iter()
                .all(|artifact| { artifact.disposition == ArtifactDisposition::QueueReembedding })
        );

        manifest.acknowledge_unsupported = true;
        std::fs::remove_file(vector.join("metadata.jsonl")).unwrap();
        let acknowledged = build_plan(&manifest, temp.path(), &target).unwrap();
        checkpoint_plan(temp.path(), &acknowledged).unwrap();
        let summary = stage_review_artifacts(temp.path(), &acknowledged).unwrap();
        assert_eq!(summary.acknowledged_unsupported, 1);
    }

    #[test]
    fn assistant_vector_sidecar_only_unlocks_its_own_store() {
        let temp = tempdir().unwrap();
        let root = temp.path().join(".openhuman");
        let first = root.join("vectors/first");
        let second = root.join("vectors/second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        std::fs::write(first.join("index.faiss"), [1_u8; 16]).unwrap();
        std::fs::write(second.join("index.faiss"), [2_u8; 16]).unwrap();
        std::fs::write(second.join("metadata.jsonl"), "{\"text\":\"second\"}\n").unwrap();
        let manifest = ImportManifest {
            sources: vec![source(
                "home",
                &root,
                ImportKind::AssistantHome,
                Some("openhuman"),
            )],
            acknowledge_unsupported: false,
        };
        let plan =
            build_plan(&manifest, temp.path(), &temp.path().join(".neoth/views.db")).unwrap();
        let first_raw = plan.sources[0]
            .artifacts
            .iter()
            .find(|artifact| artifact.relative_path == "vectors/first/index.faiss")
            .unwrap();
        let second_raw = plan.sources[0]
            .artifacts
            .iter()
            .find(|artifact| artifact.relative_path == "vectors/second/index.faiss")
            .unwrap();
        assert_eq!(
            first_raw.disposition,
            ArtifactDisposition::BlockedUnsupported
        );
        assert_eq!(
            second_raw.disposition,
            ArtifactDisposition::QueueReembedding
        );
    }

    #[test]
    fn malformed_assistant_sqlite_is_explicitly_blocked() {
        let temp = tempdir().unwrap();
        let root = temp.path().join(".openhuman");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("broken.db"), b"not sqlite").unwrap();
        let manifest = ImportManifest {
            sources: vec![source(
                "home",
                &root,
                ImportKind::AssistantHome,
                Some("openhuman"),
            )],
            acknowledge_unsupported: false,
        };
        let plan =
            build_plan(&manifest, temp.path(), &temp.path().join(".neoth/views.db")).unwrap();
        let blocked = blocked_artifacts(&plan);
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].relative_path, "broken.db");
        assert!(blocked[0].detail.contains("no valid SQLite header"));
    }

    #[test]
    fn resume_markers_and_staging_are_idempotent() {
        let temp = tempdir().unwrap();
        let root = temp.path().join(".openhuman");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("config.toml"), "model = \"local\"\n").unwrap();
        let manifest = ImportManifest {
            sources: vec![source(
                "home",
                &root,
                ImportKind::AssistantHome,
                Some("openhuman"),
            )],
            acknowledge_unsupported: false,
        };
        let target = temp.path().join(".neoth/views.db");
        let plan = build_plan(&manifest, temp.path(), &target).unwrap();
        checkpoint_plan(temp.path(), &plan).unwrap();
        mark_memory_committed(temp.path(), &plan, &target).unwrap();
        assert!(memory_already_committed(temp.path(), &plan, &target).unwrap());
        let first = stage_review_artifacts(temp.path(), &plan).unwrap();
        let second = stage_review_artifacts(temp.path(), &plan).unwrap();
        assert_eq!(first.staged, 1);
        assert_eq!(second.resumed, 1);
        mark_complete(temp.path(), &plan).unwrap();
        let status = load_plan_status(temp.path()).unwrap();
        assert_eq!(status.state, "complete");
        assert_eq!(status.artifacts_total, status.artifacts_committed);
    }
}
