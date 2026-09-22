//! Read-only CRG-03 acquisition-to-impact receipt for prompt consumers.
//!
//! This bridge owns no database writes and retains no unified diff text.  It
//! binds the explicit root to its persisted physical identity before mapping,
//! then relies on the impact service's final generation/freshness fence.

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::diff::MAX_DIFF_BYTES;
use super::diff_git::{
    AcquiredDiff, DiffImpactSeed, GitDiffSource, acquire_git_diff,
    map_acquired_diff_to_indexed_impact_seeds, parse_stdin_diff,
};
use super::impact::{ImpactOptions, ImpactResult, ImpactSeed, impact_radius_for_diff_seeds};
use super::persist::{index_freshness_receipt, load_map, root_snapshot_complete};
use super::recall::{RootGenerationSnapshot, resolve_active_root_snapshot};
use super::root_identity::CanonicalRepoRoot;

/// Maximum identities copied from the graph result into a coding citation.
/// The complete impact result stays available to CLI/MCP rendering; a coding
/// prompt gets a bounded, explicitly marked advisory projection only.
pub const MAX_CITATION_AFFECTED_IDENTITIES: usize = 96;

/// One explicit diff input.  `stdin_diff` is transient and is never embedded
/// in [`DiffImpactReceipt`] or any durable coding receipt.
#[derive(Clone, PartialEq, Eq)]
pub struct DiffImpactInput {
    pub source: GitDiffSource,
    pub stdin_diff: Option<String>,
}

impl fmt::Debug for DiffImpactInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (source_kind, committed_ref_bytes) = match &self.source {
            GitDiffSource::WorkingTree => ("working_tree", None),
            GitDiffSource::Staged => ("staged", None),
            GitDiffSource::Committed { base, target } => {
                ("committed", Some((base.len(), target.len())))
            }
            GitDiffSource::Stdin => ("stdin", None),
        };
        formatter
            .debug_struct("DiffImpactInput")
            .field("source_kind", &source_kind)
            .field("committed_ref_bytes", &committed_ref_bytes)
            .field("stdin_bytes", &self.stdin_diff.as_ref().map(String::len))
            .finish()
    }
}

impl DiffImpactInput {
    pub fn working_tree() -> Self {
        Self {
            source: GitDiffSource::WorkingTree,
            stdin_diff: None,
        }
    }

    pub fn staged() -> Self {
        Self {
            source: GitDiffSource::Staged,
            stdin_diff: None,
        }
    }

    pub fn committed(base: String, target: String) -> Self {
        Self {
            source: GitDiffSource::Committed { base, target },
            stdin_diff: None,
        }
    }

    pub fn stdin(diff: String) -> Self {
        Self {
            source: GitDiffSource::Stdin,
            stdin_diff: Some(diff),
        }
    }

    fn acquire(&self, root: &std::path::Path) -> Result<AcquiredDiff> {
        match &self.source {
            GitDiffSource::Stdin => {
                let diff = self
                    .stdin_diff
                    .as_deref()
                    .context("stdin diff source requires captured input")?;
                ensure!(
                    diff.len() <= MAX_DIFF_BYTES,
                    "stdin diff exceeds {} bytes",
                    MAX_DIFF_BYTES
                );
                parse_stdin_diff(diff)
            }
            _ => {
                ensure!(
                    self.stdin_diff.is_none(),
                    "non-stdin diff source must not carry stdin input"
                );
                acquire_git_diff(root, self.source.clone())
            }
        }
    }
}

/// Explicit source and traversal bounds for one read-only analysis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffImpactRequest {
    pub repo_root: PathBuf,
    pub input: DiffImpactInput,
    pub options: ImpactOptions,
}

/// Serializable source descriptor without a raw unified diff.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffImpactSourceDescriptor {
    WorkingTree,
    Staged,
    Committed { base: String, target: String },
    Stdin,
}

impl From<&GitDiffSource> for DiffImpactSourceDescriptor {
    fn from(source: &GitDiffSource) -> Self {
        match source {
            GitDiffSource::WorkingTree => Self::WorkingTree,
            GitDiffSource::Staged => Self::Staged,
            GitDiffSource::Committed { base, target } => Self::Committed {
                base: base.clone(),
                target: target.clone(),
            },
            GitDiffSource::Stdin => Self::Stdin,
        }
    }
}

/// One deterministic seed retained without source text.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DiffImpactSeedReceipt {
    pub file: String,
    pub symbol: Option<String>,
}

impl From<&ImpactSeed> for DiffImpactSeedReceipt {
    fn from(seed: &ImpactSeed) -> Self {
        Self {
            file: seed.file.clone(),
            symbol: seed.symbol.clone(),
        }
    }
}

/// Read-only result.  `root_snapshot_complete` and `prompt_admissible` are
/// separate because CLI/MCP may render a truthful partial snapshot while a
/// coding provider must never receive it.
#[derive(Clone, Debug, PartialEq)]
pub struct DiffImpactReceipt {
    pub root: CanonicalRepoRoot,
    pub index_generation: i64,
    pub graph_generation: i64,
    pub root_snapshot_complete: bool,
    pub source: DiffImpactSourceDescriptor,
    /// SHA-256 of the acquired unified-diff bytes. Never raw diff text.
    pub diff_sha256: String,
    pub exact_symbol_seeds: Vec<DiffImpactSeedReceipt>,
    pub file_fallback_seeds: Vec<DiffImpactSeedReceipt>,
    pub impact: ImpactResult,
    /// Display-only stale analysis is never prompt authority.
    pub allow_stale: bool,
    pub prompt_admissible: bool,
}

impl DiffImpactReceipt {
    pub fn snapshot(&self) -> RootGenerationSnapshot {
        RootGenerationSnapshot {
            root: self.root.clone(),
            index_generation: self.index_generation,
            graph_generation: self.graph_generation,
        }
    }

    /// Refuse the receipt at the coding boundary.  Traversal uncertainty is
    /// retained as visible citation data; root partiality, stale analysis,
    /// identity drift, or mismatched generations are never advisory.
    pub fn require_prompt_admissible(&self) -> Result<()> {
        ensure!(
            self.prompt_admissible,
            "diff-impact receipt is not admissible for coding prompt context"
        );
        ensure!(
            self.root_snapshot_complete,
            "partial code-map scan cannot enter coding prompt context"
        );
        ensure!(
            !self.allow_stale && !self.impact.stale,
            "stale diff-impact receipt cannot enter coding prompt context"
        );
        ensure!(
            self.index_generation > 0
                && self.index_generation == self.graph_generation
                && self.impact.index_generation == self.index_generation
                && self.impact.graph_generation == self.graph_generation,
            "diff-impact receipt generation binding is invalid"
        );
        Ok(())
    }
}

/// Acquire, map and traverse an explicit diff against one persisted root.
///
/// This function intentionally permits `allow_stale` only so read-only CLI or
/// MCP callers can display the result.  Consumers that construct provider
/// input must call [`DiffImpactReceipt::require_prompt_admissible`].
pub fn analyze_diff_impact(
    conn: &Connection,
    request: &DiffImpactRequest,
) -> Result<DiffImpactReceipt> {
    let canonical = CanonicalRepoRoot::discover(&request.repo_root)?;
    let before = resolve_active_root_snapshot(conn, canonical.path())?
        .context("explicit diff-impact root has no persisted code-map snapshot")?;
    ensure!(
        before.root == canonical,
        "persisted code-map root identity does not match explicit diff-impact root"
    );
    ensure!(
        before.index_generation > 0 && before.index_generation == before.graph_generation,
        "explicit diff-impact root has mismatched or non-positive map generations"
    );
    let complete_before = root_snapshot_complete(conn, before.root.display())?;
    let freshness_before = index_freshness_receipt(conn, before.root.display())?;
    if freshness_before.stale && !request.options.allow_stale {
        anyhow::bail!("explicit diff-impact root is stale; rebuild before analysis");
    }
    let indexed = load_map(conn, before.root.display())?
        .context("explicit diff-impact root disappeared before seed mapping")?;

    let acquired = request.input.acquire(canonical.path())?;
    ensure!(
        acquired.source == request.input.source,
        "acquired diff source changed during analysis"
    );
    let seeds = map_acquired_diff_to_indexed_impact_seeds(canonical.path(), &acquired, &indexed)?;
    ensure!(
        !seeds.is_empty(),
        "explicit diff-impact input produced no mappable seeds"
    );
    let after_mapping = resolve_active_root_snapshot(conn, canonical.path())?
        .context("explicit diff-impact root disappeared during seed mapping")?;
    ensure!(
        after_mapping == before,
        "code-map root identity or generation changed during diff seed mapping"
    );
    ensure!(
        CanonicalRepoRoot::discover(canonical.path())? == canonical,
        "physical diff-impact root changed during seed mapping"
    );

    let impact = impact_radius_for_diff_seeds(conn, canonical.path(), &seeds, request.options)?;
    ensure!(
        impact.root == canonical.display(),
        "impact result root differs from explicit diff-impact root"
    );
    ensure!(
        impact.index_generation == before.index_generation
            && impact.graph_generation == before.graph_generation,
        "impact result generation differs from mapped snapshot"
    );
    let after = resolve_active_root_snapshot(conn, canonical.path())?
        .context("explicit diff-impact root disappeared after traversal")?;
    ensure!(
        after == before,
        "code-map root identity or generation changed during diff impact traversal"
    );
    ensure!(
        CanonicalRepoRoot::discover(canonical.path())? == canonical,
        "physical diff-impact root changed during traversal"
    );
    let complete_after = root_snapshot_complete(conn, canonical.display())?;
    let freshness_after = index_freshness_receipt(conn, canonical.display())?;
    ensure!(
        freshness_before.filesystem_fingerprint == freshness_after.filesystem_fingerprint,
        "diff-impact filesystem changed during analysis"
    );

    let (exact_symbol_seeds, file_fallback_seeds) = split_seeds(&seeds);
    let prompt_admissible = complete_before
        && complete_after
        && !request.options.allow_stale
        && !impact.stale
        && !freshness_after.stale;
    Ok(DiffImpactReceipt {
        root: canonical,
        index_generation: before.index_generation,
        graph_generation: before.graph_generation,
        root_snapshot_complete: complete_before && complete_after,
        source: DiffImpactSourceDescriptor::from(&acquired.source),
        // Requires the bounded `diff_git` acquisition seam to retain only its
        // hash. W43's root-integration note adds that non-raw field.
        diff_sha256: acquired.diff_sha256,
        exact_symbol_seeds,
        file_fallback_seeds,
        impact,
        allow_stale: request.options.allow_stale,
        prompt_admissible,
    })
}

fn split_seeds(
    seeds: &[DiffImpactSeed],
) -> (Vec<DiffImpactSeedReceipt>, Vec<DiffImpactSeedReceipt>) {
    let mut exact = BTreeSet::new();
    let mut fallback = BTreeSet::new();
    for seed in seeds {
        let receipt = DiffImpactSeedReceipt::from(&seed.seed);
        if seed.exact_symbol {
            exact.insert(receipt);
        } else {
            fallback.insert(receipt);
        }
    }
    (exact.into_iter().collect(), fallback.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_map::snapshot::{RebuildOptions, rebuild_snapshot};
    use tempfile::tempdir;

    #[test]
    fn exact_and_fallback_seeds_stay_distinct_and_deterministic() {
        let seeds = vec![
            DiffImpactSeed {
                seed: ImpactSeed::file("src/z.rs"),
                exact_symbol: false,
            },
            DiffImpactSeed {
                seed: ImpactSeed::symbol("src/a.rs", "entry"),
                exact_symbol: true,
            },
            DiffImpactSeed {
                seed: ImpactSeed::file("src/z.rs"),
                exact_symbol: false,
            },
        ];
        let (exact, fallback) = split_seeds(&seeds);
        assert_eq!(
            exact,
            vec![DiffImpactSeedReceipt {
                file: "src/a.rs".into(),
                symbol: Some("entry".into())
            }]
        );
        assert_eq!(
            fallback,
            vec![DiffImpactSeedReceipt {
                file: "src/z.rs".into(),
                symbol: None
            }]
        );
    }

    #[test]
    fn context_spanning_diff_retains_file_fallback_and_cross_file_caller_edge() {
        let repo = tempdir().unwrap();
        std::fs::create_dir(repo.path().join("src")).unwrap();
        std::fs::write(
            repo.path().join("src/lib.rs"),
            "pub const DIFF_CONTEXT: &str = \"fixture\";\n\n\
             pub fn changed_symbol() -> &'static str {\n    \"after\"\n}\n",
        )
        .unwrap();
        std::fs::write(
            repo.path().join("src/caller.rs"),
            "pub fn caller_symbol() -> &'static str {\n    changed_symbol()\n}\n",
        )
        .unwrap();
        let root = CanonicalRepoRoot::discover(repo.path()).unwrap();
        let database_dir = tempdir().unwrap();
        let database = database_dir.path().join("code_map.db");
        let refreshed = rebuild_snapshot(&root, &database, RebuildOptions::default()).unwrap();
        let connection = super::super::persist::open_read_only(&database).unwrap();
        let request = DiffImpactRequest {
            repo_root: repo.path().to_path_buf(),
            input: DiffImpactInput::stdin(
                concat!(
                    "diff --git a/src/lib.rs b/src/lib.rs\n",
                    "--- a/src/lib.rs\n",
                    "+++ b/src/lib.rs\n",
                    "@@ -1,5 +1,5 @@\n",
                    " pub const DIFF_CONTEXT: &str = \"fixture\";\n",
                    "\n",
                    " pub fn changed_symbol() -> &'static str {\n",
                    "-    \"before\"\n",
                    "+    \"after\"\n",
                    " }\n",
                )
                .into(),
            ),
            options: ImpactOptions {
                direction: super::super::impact::ImpactDirection::Callers,
                max_depth: 1,
                max_nodes: 16,
                allow_stale: false,
            },
        };

        let receipt = analyze_diff_impact(&connection, &request).unwrap();
        assert_eq!(receipt.index_generation, refreshed.index_generation);
        assert_eq!(receipt.graph_generation, refreshed.graph_generation);
        assert_eq!(
            receipt.file_fallback_seeds,
            vec![DiffImpactSeedReceipt {
                file: "src/lib.rs".into(),
                symbol: None,
            }]
        );
        assert!(receipt.exact_symbol_seeds.is_empty());
        assert!(
            receipt.impact.impacted_nodes.iter().any(|node| {
                node.node.file == "src/caller.rs" && node.node.symbol == "caller_symbol"
            })
        );
        assert!(receipt.impact.traversed_edges.iter().any(|edge| {
            edge.caller.file == "src/caller.rs"
                && edge.caller.symbol == "caller_symbol"
                && edge.callee.file == "src/lib.rs"
                && edge.callee.symbol == "changed_symbol"
        }));
    }
}
