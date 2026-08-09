//! Coordinator for Graphify's pointer → SQLite → completion-WAL transaction.
//!
//! The publication layer owns the immutable generation and the `CURRENT`
//! transition.  This module owns only the boundary after that transition: it
//! binds a stable transaction id into SQLite, records the corresponding
//! publication-journal phase, then permits the caller's completion WAL to
//! become durable.  A missing or mixed SQLite state is never guessed during
//! recovery.

use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use rusqlite::Connection;

use crate::code_map::snapshot::CompanionSnapshotAttestation;
use crate::graphify_publish::{
    GraphifyGenerationReceipt, GraphifyPublicationIngestMode, GraphifyPublicationLease,
    GraphifyTransactionPhase, PublishedGraphifyPublication,
    discover_graphify_recovery_targets_under_lease, finish_recovered_transaction_under_lease,
    inspect_graphify_transaction_under_lease, load_current_graphify_generation_receipt,
    mark_recovered_graphify_ingest_phase_under_lease, recover_graphify_transaction_under_lease,
};
use crate::memory::groundtruth::list_for_scope;
use crate::wiki::{
    GraphifyIngestRevocation, GraphifyIngestScope, IngestStats,
    ingest_graphify_generation_for_scope_guarded, revoke_graphify_scope_for_no_ingest_guarded,
};

/// The only two allowed outcomes after Graphify moved `CURRENT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphifyIngestMode {
    /// Build fresh root-bound recall pointers for the published generation.
    Indexed,
    /// `--no-ingest`: revoke the prior root-bound pointer set and leave the
    /// generation visible only through its vault `CURRENT` pointer.
    SkippedAndRevoked,
}

/// Stable evidence token carried in both the caller WAL and Graphify SQLite
/// statements.  It is content-derived rather than random so recovery can
/// re-identify the transaction after a process crash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphifyTransactionId(String);

impl GraphifyTransactionId {
    pub(crate) fn for_receipt(
        receipt: &GraphifyGenerationReceipt,
        scope: GraphifyIngestScope,
    ) -> Self {
        Self(crate::wiki::ingest::graphify_ingest_transaction_id(
            receipt, scope,
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact SQLite evidence observed while recovering the publication journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActiveGraphifyScopeGeneration {
    /// Every active pointer belongs to this exact immutable generation and
    /// carries its stable transaction id.
    CommittedNew,
    /// The scope has no active pointer.  This is valid for a revoke-only
    /// no-ingest operation but otherwise needs the journal phase to interpret.
    OldOrEmpty,
}

/// Work selected from a recovered durable transaction journal. This action
/// remains attached to its lease-owning recovery session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphifyRecoveryAction {
    ApplyIndexedSqlite,
    ApplySkippedRevocation,
    MarkIndexedThenWriteCompletionWal,
    WriteIndexedCompletionWal,
    WriteSkippedCompletionWal,
}

/// A recovery opening either found no durable work or retains the exact lease
/// needed to finish it. A state-only answer is intentionally unavailable for
/// an active transaction.
pub(crate) enum GraphifyRecoveryOpen {
    NoPendingPublication(Box<GraphifyPublicationLease>),
    Pending(Box<PendingGraphifyRecovery>),
}

/// Result evidence from the SQLite half of the normal coordinator path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraphifyTransactionOutcome {
    Indexed {
        transaction_id: GraphifyTransactionId,
        stats: IngestStats,
    },
    SkippedAndRevoked {
        transaction_id: GraphifyTransactionId,
        revocation: GraphifyIngestRevocation,
    },
}

/// A type-state boundary after SQLite/journal phase and before the caller's
/// durable WAL. It deliberately retains the publication lease, but it does
/// not retain a SQLite transaction or borrow a `Connection`; async callers may
/// await their WAL write safely before calling [`Self::finish_after_durable_wal`].
pub(crate) struct PendingGraphifyCompletion {
    published: PublishedGraphifyPublication,
    outcome: GraphifyTransactionOutcome,
}

impl PendingGraphifyCompletion {
    pub(crate) fn transaction_id(&self) -> &GraphifyTransactionId {
        match &self.outcome {
            GraphifyTransactionOutcome::Indexed { transaction_id, .. }
            | GraphifyTransactionOutcome::SkippedAndRevoked { transaction_id, .. } => {
                transaction_id
            }
        }
    }

    pub(crate) fn outcome(&self) -> &GraphifyTransactionOutcome {
        &self.outcome
    }

    pub(crate) fn receipt(&self) -> &GraphifyGenerationReceipt {
        self.published.receipt()
    }

    /// Only callable after the caller's completion WAL containing
    /// [`Self::transaction_id`] is durably committed.
    pub(crate) fn finish_after_durable_wal(self) -> Result<GraphifyTransactionOutcome> {
        self.published
            .finish()
            .context("finish Graphify publication after durable completion WAL")?;
        Ok(self.outcome)
    }
}

/// Apply the SQLite half of the post-publication Graphify transaction.
///
/// The publication lease remains inside `published` until `finish`; this
/// means source/CURRENT/snapshot fences and the SQLite replacement all run in
/// one cooperative lease epoch. The returned type keeps that lease across the
/// caller's WAL await and only exposes terminal cleanup after the WAL is
/// durable.
pub(crate) fn apply_graphify_sqlite_phase<S: CompanionSnapshotAttestation>(
    mut published: PublishedGraphifyPublication,
    conn: &Connection,
    snapshot: &S,
    scope: GraphifyIngestScope,
    mode: GraphifyIngestMode,
    now_ns: i64,
) -> Result<PendingGraphifyCompletion> {
    let transaction_id = GraphifyTransactionId(published.transaction_id().to_owned());
    ensure!(
        published.ingest_scope() == scope
            && transaction_id == GraphifyTransactionId::for_receipt(published.receipt(), scope),
        "Graphify publication scope or transaction ID does not bind its receipt"
    );
    ensure!(
        matches!(
            (published.ingest_mode(), mode),
            (
                GraphifyPublicationIngestMode::Indexed,
                GraphifyIngestMode::Indexed
            ) | (
                GraphifyPublicationIngestMode::SkippedAndRevoked,
                GraphifyIngestMode::SkippedAndRevoked
            )
        ),
        "Graphify coordinator mode does not match the durable pre-CURRENT publication intent"
    );
    let outcome = match mode {
        GraphifyIngestMode::Indexed => {
            let stats = ingest_graphify_generation_for_scope_guarded(
                conn,
                &published.generation_dir,
                scope,
                published.receipt(),
                now_ns,
                || {
                    snapshot
                        .revalidate_companion_publication()
                        .context("revalidate scoped native snapshot before Graphify SQLite commit")
                },
            )?;
            published
                .mark_ingested()
                .context("record successful Graphify SQLite ingest")?;
            GraphifyTransactionOutcome::Indexed {
                transaction_id: transaction_id.clone(),
                stats,
            }
        }
        GraphifyIngestMode::SkippedAndRevoked => {
            let revocation = revoke_graphify_scope_for_no_ingest_guarded(
                conn,
                &published.corpus_dir,
                scope,
                published.receipt(),
                now_ns,
                || {
                    snapshot.revalidate_companion_publication().context(
                        "revalidate scoped native snapshot before Graphify no-ingest revoke",
                    )
                },
            )?;
            published
                .mark_ingest_skipped()
                .context("record intentional Graphify no-ingest revocation")?;
            GraphifyTransactionOutcome::SkippedAndRevoked {
                transaction_id: transaction_id.clone(),
                revocation,
            }
        }
    };

    Ok(PendingGraphifyCompletion { published, outcome })
}

/// Inspect active Graphify scope evidence without treating an arbitrary old
/// row as proof that this transaction committed.  Any active mixture or a row
/// missing the stable marker fails closed.
pub(crate) fn inspect_active_scope_generation(
    conn: &Connection,
    receipt: &GraphifyGenerationReceipt,
    scope: GraphifyIngestScope,
) -> Result<ActiveGraphifyScopeGeneration> {
    let transaction_id = GraphifyTransactionId::for_receipt(receipt, scope);
    let expected_scope = scope.groundtruth_scope(receipt);
    let active = list_for_scope(conn, &expected_scope)?
        .into_iter()
        .filter(|row| row.revoked_at.is_none())
        .collect::<Vec<_>>();
    if active.is_empty() {
        return Ok(ActiveGraphifyScopeGeneration::OldOrEmpty);
    }

    let generation_marker = format!("generation `{}`", receipt.generation_id);
    let fingerprint_marker = format!(
        "source_fingerprint_sha256: {}",
        receipt.source_fingerprint_sha256
    );
    let transaction_marker = format!("transaction_id: {}", transaction_id.as_str());
    ensure!(
        active.iter().all(|row| {
            row.statement.contains(&generation_marker)
                && row.statement.contains(&fingerprint_marker)
                && row.statement.contains(&transaction_marker)
        }),
        "Graphify active scope mixes old, unmarked, or indeterminate generations; refusing recovery guess"
    );
    Ok(ActiveGraphifyScopeGeneration::CommittedNew)
}

/// Lease-owning pre-WAL recovery state. It never holds a SQLite transaction;
/// consuming [`Self::apply_sqlite_phase`] yields
/// [`PendingGraphifyRecoveryWal`], which can safely span the caller's WAL
/// await before terminal cleanup.
pub(crate) struct PendingGraphifyRecovery {
    lease: GraphifyPublicationLease,
    corpus_dir: std::path::PathBuf,
    generation_dir: std::path::PathBuf,
    receipt: GraphifyGenerationReceipt,
    scope: GraphifyIngestScope,
    transaction_id: GraphifyTransactionId,
    action: GraphifyRecoveryAction,
}

impl PendingGraphifyRecovery {
    /// The durable pre-CURRENT intent, preserved even after the action changes
    /// from SQLite work to WAL-only work.
    fn ingest_mode(&self) -> GraphifyIngestMode {
        match self.action {
            GraphifyRecoveryAction::ApplyIndexedSqlite
            | GraphifyRecoveryAction::MarkIndexedThenWriteCompletionWal
            | GraphifyRecoveryAction::WriteIndexedCompletionWal => GraphifyIngestMode::Indexed,
            GraphifyRecoveryAction::ApplySkippedRevocation
            | GraphifyRecoveryAction::WriteSkippedCompletionWal => {
                GraphifyIngestMode::SkippedAndRevoked
            }
        }
    }

    /// Perform the durable journal's declared SQLite action while retaining
    /// the same lease acquired during recovery inspection.  Consuming `self`
    /// prevents a caller from writing a terminal WAL and finishing before the
    /// declared SQLite/revoke action reached its durable journal phase.
    pub(crate) fn apply_sqlite_phase<S: CompanionSnapshotAttestation>(
        mut self,
        conn: &Connection,
        snapshot: &S,
        now_ns: i64,
    ) -> Result<PendingGraphifyRecoveryWal> {
        match self.action {
            GraphifyRecoveryAction::ApplyIndexedSqlite => {
                ingest_graphify_generation_for_scope_guarded(
                    conn,
                    &self.generation_dir,
                    self.scope,
                    &self.receipt,
                    now_ns,
                    || {
                        snapshot.revalidate_companion_publication().context(
                            "revalidate scoped native snapshot before recovered Graphify SQLite commit",
                        )
                    },
                )?;
                self.mark_recovered_sqlite_phase()?;
            }
            GraphifyRecoveryAction::ApplySkippedRevocation => {
                revoke_graphify_scope_for_no_ingest_guarded(
                    conn,
                    &self.corpus_dir,
                    self.scope,
                    &self.receipt,
                    now_ns,
                    || {
                        snapshot.revalidate_companion_publication().context(
                            "revalidate scoped native snapshot before recovered Graphify no-ingest revoke",
                        )
                    },
                )?;
                self.mark_recovered_sqlite_phase()?;
            }
            GraphifyRecoveryAction::MarkIndexedThenWriteCompletionWal => {
                self.mark_recovered_sqlite_phase()?;
            }
            GraphifyRecoveryAction::WriteIndexedCompletionWal
            | GraphifyRecoveryAction::WriteSkippedCompletionWal => {}
        }
        let phase = match self.action {
            GraphifyRecoveryAction::WriteIndexedCompletionWal => GraphifyTransactionPhase::Ingested,
            GraphifyRecoveryAction::WriteSkippedCompletionWal => {
                GraphifyTransactionPhase::IngestSkipped
            }
            _ => bail!("recovered Graphify action did not reach WAL-ready journal phase"),
        };
        let ingest_mode = self.ingest_mode();
        Ok(PendingGraphifyRecoveryWal {
            lease: self.lease,
            corpus_dir: self.corpus_dir,
            receipt: self.receipt,
            transaction_id: self.transaction_id,
            ingest_mode,
            phase,
        })
    }

    fn mark_recovered_sqlite_phase(&mut self) -> Result<()> {
        let phase = mark_recovered_graphify_ingest_phase_under_lease(
            &self.lease,
            &self.corpus_dir,
            self.transaction_id.as_str(),
        )?;
        self.action = match phase {
            GraphifyTransactionPhase::Ingested => GraphifyRecoveryAction::WriteIndexedCompletionWal,
            GraphifyTransactionPhase::IngestSkipped => {
                GraphifyRecoveryAction::WriteSkippedCompletionWal
            }
            _ => bail!("recovered Graphify journal advanced to a nonterminal ingest phase"),
        };
        Ok(())
    }
}

/// Type-state entered only after the recovery journal records `ingested` or
/// `ingest_skipped`. It retains the lease through an async completion-WAL
/// write and is the sole recovery type with a terminal finish method.
pub(crate) struct PendingGraphifyRecoveryWal {
    lease: GraphifyPublicationLease,
    corpus_dir: std::path::PathBuf,
    receipt: GraphifyGenerationReceipt,
    transaction_id: GraphifyTransactionId,
    ingest_mode: GraphifyIngestMode,
    phase: GraphifyTransactionPhase,
}

impl PendingGraphifyRecoveryWal {
    pub(crate) fn transaction_id(&self) -> &GraphifyTransactionId {
        &self.transaction_id
    }

    pub(crate) fn receipt(&self) -> &GraphifyGenerationReceipt {
        &self.receipt
    }

    pub(crate) fn ingest_mode(&self) -> GraphifyIngestMode {
        self.ingest_mode
    }

    /// Call only after a durable caller WAL record carrying
    /// [`Self::transaction_id`] has been written.
    pub(crate) fn finish_after_durable_wal(self) -> Result<()> {
        finish_recovered_transaction_under_lease(
            &self.lease,
            &self.corpus_dir,
            self.transaction_id.as_str(),
            &[self.phase],
        )
        .context("finish recovered Graphify transaction after durable completion WAL")
    }
}

/// Discover the zero-or-one pending corpus transaction while the caller keeps
/// its pre-update lease. A caller must perform this before letting Graphify
/// mutate `graphify-out`; a normal no-pending branch returns the same lease for
/// the subsequent `GraphifyPublishRequest`.
pub(crate) fn discover_graphify_recovery_targets(
    lease: &GraphifyPublicationLease,
) -> Result<Vec<std::path::PathBuf>> {
    discover_graphify_recovery_targets_under_lease(lease)
        .context("discover pending Graphify recovery target under held lease")
}

/// Reconcile the filesystem journal and prove its scope-bound identity before
/// a caller opens SQLite.  This is intentionally separate from the SQLite
/// recovery constructor: a self-map caller must fail closed on a corpus
/// journal (and vice versa) without touching, creating, or migrating a DB.
pub(crate) fn preflight_graphify_recovery_scope_under_lease(
    lease: &GraphifyPublicationLease,
    corpus_dir: &Path,
    expected_scope: GraphifyIngestScope,
) -> Result<()> {
    recover_graphify_transaction_under_lease(lease, corpus_dir)
        .context("recover Graphify publication journal before SQLite admission")?;
    let Some(journal) = inspect_graphify_transaction_under_lease(lease, corpus_dir)
        .context("inspect Graphify publication journal before SQLite admission")?
    else {
        return Ok(());
    };
    ensure!(
        journal.ingest_scope == expected_scope,
        "Graphify recovery caller scope does not match durable journal intent"
    );
    let Some((_generation_dir, receipt)) = load_current_graphify_generation_receipt(corpus_dir)
        .context("load current Graphify generation before SQLite admission")?
    else {
        bail!("Graphify recovery journal exists but CURRENT has no generation receipt")
    };
    let expected_id = GraphifyTransactionId::for_receipt(&receipt, expected_scope);
    ensure!(
        journal.transaction_id == expected_id.as_str()
            && journal.corpus_id == receipt.corpus_id
            && journal.generation_id == receipt.generation_id,
        "Graphify recovery journal does not bind the current receipt and caller scope"
    );
    Ok(())
}

/// Open a lease-owning recovery session. The receipt is loaded strictly from
/// the journal-owned `CURRENT` generation; callers provide no receipt/path
/// from untrusted recovery state.
pub(crate) fn open_graphify_transaction_recovery<S: CompanionSnapshotAttestation>(
    conn: &Connection,
    lease: GraphifyPublicationLease,
    snapshot: &S,
    corpus_dir: &Path,
    scope: GraphifyIngestScope,
) -> Result<GraphifyRecoveryOpen> {
    preflight_graphify_recovery_scope_under_lease(&lease, corpus_dir, scope)?;
    snapshot
        .revalidate_companion_publication()
        .context("revalidate scoped native snapshot before Graphify recovery")?;
    let Some(journal) = inspect_graphify_transaction_under_lease(&lease, corpus_dir)
        .context("inspect recovered Graphify publication journal under lease")?
    else {
        return Ok(GraphifyRecoveryOpen::NoPendingPublication(Box::new(lease)));
    };
    let Some((generation_dir, receipt)) = load_current_graphify_generation_receipt(corpus_dir)
        .context("load strict current Graphify generation receipt for recovery")?
    else {
        bail!("Graphify recovery journal exists but CURRENT has no generation receipt")
    };
    let transaction_id = GraphifyTransactionId::for_receipt(&receipt, scope);
    ensure!(
        journal.ingest_scope == scope
            && journal.transaction_id == transaction_id.as_str()
            && journal.corpus_id == receipt.corpus_id
            && journal.generation_id == receipt.generation_id,
        "Graphify recovery journal caller scope or transaction identity mismatches; refusing recovery guess"
    );
    let phase = journal.phase;

    ensure!(
        receipt.canonical_repo_root == snapshot.root().display()
            && receipt.repo_root_identity_sha256 == snapshot.root_identity_sha256()
            && receipt.source_fingerprint_sha256 == snapshot.source_fingerprint_sha256()
            && receipt.native_index_generation == snapshot.index_generation()
            && receipt.native_graph_generation == snapshot.graph_generation(),
        "Graphify recovery receipt does not bind the supplied scoped native snapshot"
    );
    let active = inspect_active_scope_generation(conn, &receipt, scope)?;
    let action = select_recovery_action(phase, journal.ingest_mode, active)?;
    Ok(GraphifyRecoveryOpen::Pending(Box::new(
        PendingGraphifyRecovery {
            lease,
            corpus_dir: corpus_dir.to_path_buf(),
            generation_dir,
            receipt,
            scope,
            transaction_id,
            action,
        },
    )))
}

fn select_recovery_action(
    phase: GraphifyTransactionPhase,
    ingest_mode: GraphifyPublicationIngestMode,
    active: ActiveGraphifyScopeGeneration,
) -> Result<GraphifyRecoveryAction> {
    Ok(match (phase, ingest_mode, active) {
        (
            GraphifyTransactionPhase::CurrentPublished,
            GraphifyPublicationIngestMode::Indexed,
            ActiveGraphifyScopeGeneration::OldOrEmpty,
        ) => GraphifyRecoveryAction::ApplyIndexedSqlite,
        (
            GraphifyTransactionPhase::CurrentPublished,
            GraphifyPublicationIngestMode::SkippedAndRevoked,
            ActiveGraphifyScopeGeneration::OldOrEmpty,
        ) => GraphifyRecoveryAction::ApplySkippedRevocation,
        (
            GraphifyTransactionPhase::CurrentPublished,
            GraphifyPublicationIngestMode::Indexed,
            ActiveGraphifyScopeGeneration::CommittedNew,
        ) => GraphifyRecoveryAction::MarkIndexedThenWriteCompletionWal,
        (
            GraphifyTransactionPhase::Ingested,
            GraphifyPublicationIngestMode::Indexed,
            ActiveGraphifyScopeGeneration::CommittedNew,
        ) => GraphifyRecoveryAction::WriteIndexedCompletionWal,
        (
            GraphifyTransactionPhase::IngestSkipped,
            GraphifyPublicationIngestMode::SkippedAndRevoked,
            ActiveGraphifyScopeGeneration::OldOrEmpty,
        ) => GraphifyRecoveryAction::WriteSkippedCompletionWal,
        (GraphifyTransactionPhase::Ingested, _, ActiveGraphifyScopeGeneration::OldOrEmpty) => {
            bail!(
                "Graphify journal says SQLite ingest completed but the active scope is old or empty"
            )
        }
        (
            GraphifyTransactionPhase::IngestSkipped,
            _,
            ActiveGraphifyScopeGeneration::CommittedNew,
        ) => {
            bail!(
                "Graphify journal says no-ingest but the active scope contains the new generation"
            )
        }
        (
            GraphifyTransactionPhase::CurrentPublished,
            _,
            ActiveGraphifyScopeGeneration::CommittedNew,
        ) => {
            bail!(
                "Graphify current_published journal intent conflicts with active scope generation"
            )
        }
        (GraphifyTransactionPhase::Completed | GraphifyTransactionPhase::Prepared, _, _) => {
            unreachable!("recovery removes completed/prepared journals before inspection")
        }
        (phase, mode, active) => bail!(
            "Graphify recovery phase {phase:?}, intent {mode:?}, and active scope {active:?} are indeterminate"
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphify_publish::{GRAPHIFY_PUBLISH_SCHEMA, GraphifyArtifactReceipt};
    use crate::memory::groundtruth::{Source, insert};

    fn receipt(root_digest: char) -> GraphifyGenerationReceipt {
        GraphifyGenerationReceipt {
            schema_version: GRAPHIFY_PUBLISH_SCHEMA,
            corpus_id: format!("graphify-root-v1-{}", root_digest.to_string().repeat(64)),
            corpus_namespace: format!("graphify-v1-{}", root_digest.to_string().repeat(64)),
            generation_id: format!("gen-v1-{}", root_digest.to_string().repeat(64)),
            friendly_subdir: "Graphify".to_owned(),
            canonical_repo_root: "/not-used-by-this-unit-test".to_owned(),
            repo_root_identity_sha256: root_digest.to_string().repeat(64),
            canonical_vault_root: "/not-used-by-this-unit-test".to_owned(),
            vault_root_identity_sha256: "b".repeat(64),
            source_fingerprint_sha256: "c".repeat(64),
            native_index_generation: 1,
            native_graph_generation: 1,
            artifacts: vec![GraphifyArtifactReceipt {
                name: "GRAPH_REPORT.md".to_owned(),
                bytes: 1,
                sha256: "d".repeat(64),
            }],
        }
    }

    fn connection() -> (tempfile::TempDir, Connection) {
        let directory = tempfile::tempdir().unwrap();
        let connection = crate::memory::store::open(&directory.path().join("views.db")).unwrap();
        (directory, connection)
    }

    #[test]
    fn transaction_id_is_stable_and_root_bound() {
        let first = receipt('a');
        let second = receipt('e');
        let first_id = GraphifyTransactionId::for_receipt(&first, GraphifyIngestScope::SelfMap);
        assert_eq!(
            first_id,
            GraphifyTransactionId::for_receipt(&first, GraphifyIngestScope::SelfMap)
        );
        assert_ne!(
            first_id,
            GraphifyTransactionId::for_receipt(&second, GraphifyIngestScope::SelfMap)
        );
        assert_ne!(
            first_id,
            GraphifyTransactionId::for_receipt(&first, GraphifyIngestScope::Corpus),
            "self-map and corpus recovery must never share one WAL/SQLite id domain"
        );
        assert!(first_id.as_str().starts_with("graphify-txn-v2-self_map-"));
    }

    #[test]
    fn active_scope_inspection_distinguishes_committed_new_from_mixed_state() {
        let (_directory, connection) = connection();
        let receipt = receipt('a');
        let scope = GraphifyIngestScope::Corpus;
        let transaction_id = GraphifyTransactionId::for_receipt(&receipt, scope);
        let groundtruth_scope = scope.groundtruth_scope(&receipt);
        insert(
            &connection,
            &format!(
                "generation `{}` source_fingerprint_sha256: {}; transaction_id: {}",
                receipt.generation_id,
                receipt.source_fingerprint_sha256,
                transaction_id.as_str()
            ),
            &Source::BulkText,
            &groundtruth_scope,
            1,
        )
        .unwrap();
        assert_eq!(
            inspect_active_scope_generation(&connection, &receipt, scope).unwrap(),
            ActiveGraphifyScopeGeneration::CommittedNew
        );

        insert(
            &connection,
            "generation `old` source_fingerprint_sha256: old; transaction_id: old",
            &Source::BulkText,
            &groundtruth_scope,
            2,
        )
        .unwrap();
        let error = inspect_active_scope_generation(&connection, &receipt, scope).unwrap_err();
        assert!(error.to_string().contains("indeterminate generations"));
    }

    #[test]
    fn recovery_inspection_uses_durable_intent_not_empty_scope_guesswork() {
        assert_eq!(
            select_recovery_action(
                GraphifyTransactionPhase::CurrentPublished,
                GraphifyPublicationIngestMode::Indexed,
                ActiveGraphifyScopeGeneration::OldOrEmpty,
            )
            .unwrap(),
            GraphifyRecoveryAction::ApplyIndexedSqlite
        );
        assert_eq!(
            select_recovery_action(
                GraphifyTransactionPhase::CurrentPublished,
                GraphifyPublicationIngestMode::SkippedAndRevoked,
                ActiveGraphifyScopeGeneration::OldOrEmpty,
            )
            .unwrap(),
            GraphifyRecoveryAction::ApplySkippedRevocation
        );
        assert_eq!(
            select_recovery_action(
                GraphifyTransactionPhase::Ingested,
                GraphifyPublicationIngestMode::Indexed,
                ActiveGraphifyScopeGeneration::CommittedNew,
            )
            .unwrap(),
            GraphifyRecoveryAction::WriteIndexedCompletionWal
        );
        assert!(
            select_recovery_action(
                GraphifyTransactionPhase::IngestSkipped,
                GraphifyPublicationIngestMode::SkippedAndRevoked,
                ActiveGraphifyScopeGeneration::CommittedNew,
            )
            .is_err()
        );
    }
}
