//! Local operator transcript provenance, bound to the home WAL authority.
//!
//! A configured finite opt-in plus the opaque local chat capability permits
//! fresh births only. Stored flags never substitute for authenticated WAL
//! read-back. Incognito callers must not enter this module.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use hmac::{Hmac, Mac};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use sha2::Sha256;

use crate::config::memory::TranscriptMiningRetention;

use super::transcript_mining_provenance::FiniteRetention;
use super::transcript_mining_store::{
    PendingMiningOperation, PreparedBound, RawReceiptResolution, TranscriptMiningStore,
};

#[derive(Default, serde::Serialize)]
pub(crate) struct ReconciliationReport {
    raw_verified: usize,
    bound_verified: usize,
    revoked_verified: usize,
    expired_cancelled: usize,
}

/// Non-serializable authority for one explicitly opted-in local ingress.
/// The private constructor input is minted only by `cli::chat`; neither
/// source text, a platform subject string nor a SQLite row can mint it.
pub(crate) struct AuthenticatedLocalIngress {
    home: PathBuf,
    subject_sha256: [u8; 32],
    retention: Option<FiniteRetention>,
    authority: crate::cli::security::HmacWriterAuthority,
}

impl AuthenticatedLocalIngress {
    fn for_existing_reader(home: &Path) -> Result<Option<Self>> {
        let home = home
            .canonicalize()
            .context("bind existing transcript evidence home")?;
        let Some(authority) = crate::cli::security::acquire_existing_hmac_writer_authority(
            &home,
            &home.join("wal").join("hmac.key"),
        )
        .context("acquire existing transcript evidence authority")?
        else {
            return Ok(None);
        };
        authority.validate_namespace_binding()?;
        let subject_sha256 = subject_mac(&authority.active_key)?
            .finalize()
            .into_bytes()
            .into();
        Ok(Some(Self {
            home,
            subject_sha256,
            retention: None,
            authority,
        }))
    }

    pub(crate) fn from_local_chat(
        subject: &crate::cli::chat::LocalChatCommunicationSubject,
        home: &Path,
        retention: TranscriptMiningRetention,
    ) -> Result<Self> {
        Self::from_local_operator(subject, home, Some(retention))
    }

    /// Reconcile already-authorized durable work without granting a new birth.
    pub(crate) fn for_reconciliation(
        _subject: &crate::cli::recall_score::LocalTranscriptRecoverySubject,
        home: &Path,
    ) -> Result<Self> {
        Self::bind_home(home, None)
    }

    fn from_local_operator(
        _subject: &crate::cli::chat::LocalChatCommunicationSubject,
        home: &Path,
        retention: Option<TranscriptMiningRetention>,
    ) -> Result<Self> {
        Self::bind_home(home, retention)
    }

    fn bind_home(home: &Path, retention: Option<TranscriptMiningRetention>) -> Result<Self> {
        let home = home.canonicalize().context("bind transcript mining home")?;
        let authority = crate::cli::security::acquire_hmac_writer_authority(
            &home,
            &home.join("wal").join("hmac.key"),
        )
        .context("authenticate local transcript mining ingress")?;
        authority.validate_namespace_binding()?;
        let subject_sha256 = subject_mac(&authority.active_key)?
            .finalize()
            .into_bytes()
            .into();
        let retention = retention.map(|retention| match retention {
            TranscriptMiningRetention::Minutes15 => FiniteRetention::Minutes15,
            TranscriptMiningRetention::Hours24 => FiniteRetention::Hours24,
            TranscriptMiningRetention::Days30 => FiniteRetention::Days30,
        });
        Ok(Self {
            home,
            subject_sha256,
            retention,
            authority,
        })
    }

    pub(crate) fn home(&self) -> &Path {
        &self.home
    }

    pub(crate) fn subject_sha256(&self) -> [u8; 32] {
        self.subject_sha256
    }

    pub(crate) fn retention(&self) -> Result<FiniteRetention> {
        self.retention
            .context("new transcript mining binding requires explicit finite opt-in")
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.authority.validate_namespace_binding()
    }

    /// Recovery retains the prepared subject, including its old key epoch.
    /// Rotation may change the identity for new births; it cannot rewrite an
    /// interrupted descriptor. Only the home's retained verification keys
    /// may authorize recovery of that original subject.
    pub(crate) fn accepts_subject_sha256(&self, subject: &[u8; 32]) -> Result<bool> {
        self.validate()?;
        for key in &self.authority.verification_keys {
            if subject_mac(key)?.verify_slice(subject).is_ok() {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn subject_mac(key: &[u8]) -> Result<Hmac<Sha256>> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).context("derive local transcript mining subject")?;
    mac.update(b"NEOTH/transcript-mining/local-interactive-subject/v1");
    Ok(mac)
}

/// Existing-only, read-only local evidence access. This value cannot expose a
/// birth capability or mutate the transcript lifecycle. The home and key lease
/// are transient and never enter a candidate artifact or serializable report.
pub(crate) struct AuthenticatedLocalTranscriptReader {
    ingress: AuthenticatedLocalIngress,
    conn: Connection,
    root: crate::skills::store::BoundDirectory,
    views: crate::skills::store::BoundChildObject,
}

impl AuthenticatedLocalTranscriptReader {
    pub(crate) fn home(&self) -> &Path {
        self.ingress.home()
    }

    pub(crate) fn revalidation_token(&self) -> Result<i64> {
        self.validate_namespace()?;
        super::transcript_mining_store::views_data_version(&self.conn)
    }

    pub(crate) fn list_active_ids(&self, limit: usize) -> Result<Vec<String>> {
        ensure!(
            (1..=512).contains(&limit),
            "local candidate listing limit must be between 1 and 512"
        );
        self.validate_namespace()?;
        let mut statement = self.conn.prepare(
            "SELECT provenance_id FROM transcript_mining_provenance
             WHERE lifecycle='active' AND terminal_cause IS NULL AND expires_at_unix>?1
             ORDER BY created_at_unix DESC,provenance_id LIMIT ?2",
        )?;
        statement
            .query_map(rusqlite::params![current_unix()?, limit as i64], |row| {
                row.get(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("list bounded local transcript provenance")
    }

    pub(crate) fn open_existing(home: &Path) -> Result<Option<Self>> {
        let Some(ingress) = AuthenticatedLocalIngress::for_existing_reader(home)? else {
            return Ok(None);
        };
        let root = crate::skills::store::open_bound_directory_from_trusted_anchor(
            ingress
                .home()
                .parent()
                .context("transcript home has no parent")?,
            ingress.home(),
            false,
            "local transcript evidence",
        )?
        .context("transcript evidence home is absent")?;
        let name = std::ffi::OsStr::new("views.db");
        match root.dir.symlink_metadata(name) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("inspect existing transcript database"),
            Ok(_) => {}
        }
        let display = root.display_path.join(name);
        let (_file, views) =
            crate::skills::store::open_bound_regular_file(&root.dir, name, &display)?;
        let conn = Connection::open_with_flags(
            &display,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .context("open transcript evidence database read-only")?;
        conn.pragma_update(None, "query_only", true)?;
        let reader = Self {
            ingress,
            conn,
            root,
            views,
        };
        reader.validate_namespace()?;
        Ok(Some(reader))
    }

    fn validate_namespace(&self) -> Result<()> {
        self.ingress.validate()?;
        ensure!(
            self.views.matches_regular_file_child_readonly(
                &self.root.dir,
                std::ffi::OsStr::new("views.db"),
                &self.root.display_path.join("views.db"),
            )?,
            "transcript evidence database identity changed"
        );
        Ok(())
    }

    /// A byte bound is checked inside the same snapshot before loading text.
    /// Another connection's commit invalidates the result, including a delete
    /// or revocation while WAL authentication was reading retained segments.
    pub(crate) fn read_active(
        &self,
        provenance_id: &str,
        max_text_bytes: usize,
    ) -> Result<Option<super::transcript_mining_store::AuthenticatedTranscriptProjection>> {
        self.read_active_revalidated(provenance_id, max_text_bytes, || Ok(()))
    }

    #[cfg(test)]
    pub(crate) fn read_active_with_test_hook(
        &self,
        provenance_id: &str,
        max_text_bytes: usize,
        after_proof: impl FnOnce() -> Result<()>,
    ) -> Result<Option<super::transcript_mining_store::AuthenticatedTranscriptProjection>> {
        self.read_active_revalidated(provenance_id, max_text_bytes, after_proof)
    }

    fn read_active_revalidated(
        &self,
        provenance_id: &str,
        max_text_bytes: usize,
        after_proof: impl FnOnce() -> Result<()>,
    ) -> Result<Option<super::transcript_mining_store::AuthenticatedTranscriptProjection>> {
        self.validate_namespace()?;
        let before = super::transcript_mining_store::views_data_version(&self.conn)?;
        let transaction = self.conn.unchecked_transaction()?;
        let now = current_unix()?;
        let raw_turn_id: Option<i64> = transaction
            .query_row(
                "SELECT p.raw_turn_id FROM transcript_mining_provenance p
             JOIN raw_turns r ON r.id=p.raw_turn_id
             WHERE p.provenance_id=?1 AND p.lifecycle='active'
               AND p.terminal_cause IS NULL AND p.expires_at_unix>?2
               AND length(CAST(r.text AS BLOB))<=?3",
                rusqlite::params![
                    provenance_id,
                    now,
                    i64::try_from(max_text_bytes)
                        .context("transcript evidence text bound exceeds i64")?
                ],
                |row| row.get(0),
            )
            .optional()
            .context("select active local transcript evidence")?;
        let projection = match raw_turn_id {
            Some(raw_turn_id) => super::transcript_mining_store::authenticate_active_binding(
                &transaction,
                &self.ingress,
                raw_turn_id,
                now,
            )?,
            None => None,
        };
        after_proof()?;
        transaction.commit()?;
        self.validate_namespace()?;
        if super::transcript_mining_store::views_data_version(&self.conn)? != before {
            anyhow::bail!("transcript state changed during evidence authentication; retry");
        }
        let Some(projection) = projection else {
            return Ok(None);
        };
        if projection.provenance_id() != provenance_id
            || projection.expires_at_unix() <= current_unix()?
        {
            return Ok(None);
        }
        Ok(Some(projection))
    }
}

/// Persist the fresh operator row and both independently authenticated frames
/// before dispatch. A failed or lost acknowledgement leaves the committed
/// descriptor leased for exact recovery; callers must not add a legacy row.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn persist_local_operator_turn(
    subject: &crate::cli::chat::LocalChatCommunicationSubject,
    home: &Path,
    writer: &crate::wal::writer::WalWriterHandle,
    retention: TranscriptMiningRetention,
    session_id: &str,
    text: &str,
    now: i64,
) -> Result<i64> {
    let ingress = AuthenticatedLocalIngress::from_local_chat(subject, home, retention)?;
    let canonical_home = ingress.home().to_path_buf();
    let home = canonical_home.as_path();
    let conn = super::store::open(&ingress.home().join("views.db"))?;
    let mut store = TranscriptMiningStore::open(conn, ingress)?;
    reconcile_store(&mut store, home, writer).await?;
    let prepared = store.prepare_operator_raw_birth(session_id, text, now)?;
    let event_id = prepared.event_id();
    let receipt = writer
        .append_planned_raw_text_once(home, prepared.raw_descriptor()?)
        .await
        .context("authenticate planned operator RAW_TEXT")?;
    match store.record_raw_receipt(&prepared, &receipt, current_unix()?)? {
        RawReceiptResolution::Bound(bound) => {
            complete_bound(&mut store, home, writer, &bound).await?;
        }
        RawReceiptResolution::ExpiredCancelled => {}
    }
    reconcile_store(&mut store, home, writer).await?;
    Ok(event_id)
}

fn current_unix() -> Result<i64> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("transcript reconciliation clock precedes Unix epoch")?
        .as_secs();
    i64::try_from(seconds).context("transcript reconciliation clock overflow")
}

/// Returns true only for a real authenticated Bound receipt; expired complete
/// absence instead consumes the writer's sealed cancellation evidence.
async fn complete_bound(
    store: &mut TranscriptMiningStore,
    home: &Path,
    writer: &crate::wal::writer::WalWriterHandle,
    bound: &PreparedBound,
) -> Result<bool> {
    match writer
        .append_planned_mining_outbox_once(home, bound.bound_descriptor()?)
        .await
    {
        Ok(receipt) => {
            let now = current_unix()?;
            store.record_bound_receipt(bound, &receipt, now)?;
            if now < bound.expires_at_unix() {
                anyhow::ensure!(
                    store.active_binding_is_usable(bound.raw_turn_id(), now)?,
                    "completed transcript binding failed authenticated read-back"
                );
            }
            Ok(true)
        }
        Err(crate::wal::TranscriptMiningOnceError::ExpiredAbsent(absence)) => {
            store.record_expired_bound_absence(bound, &absence)?;
            Ok(false)
        }
        Err(error) => Err(error).context("authenticate planned transcript binding"),
    }
}

async fn reconcile_store(
    store: &mut TranscriptMiningStore,
    home: &Path,
    writer: &crate::wal::writer::WalWriterHandle,
) -> Result<ReconciliationReport> {
    let mut report = ReconciliationReport::default();
    for operation in store.resume_pending(current_unix()?)? {
        let bound = match operation {
            PendingMiningOperation::Raw(raw) => {
                let receipt = writer
                    .append_planned_raw_text_once(home, raw.raw_descriptor()?)
                    .await
                    .context("reconcile exact operator RAW_TEXT")?;
                report.raw_verified += 1;
                match store.record_raw_receipt(&raw, &receipt, current_unix()?)? {
                    RawReceiptResolution::Bound(bound) => *bound,
                    RawReceiptResolution::ExpiredCancelled => {
                        report.expired_cancelled += 1;
                        continue;
                    }
                }
            }
            PendingMiningOperation::Bound(bound) => bound,
        };
        if complete_bound(store, home, writer, &bound).await? {
            report.bound_verified += 1;
        } else {
            report.expired_cancelled += 1;
        }
    }
    for revoked in store.prepare_pending_revocations(current_unix()?)? {
        let receipt = writer
            .append_planned_mining_outbox_once(home, revoked.revoked_descriptor()?)
            .await
            .context("reconcile exact transcript revocation")?;
        store.record_revoked_receipt(&revoked, &receipt, current_unix()?)?;
        report.revoked_verified += 1;
    }
    Ok(report)
}

/// Explicit operator recovery also works after disabling new mining opt-in.
/// It uses a capability that cannot create fresh transcript bindings.
pub(crate) async fn reconcile_local_transcripts(
    subject: &crate::cli::recall_score::LocalTranscriptRecoverySubject,
    home: &Path,
) -> Result<ReconciliationReport> {
    anyhow::ensure!(
        home.join("views.db").is_file(),
        "transcript database does not exist"
    );
    let ingress = AuthenticatedLocalIngress::for_reconciliation(subject, home)?;
    let canonical_home = ingress.home().to_path_buf();
    let home = canonical_home.as_path();
    let conn = super::store::open(&ingress.home().join("views.db"))?;
    let mut store = TranscriptMiningStore::open(conn, ingress)?;
    let segment = crate::wal::writer::unique_standalone_segment_path(
        &home.join("wal"),
        "transcript-reconcile",
    );
    let (writer, join) = crate::wal::writer::spawn_for_home(segment, home.to_path_buf())?;
    let result = reconcile_store(&mut store, home, &writer).await;
    drop(writer);
    join.await
        .context("drain transcript reconciliation writer")?;
    result
}
