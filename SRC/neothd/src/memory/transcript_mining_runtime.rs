//! Local operator transcript provenance, bound to the home WAL authority.
//!
//! A configured finite opt-in plus the opaque local chat capability permits
//! fresh births only. Stored flags never substitute for authenticated WAL
//! read-back. Incognito callers must not enter this module.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
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
