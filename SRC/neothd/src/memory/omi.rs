//! Durable OMI conversation reconciliation.
//!
//! OMI's Developer API does not expose an update revision. The transport hashes
//! each complete detail response and this module combines that remote digest
//! with the active projection controls. It is the single transactional boundary: conversation,
//! aligned segments, media metadata, candidate memory, and kanban action
//! mappings commit together. Replaying the same revision is a strict no-op.
//!
//! Privacy defaults are structural: segment text is nullable, media bytes are
//! never stored in `views.db`, and a purge leaves a tombstone so a subsequent
//! remote poll cannot silently resurrect operator-deleted data.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::coding::types::{KanbanSessionId, KanbanTaskId, TaskStatus};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OmiMediaKind {
    Audio,
    Image,
    Video,
}

impl OmiMediaKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Audio => "audio",
            Self::Image => "image",
            Self::Video => "video",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OmiSegment {
    pub id: String,
    pub start_ms: i64,
    pub end_ms: i64,
    pub speaker: Option<String>,
    pub speaker_id: Option<i64>,
    /// `None` when the source API does not identify the operator. In
    /// particular, OMI Developer API speaker ids are diarization labels, not
    /// user identity, so callers must not infer this field from speaker `0`.
    pub is_user: Option<bool>,
    pub person_id: Option<String>,
    pub stt_provider: Option<String>,
    /// Sanitized text. It is hashed unconditionally and persisted only when
    /// `OmiCommitOptions::retain_transcript` is true.
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OmiMedia {
    pub id: String,
    pub kind: OmiMediaKind,
    pub created_at_ms: Option<i64>,
    pub duration_ms: Option<i64>,
    pub content_hash: Option<String>,
    pub processing_status: String,
    pub metadata: Option<serde_json::Value>,
    pub processed_at_ts: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OmiConversation {
    pub source_id: String,
    /// Deterministic digest of the complete source detail response.
    pub revision: String,
    pub status: String,
    pub source: Option<String>,
    pub language: Option<String>,
    pub started_at_ms: Option<i64>,
    pub finished_at_ms: Option<i64>,
    pub call_id: Option<String>,
    pub title: Option<String>,
    /// Sanitized deterministic/upstream overview. `None` means summary storage
    /// is disabled or the upstream has no final summary.
    pub summary: Option<String>,
    /// Sanitized, non-secret source metadata that has no first-class NEOTH
    /// projection (for Developer API imports: category, folder, geolocation,
    /// and structured calendar-event suggestions). Raw transcript/media bytes
    /// never belong here.
    pub metadata: Option<serde_json::Value>,
    pub segments: Vec<OmiSegment>,
    pub media: Vec<OmiMedia>,
    /// Final structured action items. Transcript marker extraction belongs to
    /// the transport/service layer and must produce this same normalized shape.
    pub actions: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OmiCommitOptions {
    pub retain_transcript: bool,
    /// Persist the sanitized overview in the OMI ledger. Disabling this also
    /// removes its ground-truth projection on the next reconciliation.
    pub summary_enabled: bool,
    pub seed_groundtruth: bool,
    pub create_actions: bool,
    pub audio_consent: bool,
    pub image_consent: bool,
    pub video_consent: bool,
    /// Remote imports honor purge tombstones. Operator-owned local recovery
    /// tools can explicitly clear the tombstone before committing.
    pub honor_tombstone: bool,
}

impl Default for OmiCommitOptions {
    fn default() -> Self {
        Self {
            retain_transcript: false,
            summary_enabled: true,
            seed_groundtruth: true,
            create_actions: true,
            audio_consent: false,
            image_consent: false,
            video_consent: false,
            honor_tombstone: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OmiCommitKind {
    Inserted,
    Updated,
    Unchanged,
    Tombstoned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OmiCommitOutcome {
    pub kind: OmiCommitKind,
    pub groundtruth_id: Option<i64>,
    pub kanban_session_id: Option<i64>,
    pub created_tasks: usize,
    pub archived_tasks: usize,
}

type StoredProjectionIdentity = (String, String, String, Option<i64>, Option<i64>);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OmiStatus {
    pub conversations: u64,
    pub segments: u64,
    pub media: u64,
    pub actions: u64,
    pub tombstones: u64,
    /// Projection intents whose terminal result has not yet been reconciled.
    pub pending_audits: u64,
    pub sanitizer_halted: bool,
    pub last_success_ts: Option<i64>,
    pub last_error: Option<String>,
    pub last_retention_purge_ts: Option<i64>,
    pub last_retention_error: Option<String>,
    /// Last durable supervisor state (`starting`, `healthy`, `disabled`,
    /// `degraded`, `failed`, or `stopped`). CLI/Doctor additionally verify PID liveness
    /// before treating a persisted `healthy` value as active.
    pub runtime_state: Option<String>,
    /// Bounded, credential-free supervisor detail for operator diagnosis.
    pub runtime_detail: Option<String>,
    pub runtime_pid: Option<u32>,
    pub runtime_updated_ts: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OmiStoredReceipt {
    pub revision: String,
    pub status: String,
    pub finished_at_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OmiPurgeOutcome {
    pub conversations: usize,
    pub segments: usize,
    pub media: usize,
    pub actions: usize,
    pub tasks: usize,
    pub groundtruth: usize,
}

/// Private OMI projections removed immediately after an operator disables
/// their corresponding storage/effect control. This is intentionally separate
/// from source reconciliation: privacy opt-outs must not wait for the remote
/// conversation to be selected by a later deep-poll pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OmiPrivacyScrubOutcome {
    pub conversations: usize,
    pub transcript_segments: usize,
    pub media: usize,
    pub summaries: usize,
    pub groundtruth: usize,
    pub actions: usize,
    pub tasks: usize,
}

impl OmiPrivacyScrubOutcome {
    pub const fn changed(self) -> bool {
        self.conversations > 0
            || self.transcript_segments > 0
            || self.media > 0
            || self.summaries > 0
            || self.groundtruth > 0
            || self.actions > 0
            || self.tasks > 0
    }
}

fn text_hash(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

fn transcript_hash(segments: &[OmiSegment]) -> String {
    let mut body = String::new();
    for segment in segments {
        body.push_str(&segment.id);
        body.push('\0');
        body.push_str(&segment.start_ms.to_string());
        body.push(':');
        body.push_str(&segment.end_ms.to_string());
        body.push('\0');
        body.push_str(segment.speaker.as_deref().unwrap_or(""));
        body.push('\0');
        if let Some(speaker_id) = segment.speaker_id {
            body.push_str(&speaker_id.to_string());
        }
        body.push('\0');
        body.push_str(match segment.is_user {
            Some(true) => "user",
            Some(false) => "other",
            None => "unknown",
        });
        body.push('\0');
        body.push_str(segment.person_id.as_deref().unwrap_or(""));
        body.push('\0');
        body.push_str(segment.stt_provider.as_deref().unwrap_or(""));
        body.push('\0');
        body.push_str(&segment.text);
        body.push('\n');
    }
    text_hash(&body)
}

fn projection_hash(options: OmiCommitOptions) -> String {
    text_hash(&format!(
        "retain_transcript={};summary_enabled={};seed_groundtruth={};create_actions={};audio_consent={};image_consent={};video_consent={}",
        options.retain_transcript,
        options.summary_enabled,
        options.seed_groundtruth,
        options.create_actions,
        options.audio_consent,
        options.image_consent,
        options.video_consent,
    ))
}

/// True only when both the authoritative source revision and every active
/// projection/retention control match the stored row. Callers use this as a
/// no-effect preflight so periodic deep reconciliation does not emit intent
/// audit noise for strict no-ops.
pub fn projection_is_current(
    conn: &Connection,
    source_id: &str,
    revision: &str,
    status: &str,
    options: OmiCommitOptions,
) -> Result<bool> {
    let stored: Option<(String, String, String)> = conn
        .query_row(
            "SELECT revision, projection_hash, status \
             FROM idx_omi_conversations WHERE source_id = ?1",
            [source_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .context("read OMI projection identity")?;
    Ok(
        stored.is_some_and(|(stored_revision, stored_projection, stored_status)| {
            stored_revision == revision
                && stored_projection == projection_hash(options)
                && stored_status == status
        }),
    )
}

fn action_key(text: &str) -> String {
    text_hash(
        &text
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase(),
    )
}

fn validate_source_id(source_id: &str) -> Result<()> {
    if source_id.trim().is_empty() || source_id.chars().any(char::is_control) {
        bail!("OMI conversation id must be non-empty and contain no control characters");
    }
    Ok(())
}

fn validate(input: &OmiConversation) -> Result<()> {
    validate_source_id(&input.source_id)?;
    if input.revision.trim().is_empty() {
        bail!("OMI conversation revision must be non-empty");
    }
    if input.status.trim().is_empty() {
        bail!("OMI conversation status must be non-empty");
    }

    let mut segment_ids = BTreeSet::new();
    for segment in &input.segments {
        if segment.id.trim().is_empty() {
            bail!("OMI segment id must be non-empty");
        }
        if !segment_ids.insert(segment.id.as_str()) {
            bail!("duplicate OMI segment id `{}` in one revision", segment.id);
        }
        if segment.start_ms < 0 || segment.end_ms <= segment.start_ms {
            bail!(
                "invalid OMI segment timeline for `{}`: {}..{}",
                segment.id,
                segment.start_ms,
                segment.end_ms
            );
        }
    }

    let mut media_ids = BTreeSet::new();
    for item in &input.media {
        if item.id.trim().is_empty() {
            bail!("OMI media id must be non-empty");
        }
        if item.processing_status.trim().is_empty() {
            bail!("OMI media processing status must be non-empty");
        }
        let key = (item.kind.as_str(), item.id.as_str());
        if !media_ids.insert(key) {
            bail!(
                "duplicate OMI {} media id `{}` in one revision",
                item.kind.as_str(),
                item.id
            );
        }
    }
    Ok(())
}

pub fn stored_revision(conn: &Connection, source_id: &str) -> Result<Option<String>> {
    conn.query_row(
        "SELECT revision FROM idx_omi_conversations WHERE source_id = ?1",
        [source_id],
        |row| row.get(0),
    )
    .optional()
    .context("read stored OMI revision")
}

/// Minimal authoritative fields needed to finish a crash-interrupted native
/// idempotency receipt without reconstructing or overwriting private content.
pub fn stored_receipt(conn: &Connection, source_id: &str) -> Result<Option<OmiStoredReceipt>> {
    conn.query_row(
        "SELECT revision, status, finished_at_ms FROM idx_omi_conversations WHERE source_id = ?1",
        [source_id],
        |row| {
            Ok(OmiStoredReceipt {
                revision: row.get(0)?,
                status: row.get(1)?,
                finished_at_ms: row.get(2)?,
            })
        },
    )
    .optional()
    .context("read stored OMI terminal receipt")
}

pub fn is_tombstoned(conn: &Connection, source_id: &str) -> Result<bool> {
    let key = format!("tombstone:{source_id}");
    let exists: Option<i64> = conn
        .query_row("SELECT 1 FROM idx_omi_state WHERE key = ?1", [key], |row| {
            row.get(0)
        })
        .optional()
        .context("read OMI tombstone")?;
    Ok(exists.is_some())
}

pub fn clear_tombstone(conn: &Connection, source_id: &str) -> Result<bool> {
    validate_source_id(source_id)?;
    let tombstone_key = format!("tombstone:{source_id}");
    let existed: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM idx_omi_state WHERE key = ?1",
            [&tombstone_key],
            |row| row.get(0),
        )
        .optional()?;
    conn.execute(
        "DELETE FROM idx_omi_state WHERE key IN (?1, ?2, ?3, ?4, ?5)",
        params![
            tombstone_key,
            format!("developer_summary_revision:{source_id}"),
            format!("developer_detail_checked:{source_id}"),
            format!("pending_audit:{source_id}"),
            format!("native_pending_audit:{}", text_hash(source_id)),
        ],
    )?;
    Ok(existed.is_some())
}

/// Commit one final OMI revision and every derived projection atomically.
/// Identical revisions return [`OmiCommitKind::Unchanged`] before opening a
/// write transaction, so a poll replay performs exactly zero writes.
pub fn commit_conversation(
    conn: &mut Connection,
    input: &OmiConversation,
    options: OmiCommitOptions,
    now_ns: u64,
) -> Result<OmiCommitOutcome> {
    validate(input)?;
    if options.honor_tombstone && is_tombstoned(conn, &input.source_id)? {
        return Ok(OmiCommitOutcome {
            kind: OmiCommitKind::Tombstoned,
            groundtruth_id: None,
            kanban_session_id: None,
            created_tasks: 0,
            archived_tasks: 0,
        });
    }
    let active_projection_hash = projection_hash(options);
    let stored: Option<StoredProjectionIdentity> = conn
        .query_row(
            "SELECT revision, projection_hash, status, summary_groundtruth_id, kanban_session_id \
             FROM idx_omi_conversations WHERE source_id = ?1",
            [&input.source_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .context("read stored OMI projection identity")?;
    if let Some((revision, projection, status, groundtruth_id, kanban_session_id)) = stored
        && revision == input.revision
        && projection == active_projection_hash
        && status == input.status
    {
        return Ok(OmiCommitOutcome {
            kind: OmiCommitKind::Unchanged,
            groundtruth_id,
            kanban_session_id,
            created_tasks: 0,
            archived_tasks: 0,
        });
    }

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin OMI reconciliation transaction")?;
    let previous: Option<(Option<String>, Option<i64>, Option<i64>)> = tx
        .query_row(
            "SELECT summary, summary_groundtruth_id, kanban_session_id \
             FROM idx_omi_conversations WHERE source_id = ?1",
            [&input.source_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .context("read previous OMI projection")?;
    let kind = if previous.is_some() {
        OmiCommitKind::Updated
    } else {
        OmiCommitKind::Inserted
    };
    let (previous_summary, mut groundtruth_id, mut kanban_session_id) =
        previous.unwrap_or((None, None, None));
    let stored_summary = options
        .summary_enabled
        .then_some(input.summary.as_deref())
        .flatten();
    let summary_changed = previous_summary.as_deref() != stored_summary;
    let metadata_json = input
        .metadata
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .context("serialize OMI conversation metadata")?;

    let hash = transcript_hash(&input.segments);
    let photo_count = input
        .media
        .iter()
        .filter(|item| item.kind == OmiMediaKind::Image)
        .count() as i64;
    let audio_count = input
        .media
        .iter()
        .filter(|item| item.kind == OmiMediaKind::Audio)
        .count() as i64;
    let video_count = input
        .media
        .iter()
        .filter(|item| item.kind == OmiMediaKind::Video)
        .count() as i64;
    let now_i64 = i64::try_from(now_ns).unwrap_or(i64::MAX);

    tx.execute(
        "INSERT INTO idx_omi_conversations (\
             source_id, revision, projection_hash, status, source, language, started_at_ms, \
             finished_at_ms, call_id, title, summary, metadata_json, transcript_hash, \
             segment_count, photo_count, audio_count, video_count, summary_groundtruth_id, kanban_session_id, \
             retain_transcript, audio_consent, image_consent, video_consent, first_seen_ts, \
             ingested_at_ts) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                 ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?24) \
         ON CONFLICT(source_id) DO UPDATE SET \
             revision = excluded.revision, projection_hash = excluded.projection_hash, \
             status = excluded.status, source = excluded.source, language = excluded.language, \
             started_at_ms = excluded.started_at_ms, \
             finished_at_ms = excluded.finished_at_ms, call_id = excluded.call_id, \
             title = excluded.title, summary = excluded.summary, \
             metadata_json = excluded.metadata_json, \
             transcript_hash = excluded.transcript_hash, segment_count = excluded.segment_count, \
             photo_count = excluded.photo_count, audio_count = excluded.audio_count, \
             video_count = excluded.video_count, \
             retain_transcript = excluded.retain_transcript, \
             audio_consent = excluded.audio_consent, image_consent = excluded.image_consent, \
             video_consent = excluded.video_consent, ingested_at_ts = excluded.ingested_at_ts",
        params![
            input.source_id,
            input.revision,
            active_projection_hash,
            input.status,
            input.source,
            input.language,
            input.started_at_ms,
            input.finished_at_ms,
            input.call_id,
            input.title,
            stored_summary,
            metadata_json,
            hash,
            input.segments.len() as i64,
            photo_count,
            audio_count,
            video_count,
            groundtruth_id,
            kanban_session_id,
            options.retain_transcript as i64,
            options.audio_consent as i64,
            options.image_consent as i64,
            options.video_consent as i64,
            now_i64,
        ],
    )
    .context("upsert OMI conversation")?;

    tx.execute(
        "DELETE FROM idx_omi_segments WHERE conversation_id = ?1",
        [&input.source_id],
    )?;
    for (ordinal, segment) in input.segments.iter().enumerate() {
        tx.execute(
            "INSERT INTO idx_omi_segments (conversation_id, segment_id, ordinal, start_ms, \
                 end_ms, speaker, speaker_id, is_user, person_id, stt_provider, text_hash, text) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                input.source_id,
                segment.id,
                ordinal as i64,
                segment.start_ms,
                segment.end_ms,
                segment.speaker,
                segment.speaker_id,
                segment.is_user.map(|is_user| if is_user { 1 } else { 0 }),
                segment.person_id,
                segment.stt_provider,
                text_hash(&segment.text),
                options.retain_transcript.then_some(segment.text.as_str()),
            ],
        )
        .with_context(|| format!("insert OMI segment {}", segment.id))?;
    }

    tx.execute(
        "DELETE FROM idx_omi_media WHERE conversation_id = ?1",
        [&input.source_id],
    )?;
    for item in &input.media {
        let metadata_json = item
            .metadata
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .context("serialize OMI media metadata")?;
        tx.execute(
            "INSERT INTO idx_omi_media (conversation_id, media_id, kind, created_at_ms, \
                 duration_ms, content_hash, processing_status, metadata_json, processed_at_ts) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                input.source_id,
                item.id,
                item.kind.as_str(),
                item.created_at_ms,
                item.duration_ms,
                item.content_hash,
                item.processing_status,
                metadata_json,
                item.processed_at_ts,
            ],
        )
        .with_context(|| format!("insert OMI {} media {}", item.kind.as_str(), item.id))?;
    }

    let desired_groundtruth = options
        .seed_groundtruth
        .then_some(stored_summary)
        .flatten()
        .filter(|summary| !summary.trim().is_empty());
    if desired_groundtruth.is_none() {
        if let Some(old_id) = groundtruth_id.take() {
            crate::memory::groundtruth::revoke(&tx, old_id, now_i64)
                .context("revoke disabled OMI summary candidate")?;
        }
    } else if summary_changed || groundtruth_id.is_none() {
        if let Some(old_id) = groundtruth_id.take() {
            crate::memory::groundtruth::revoke(&tx, old_id, now_i64)
                .context("revoke superseded OMI summary candidate")?;
        }
        if let Some(summary) = desired_groundtruth {
            let scope = format!("omi:{}", input.source_id);
            groundtruth_id = Some(
                crate::memory::groundtruth::insert(
                    &tx,
                    summary,
                    &crate::memory::groundtruth::Source::Omi,
                    &scope,
                    now_i64,
                )
                .context("seed OMI summary candidate")?,
            );
        }
    }

    let mut created_tasks = 0usize;
    let mut archived_tasks = 0usize;
    let mut existing = BTreeMap::<String, i64>::new();
    {
        let mut stmt = tx.prepare(
            "SELECT action_hash, task_id FROM idx_omi_actions WHERE conversation_id = ?1",
        )?;
        for row in stmt.query_map([&input.source_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })? {
            let (key, task_id) = row?;
            existing.insert(key, task_id);
        }
    }
    if options.create_actions || !existing.is_empty() {
        crate::coding::store::ensure_schema(&tx).context("ensure OMI kanban schema")?;
        let mut current = BTreeMap::<String, &str>::new();
        if options.create_actions {
            for action in input
                .actions
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
            {
                current.entry(action_key(action)).or_insert(action);
            }
        }
        for (key, task_id) in existing
            .iter()
            .filter(|(key, _)| !current.contains_key(*key))
        {
            crate::coding::store::patch_task_status(
                &tx,
                KanbanTaskId(*task_id),
                TaskStatus::Archived,
                now_ns,
            )
            .with_context(|| format!("archive removed OMI action task {task_id}"))?;
            tx.execute(
                "DELETE FROM idx_omi_actions WHERE conversation_id = ?1 AND action_hash = ?2",
                params![input.source_id, key],
            )?;
            archived_tasks += 1;
        }

        let has_new = current.keys().any(|key| !existing.contains_key(key));
        if has_new && kanban_session_id.is_none() {
            let title = input.title.as_deref().unwrap_or("OMI conversation ingest");
            kanban_session_id = Some(
                crate::coding::store::insert_session(
                    &tx,
                    now_ns,
                    title,
                    &text_hash(&format!("{}:{}", input.source_id, input.revision)),
                    "omi",
                    None,
                )
                .context("create OMI kanban session")?
                .raw(),
            );
        }
        if let Some(session_id) = kanban_session_id {
            for (key, action) in current {
                if existing.contains_key(&key) {
                    continue;
                }
                let task_id = crate::coding::store::insert_task(
                    &tx,
                    KanbanSessionId(session_id),
                    now_ns,
                    action,
                    Some(&format!("OMI conversation {}", input.source_id)),
                    "omi_action",
                    None,
                )
                .with_context(|| format!("create OMI action `{action}`"))?;
                tx.execute(
                    "INSERT INTO idx_omi_actions \
                         (conversation_id, action_hash, task_id, created_at_ts) \
                     VALUES (?1, ?2, ?3, ?4)",
                    params![input.source_id, key, task_id.raw(), now_i64],
                )?;
                created_tasks += 1;
            }
        }
    }

    tx.execute(
        "UPDATE idx_omi_conversations \
         SET summary_groundtruth_id = ?2, kanban_session_id = ?3 \
         WHERE source_id = ?1",
        params![input.source_id, groundtruth_id, kanban_session_id],
    )?;
    tx.commit()
        .context("commit OMI reconciliation transaction")?;

    Ok(OmiCommitOutcome {
        kind,
        groundtruth_id,
        kanban_session_id,
        created_tasks,
        archived_tasks,
    })
}

pub fn set_state(conn: &Connection, key: &str, value: &str, now_ts: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO idx_omi_state (key, value, updated_ts) VALUES (?1, ?2, ?3) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_ts = excluded.updated_ts",
        params![key, value, now_ts],
    )?;
    Ok(())
}

pub fn get_state(conn: &Connection, key: &str) -> Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM idx_omi_state WHERE key = ?1",
        [key],
        |row| row.get(0),
    )
    .optional()
    .context("read OMI state")
}

pub fn get_state_with_timestamp(conn: &Connection, key: &str) -> Result<Option<(String, i64)>> {
    conn.query_row(
        "SELECT value, updated_ts FROM idx_omi_state WHERE key = ?1",
        [key],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .context("read timestamped OMI state")
}

/// Apply disabled OMI projection controls to every already-stored
/// conversation in one transaction. Affected projection hashes are invalidated
/// so a future authoritative source reconciliation can rebuild only the
/// projections that remain enabled.
///
/// Ground-truth rows and kanban sessions are deleted rather than merely
/// revoked/archived: those rows contain the derived private text whose storage
/// the operator just disabled. OMI owns the referenced session per
/// conversation, so deleting it cannot remove a non-OMI task.
pub fn scrub_disabled_projections(
    conn: &mut Connection,
    options: OmiCommitOptions,
) -> Result<OmiPrivacyScrubOutcome> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin OMI privacy scrub transaction")?;
    let mut affected = BTreeSet::<String>::new();
    let mut outcome = OmiPrivacyScrubOutcome::default();

    if !options.retain_transcript {
        let source_ids = {
            let mut stmt = tx.prepare(
                "SELECT c.source_id FROM idx_omi_conversations c \
                 WHERE c.retain_transcript != 0 OR EXISTS (\
                     SELECT 1 FROM idx_omi_segments s \
                     WHERE s.conversation_id = c.source_id AND s.text IS NOT NULL\
                 )",
            )?;
            stmt.query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        affected.extend(source_ids);
        outcome.transcript_segments = tx.execute(
            "UPDATE idx_omi_segments SET text = NULL WHERE text IS NOT NULL",
            [],
        )?;
        tx.execute(
            "UPDATE idx_omi_conversations SET retain_transcript = 0 \
             WHERE retain_transcript != 0",
            [],
        )?;
    }

    for (enabled, kind, count_column, consent_column) in [
        (
            options.audio_consent,
            "audio",
            "audio_count",
            "audio_consent",
        ),
        (
            options.image_consent,
            "image",
            "photo_count",
            "image_consent",
        ),
        (
            options.video_consent,
            "video",
            "video_count",
            "video_consent",
        ),
    ] {
        if enabled {
            continue;
        }
        let source_ids = {
            let query = format!(
                "SELECT c.source_id FROM idx_omi_conversations c \
                 WHERE c.{consent_column} != 0 OR EXISTS (\
                     SELECT 1 FROM idx_omi_media m \
                     WHERE m.conversation_id = c.source_id AND m.kind = ?1\
                 )"
            );
            let mut stmt = tx.prepare(&query)?;
            stmt.query_map([kind], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        affected.extend(source_ids);
        outcome.media += tx.execute("DELETE FROM idx_omi_media WHERE kind = ?1", [kind])?;
        tx.execute(
            &format!(
                "UPDATE idx_omi_conversations \
                 SET {count_column} = 0, {consent_column} = 0 \
                 WHERE {count_column} != 0 OR {consent_column} != 0"
            ),
            [],
        )?;
    }

    if !options.summary_enabled || !options.seed_groundtruth {
        let source_ids = {
            let mut stmt = tx.prepare(
                "SELECT c.source_id FROM idx_omi_conversations c \
                 WHERE c.summary_groundtruth_id IS NOT NULL \
                    OR EXISTS (\
                        SELECT 1 FROM idx_groundtruth g \
                        WHERE g.source = 'omi' AND g.scope = 'omi:' || c.source_id\
                    ) \
                    OR (?1 = 0 AND c.summary IS NOT NULL)",
            )?;
            stmt.query_map([options.summary_enabled as i64], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
        };
        affected.extend(source_ids);
        outcome.groundtruth = tx.execute(
            "DELETE FROM idx_groundtruth \
             WHERE source = 'omi' AND EXISTS (\
                 SELECT 1 FROM idx_omi_conversations c \
                 WHERE idx_groundtruth.scope = 'omi:' || c.source_id\
             )",
            [],
        )?;
        tx.execute(
            "UPDATE idx_omi_conversations SET summary_groundtruth_id = NULL \
             WHERE summary_groundtruth_id IS NOT NULL",
            [],
        )?;
        if !options.summary_enabled {
            outcome.summaries = tx.execute(
                "UPDATE idx_omi_conversations SET summary = NULL WHERE summary IS NOT NULL",
                [],
            )?;
        }
    }

    if !options.create_actions {
        let source_ids = {
            let mut stmt = tx.prepare(
                "SELECT c.source_id FROM idx_omi_conversations c \
                 WHERE c.kanban_session_id IS NOT NULL OR EXISTS (\
                     SELECT 1 FROM idx_omi_actions a \
                     WHERE a.conversation_id = c.source_id\
                 )",
            )?;
            stmt.query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        affected.extend(source_ids);
        let session_ids = {
            let mut stmt = tx.prepare(
                "SELECT DISTINCT kanban_session_id FROM idx_omi_conversations \
                 WHERE kanban_session_id IS NOT NULL",
            )?;
            stmt.query_map([], |row| row.get::<_, i64>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        outcome.actions = tx.execute("DELETE FROM idx_omi_actions", [])?;
        if !session_ids.is_empty() {
            crate::coding::store::ensure_schema(&tx).context("ensure OMI kanban schema")?;
        }
        for session_id in session_ids {
            tx.execute(
                "DELETE FROM idx_kanban_task_event WHERE task_id IN \
                 (SELECT task_id FROM idx_kanban_task WHERE session_id = ?1)",
                [session_id],
            )?;
            tx.execute(
                "DELETE FROM idx_kanban_comment WHERE task_id IN \
                 (SELECT task_id FROM idx_kanban_task WHERE session_id = ?1)",
                [session_id],
            )?;
            tx.execute(
                "DELETE FROM idx_kanban_task_dep WHERE task_id IN \
                 (SELECT task_id FROM idx_kanban_task WHERE session_id = ?1) \
                 OR depends_on_task_id IN \
                 (SELECT task_id FROM idx_kanban_task WHERE session_id = ?1)",
                [session_id],
            )?;
            outcome.tasks += tx.execute(
                "DELETE FROM idx_kanban_task WHERE session_id = ?1",
                [session_id],
            )?;
            tx.execute(
                "DELETE FROM idx_kanban_session WHERE session_id = ?1",
                [session_id],
            )?;
        }
        tx.execute(
            "UPDATE idx_omi_conversations SET kanban_session_id = NULL \
             WHERE kanban_session_id IS NOT NULL",
            [],
        )?;
    }

    for source_id in &affected {
        tx.execute(
            "UPDATE idx_omi_conversations SET projection_hash = '' WHERE source_id = ?1",
            [source_id],
        )?;
    }
    outcome.conversations = affected.len();
    tx.commit()
        .context("commit OMI privacy scrub transaction")?;
    Ok(outcome)
}

pub fn mark_remote_unavailable(conn: &Connection, source_id: &str) -> Result<bool> {
    let updated = conn.execute(
        "UPDATE idx_omi_conversations SET status = 'remote_unavailable' \
         WHERE source_id = ?1 AND status <> 'remote_unavailable'",
        [source_id],
    )?;
    Ok(updated > 0)
}

/// Native call journals are filesystem derivatives, but their durable deletion
/// is driven by the SQLite tombstone source of truth. Returning the tombstoned
/// native source ids lets the service/CLI remove those journals without making
/// the memory layer depend on filesystem layout.
pub fn tombstoned_native_source_ids(conn: &Connection) -> Result<Vec<String>> {
    let mut statement = conn.prepare(
        "SELECT substr(key, length('tombstone:') + 1) \
         FROM idx_omi_state WHERE key LIKE 'tombstone:native:%' ORDER BY key",
    )?;
    statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("read tombstoned native OMI source ids")
}

pub fn status(conn: &Connection) -> Result<OmiStatus> {
    fn count(conn: &Connection, table: &str) -> Result<u64> {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        let value: i64 = conn.query_row(&sql, [], |row| row.get(0))?;
        Ok(value.max(0) as u64)
    }
    let tombstones: i64 = conn.query_row(
        "SELECT COUNT(*) FROM idx_omi_state WHERE key LIKE 'tombstone:%'",
        [],
        |row| row.get(0),
    )?;
    let pending_audits: i64 = conn.query_row(
        "SELECT COUNT(*) FROM idx_omi_state \
         WHERE key GLOB 'pending_audit:*' OR key GLOB 'native_pending_audit:*'",
        [],
        |row| row.get(0),
    )?;
    let runtime = get_state_with_timestamp(conn, "runtime_state")?;
    Ok(OmiStatus {
        conversations: count(conn, "idx_omi_conversations")?,
        segments: count(conn, "idx_omi_segments")?,
        media: count(conn, "idx_omi_media")?,
        actions: count(conn, "idx_omi_actions")?,
        tombstones: tombstones.max(0) as u64,
        pending_audits: pending_audits.max(0) as u64,
        sanitizer_halted: get_state(conn, "sanitizer_halted")?.is_some(),
        last_success_ts: get_state(conn, "last_success_ts")?.and_then(|value| value.parse().ok()),
        last_error: get_state(conn, "last_error")?.filter(|value| !value.is_empty()),
        last_retention_purge_ts: get_state(conn, "last_retention_purge_ts")?
            .and_then(|value| value.parse().ok()),
        last_retention_error: get_state(conn, "last_retention_error")?
            .filter(|value| !value.is_empty()),
        runtime_state: runtime.as_ref().map(|(value, _)| value.clone()),
        runtime_detail: get_state(conn, "runtime_detail")?.filter(|value| !value.is_empty()),
        runtime_pid: get_state(conn, "runtime_pid")?.and_then(|value| value.parse().ok()),
        runtime_updated_ts: runtime.map(|(_, updated_ts)| updated_ts),
    })
}

fn purge_conversation_in_tx(
    tx: &Transaction<'_>,
    source_id: &str,
    now_ns: u64,
    reason: &str,
) -> Result<OmiPurgeOutcome> {
    fn clear_reconciliation_state(tx: &Transaction<'_>, source_id: &str) -> Result<()> {
        for key in [
            format!("developer_summary_revision:{source_id}"),
            format!("developer_detail_checked:{source_id}"),
            format!("pending_audit:{source_id}"),
            format!("native_pending_audit:{}", text_hash(source_id)),
        ] {
            tx.execute("DELETE FROM idx_omi_state WHERE key = ?1", [key])?;
        }
        Ok(())
    }

    let ids: Option<(Option<i64>, Option<i64>)> = tx
        .query_row(
            "SELECT summary_groundtruth_id, kanban_session_id \
             FROM idx_omi_conversations WHERE source_id = ?1",
            [source_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((groundtruth_id, session_id)) = ids else {
        set_state(
            tx,
            &format!("tombstone:{source_id}"),
            reason,
            i64::try_from(now_ns).unwrap_or(i64::MAX),
        )?;
        clear_reconciliation_state(tx, source_id)?;
        return Ok(OmiPurgeOutcome::default());
    };

    let segments = tx.query_row(
        "SELECT COUNT(*) FROM idx_omi_segments WHERE conversation_id = ?1",
        [source_id],
        |row| row.get::<_, i64>(0),
    )? as usize;
    let media = tx.query_row(
        "SELECT COUNT(*) FROM idx_omi_media WHERE conversation_id = ?1",
        [source_id],
        |row| row.get::<_, i64>(0),
    )? as usize;
    let actions = tx.query_row(
        "SELECT COUNT(*) FROM idx_omi_actions WHERE conversation_id = ?1",
        [source_id],
        |row| row.get::<_, i64>(0),
    )? as usize;

    let mut tasks = 0usize;
    if let Some(session_id) = session_id {
        tx.execute(
            "DELETE FROM idx_kanban_task_event WHERE task_id IN \
             (SELECT task_id FROM idx_kanban_task WHERE session_id = ?1)",
            [session_id],
        )?;
        tx.execute(
            "DELETE FROM idx_kanban_comment WHERE task_id IN \
             (SELECT task_id FROM idx_kanban_task WHERE session_id = ?1)",
            [session_id],
        )?;
        tx.execute(
            "DELETE FROM idx_kanban_task_dep WHERE task_id IN \
             (SELECT task_id FROM idx_kanban_task WHERE session_id = ?1) \
             OR depends_on_task_id IN \
             (SELECT task_id FROM idx_kanban_task WHERE session_id = ?1)",
            [session_id],
        )?;
        tasks = tx.execute(
            "DELETE FROM idx_kanban_task WHERE session_id = ?1",
            [session_id],
        )?;
        tx.execute(
            "DELETE FROM idx_kanban_session WHERE session_id = ?1",
            [session_id],
        )?;
    }
    let groundtruth = if let Some(id) = groundtruth_id {
        tx.execute("DELETE FROM idx_groundtruth WHERE id = ?1", [id])?
    } else {
        0
    };
    let conversations = tx.execute(
        "DELETE FROM idx_omi_conversations WHERE source_id = ?1",
        [source_id],
    )?;
    set_state(
        tx,
        &format!("tombstone:{source_id}"),
        reason,
        i64::try_from(now_ns).unwrap_or(i64::MAX),
    )?;
    // Per-source reconciliation cursors/audit recovery markers are derivatives
    // too. Keep only the anti-resurrection tombstone above.
    clear_reconciliation_state(tx, source_id)?;
    Ok(OmiPurgeOutcome {
        conversations,
        segments,
        media,
        actions,
        tasks,
        groundtruth,
    })
}

/// Delete a conversation and all locally-derived private data atomically, then
/// leave an operator tombstone that blocks automatic remote resurrection.
pub fn purge_conversation(
    conn: &mut Connection,
    source_id: &str,
    now_ns: u64,
) -> Result<OmiPurgeOutcome> {
    validate_source_id(source_id)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin OMI purge transaction")?;
    let outcome = purge_conversation_in_tx(&tx, source_id, now_ns, "operator_deleted")?;
    tx.commit().context("commit OMI purge transaction")?;
    Ok(outcome)
}

/// Atomically expire every OMI conversation ingested before `cutoff_ns`.
/// Retention tombstones are intentional: an old remote conversation must not
/// be re-imported on the next poll and thereby defeat the configured window.
pub fn purge_expired(
    conn: &mut Connection,
    cutoff_ns: u64,
    now_ns: u64,
) -> Result<OmiPurgeOutcome> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin OMI retention transaction")?;
    let cutoff = i64::try_from(cutoff_ns).unwrap_or(i64::MAX);
    let source_ids = {
        let mut stmt = tx.prepare(
            "SELECT source_id FROM idx_omi_conversations \
             WHERE ingested_at_ts < ?1 ORDER BY source_id",
        )?;
        stmt.query_map([cutoff], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };

    let mut total = OmiPurgeOutcome::default();
    for source_id in source_ids {
        let outcome = purge_conversation_in_tx(&tx, &source_id, now_ns, "retention_expired")?;
        total.conversations += outcome.conversations;
        total.segments += outcome.segments;
        total.media += outcome.media;
        total.actions += outcome.actions;
        total.tasks += outcome.tasks;
        total.groundtruth += outcome.groundtruth;
    }
    set_state(
        &tx,
        "last_retention_purge_ts",
        &now_ns.to_string(),
        i64::try_from(now_ns).unwrap_or(i64::MAX),
    )?;
    tx.execute(
        "DELETE FROM idx_omi_state WHERE key = 'last_retention_error'",
        [],
    )?;
    tx.commit().context("commit OMI retention transaction")?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        crate::coding::store::ensure_schema(&conn).unwrap();
        (dir, conn)
    }

    fn conversation(revision: &str) -> OmiConversation {
        OmiConversation {
            source_id: "conv-1".into(),
            revision: revision.into(),
            status: "completed".into(),
            source: Some("phone_call".into()),
            language: Some("en".into()),
            started_at_ms: Some(1_000),
            finished_at_ms: Some(5_000),
            call_id: Some("call-1".into()),
            title: Some("Planning call".into()),
            summary: Some("The team agreed to ship the release on Friday.".into()),
            metadata: Some(serde_json::json!({"category":"work"})),
            segments: vec![OmiSegment {
                id: "seg-1".into(),
                start_ms: 0,
                end_ms: 1_500,
                speaker: Some("SPEAKER_00".into()),
                speaker_id: Some(0),
                is_user: Some(true),
                person_id: None,
                stt_provider: Some("deepgram".into()),
                text: "We should ship the release on Friday.".into(),
            }],
            media: vec![OmiMedia {
                id: "audio-1".into(),
                kind: OmiMediaKind::Audio,
                created_at_ms: Some(1_000),
                duration_ms: Some(4_000),
                content_hash: None,
                processing_status: "remote_metadata_only".into(),
                metadata: Some(serde_json::json!({"provider":"gcp"})),
                processed_at_ts: None,
            }],
            actions: vec!["TODO: publish the release notes".into()],
        }
    }

    #[test]
    fn same_revision_is_a_strict_noop() {
        let (_dir, mut conn) = open();
        let first = commit_conversation(
            &mut conn,
            &conversation("r1"),
            OmiCommitOptions::default(),
            1_000_000_000,
        )
        .unwrap();
        assert_eq!(first.kind, OmiCommitKind::Inserted);
        assert_eq!(first.created_tasks, 1);
        let groundtruth_id = first
            .groundtruth_id
            .expect("summary projection must create one groundtruth candidate");
        let confirmations_before: i64 = conn
            .query_row(
                "SELECT confirmed_count FROM idx_groundtruth WHERE id = ?1",
                [groundtruth_id],
                |row| row.get(0),
            )
            .unwrap();

        let second = commit_conversation(
            &mut conn,
            &conversation("r1"),
            OmiCommitOptions::default(),
            2_000_000_000,
        )
        .unwrap();
        assert_eq!(second.kind, OmiCommitKind::Unchanged);
        assert_eq!(second.created_tasks, 0);
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM idx_omi_segments", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM idx_kanban_task", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        let confirmations_after: i64 = conn
            .query_row(
                "SELECT confirmed_count FROM idx_groundtruth WHERE id = ?1",
                [groundtruth_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            confirmations_after, confirmations_before,
            "poll replay must not mature the candidate"
        );
    }

    #[test]
    fn remote_unavailable_is_idempotent_does_not_extend_retention_and_recovers() {
        let (_dir, mut conn) = open();
        commit_conversation(
            &mut conn,
            &conversation("r1"),
            OmiCommitOptions::default(),
            100,
        )
        .unwrap();
        assert!(mark_remote_unavailable(&conn, "conv-1").unwrap());
        assert!(!mark_remote_unavailable(&conn, "conv-1").unwrap());
        let (status, ingested_at): (String, i64) = conn
            .query_row(
                "SELECT status, ingested_at_ts FROM idx_omi_conversations WHERE source_id = 'conv-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "remote_unavailable");
        assert_eq!(ingested_at, 100, "404 polling must not postpone retention");

        let recovered = commit_conversation(
            &mut conn,
            &conversation("r1"),
            OmiCommitOptions::default(),
            200,
        )
        .unwrap();
        assert_eq!(recovered.kind, OmiCommitKind::Updated);
        assert_eq!(
            conn.query_row(
                "SELECT status FROM idx_omi_conversations WHERE source_id = 'conv-1'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "completed"
        );
    }

    #[test]
    fn transcript_retention_is_explicit() {
        let (_dir, mut conn) = open();
        commit_conversation(
            &mut conn,
            &conversation("r1"),
            OmiCommitOptions::default(),
            1,
        )
        .unwrap();
        let (hash, text): (String, Option<String>) = conn
            .query_row("SELECT text_hash, text FROM idx_omi_segments", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert!(!hash.is_empty());
        assert!(text.is_none());
    }

    #[test]
    fn same_remote_revision_reconciles_changed_projection_controls() {
        let (_dir, mut conn) = open();
        let first = commit_conversation(
            &mut conn,
            &conversation("r1"),
            OmiCommitOptions::default(),
            1,
        )
        .unwrap();
        let groundtruth_id = first.groundtruth_id.unwrap();

        let controls = OmiCommitOptions {
            retain_transcript: true,
            summary_enabled: false,
            seed_groundtruth: false,
            create_actions: false,
            ..OmiCommitOptions::default()
        };
        let changed = commit_conversation(&mut conn, &conversation("r1"), controls, 2).unwrap();
        assert_eq!(changed.kind, OmiCommitKind::Updated);
        assert_eq!(changed.groundtruth_id, None);
        assert_eq!(changed.archived_tasks, 1);

        let (summary, text, actions, status): (Option<String>, Option<String>, i64, String) = conn
            .query_row(
                "SELECT c.summary, s.text, \
                    (SELECT COUNT(*) FROM idx_omi_actions), \
                    (SELECT status FROM idx_kanban_task ORDER BY task_id LIMIT 1) \
                 FROM idx_omi_conversations c \
                 JOIN idx_omi_segments s ON s.conversation_id = c.source_id",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert!(summary.is_none());
        assert_eq!(
            text.as_deref(),
            Some("We should ship the release on Friday.")
        );
        assert_eq!(actions, 0);
        assert_eq!(status, "archived");
        let revoked_at: Option<i64> = conn
            .query_row(
                "SELECT revoked_at FROM idx_groundtruth WHERE id = ?1",
                [groundtruth_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(revoked_at, Some(2));

        let replay = commit_conversation(&mut conn, &conversation("r1"), controls, 3).unwrap();
        assert_eq!(replay.kind, OmiCommitKind::Unchanged);
        assert_eq!(replay.archived_tasks, 0);
    }

    #[test]
    fn changed_revision_reconciles_actions_without_duplicates() {
        let (_dir, mut conn) = open();
        commit_conversation(
            &mut conn,
            &conversation("r1"),
            OmiCommitOptions::default(),
            1,
        )
        .unwrap();
        let mut changed = conversation("r2");
        changed.actions = vec!["TODO: notify users".into()];
        let out = commit_conversation(&mut conn, &changed, OmiCommitOptions::default(), 2).unwrap();
        assert_eq!(out.kind, OmiCommitKind::Updated);
        assert_eq!(out.archived_tasks, 1);
        assert_eq!(out.created_tasks, 1);
        let statuses: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT status FROM idx_kanban_task ORDER BY task_id")
                .unwrap();
            stmt.query_map([], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        assert_eq!(statuses, vec!["archived", "backlog"]);
    }

    #[test]
    fn privacy_opt_out_scrubs_sqlite_and_all_historical_derived_text_immediately() {
        let (_dir, mut conn) = open();
        let retained = OmiCommitOptions {
            retain_transcript: true,
            audio_consent: true,
            ..OmiCommitOptions::default()
        };
        commit_conversation(&mut conn, &conversation("r1"), retained, 1).unwrap();

        let mut revised = conversation("r2");
        revised.summary = Some("A superseding private summary.".into());
        revised.actions = vec!["TODO: superseding private task".into()];
        commit_conversation(&mut conn, &revised, retained, 2).unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM idx_groundtruth", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            2,
            "the fixture includes one revoked historical summary"
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM idx_kanban_task", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            2,
            "the fixture includes one archived historical action"
        );

        let disabled = OmiCommitOptions {
            retain_transcript: false,
            summary_enabled: false,
            seed_groundtruth: false,
            create_actions: false,
            ..OmiCommitOptions::default()
        };
        let scrubbed = scrub_disabled_projections(&mut conn, disabled).unwrap();
        assert_eq!(scrubbed.conversations, 1);
        assert_eq!(scrubbed.transcript_segments, 1);
        assert_eq!(scrubbed.media, 1);
        assert_eq!(scrubbed.summaries, 1);
        assert_eq!(scrubbed.groundtruth, 2);
        assert_eq!(scrubbed.actions, 1);
        assert_eq!(scrubbed.tasks, 2);

        let row: (Option<String>, i64, Option<i64>, Option<i64>, String) = conn
            .query_row(
                "SELECT summary, retain_transcript, summary_groundtruth_id, \
                        kanban_session_id, projection_hash \
                 FROM idx_omi_conversations WHERE source_id = 'conv-1'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(row, (None, 0, None, None, String::new()));
        let segment_text: Option<String> = conn
            .query_row("SELECT text FROM idx_omi_segments", [], |row| row.get(0))
            .unwrap();
        assert!(segment_text.is_none());
        for table in [
            "idx_groundtruth",
            "idx_omi_actions",
            "idx_kanban_task",
            "idx_kanban_session",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "private derivative remained in {table}");
        }
        assert_eq!(
            scrub_disabled_projections(&mut conn, disabled).unwrap(),
            OmiPrivacyScrubOutcome::default(),
            "privacy scrub must be idempotent"
        );
    }

    #[test]
    fn purge_cascades_private_derivatives_and_blocks_reimport() {
        let (_dir, mut conn) = open();
        commit_conversation(
            &mut conn,
            &conversation("r1"),
            OmiCommitOptions::default(),
            1,
        )
        .unwrap();
        let purged = purge_conversation(&mut conn, "conv-1", 2).unwrap();
        assert_eq!(purged.conversations, 1);
        assert_eq!(purged.segments, 1);
        assert_eq!(purged.media, 1);
        assert_eq!(purged.actions, 1);
        assert_eq!(purged.tasks, 1);
        assert_eq!(purged.groundtruth, 1);
        assert!(is_tombstoned(&conn, "conv-1").unwrap());
        let retry = commit_conversation(
            &mut conn,
            &conversation("r2"),
            OmiCommitOptions::default(),
            3,
        )
        .unwrap();
        assert_eq!(retry.kind, OmiCommitKind::Tombstoned);
        assert_eq!(status(&conn).unwrap().conversations, 0);
    }

    #[test]
    fn allow_reimport_clears_every_reconciliation_key_idempotently() {
        let (_dir, conn) = open();
        let source_id = "native:call-reimport";
        for key in [
            format!("tombstone:{source_id}"),
            format!("developer_summary_revision:{source_id}"),
            format!("developer_detail_checked:{source_id}"),
            format!("pending_audit:{source_id}"),
            format!("native_pending_audit:{}", text_hash(source_id)),
        ] {
            set_state(&conn, &key, "stale", 1).unwrap();
        }

        assert!(clear_tombstone(&conn, source_id).unwrap());
        assert!(!clear_tombstone(&conn, source_id).unwrap());
        for key in [
            format!("tombstone:{source_id}"),
            format!("developer_summary_revision:{source_id}"),
            format!("developer_detail_checked:{source_id}"),
            format!("pending_audit:{source_id}"),
            format!("native_pending_audit:{}", text_hash(source_id)),
        ] {
            assert_eq!(get_state(&conn, &key).unwrap(), None, "stale key: {key}");
        }
    }

    #[test]
    fn retention_purge_is_atomic_and_tombstones_only_expired_rows() {
        let (_dir, mut conn) = open();
        let old = conversation("old-revision");
        commit_conversation(&mut conn, &old, OmiCommitOptions::default(), 1).unwrap();

        let mut recent = conversation("recent-revision");
        recent.source_id = "conv-2".into();
        commit_conversation(&mut conn, &recent, OmiCommitOptions::default(), 100).unwrap();

        let purged = purge_expired(&mut conn, 50, 200).unwrap();
        assert_eq!(purged.conversations, 1);
        assert_eq!(purged.segments, 1);
        assert_eq!(purged.media, 1);
        assert_eq!(purged.actions, 1);
        assert_eq!(purged.tasks, 1);
        assert_eq!(purged.groundtruth, 1);
        assert_eq!(status(&conn).unwrap().conversations, 1);
        assert_eq!(
            get_state(&conn, "tombstone:conv-1").unwrap().as_deref(),
            Some("retention_expired")
        );
        assert!(!is_tombstoned(&conn, "conv-2").unwrap());
        assert_eq!(
            get_state(&conn, "last_retention_purge_ts")
                .unwrap()
                .as_deref(),
            Some("200")
        );
    }

    #[test]
    fn duplicate_segment_id_rejects_whole_revision() {
        let (_dir, mut conn) = open();
        let mut input = conversation("r1");
        input.segments.push(input.segments[0].clone());
        let err =
            commit_conversation(&mut conn, &input, OmiCommitOptions::default(), 1).unwrap_err();
        assert!(err.to_string().contains("duplicate OMI segment id"));
        assert_eq!(status(&conn).unwrap().conversations, 0);
    }

    #[test]
    fn zero_duration_segment_rejects_whole_revision() {
        let (_dir, mut conn) = open();
        let mut input = conversation("r1");
        input.segments[0].end_ms = input.segments[0].start_ms;
        let err =
            commit_conversation(&mut conn, &input, OmiCommitOptions::default(), 1).unwrap_err();
        assert!(err.to_string().contains("invalid OMI segment timeline"));
        assert_eq!(status(&conn).unwrap().conversations, 0);
    }

    #[test]
    fn status_exposes_pending_reconciliation_and_timestamped_runtime_health() {
        let (_dir, conn) = open();
        set_state(&conn, "pending_audit:conversation-1", "revision", 10).unwrap();
        set_state(&conn, "runtime_state", "healthy", 20).unwrap();
        set_state(&conn, "runtime_detail", "ready", 20).unwrap();
        set_state(&conn, "runtime_pid", "42", 20).unwrap();

        let status = status(&conn).unwrap();
        assert_eq!(status.pending_audits, 1);
        assert_eq!(status.runtime_state.as_deref(), Some("healthy"));
        assert_eq!(status.runtime_detail.as_deref(), Some("ready"));
        assert_eq!(status.runtime_pid, Some(42));
        assert_eq!(status.runtime_updated_ts, Some(20));
    }
}
