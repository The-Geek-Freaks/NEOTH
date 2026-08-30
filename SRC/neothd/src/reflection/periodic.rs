//! Daily + yearly self-reflection cadences.
//!
//! Mirrors the weekly OB-02 surface ([`super::WeeklyReflection`]): an archivable
//! record that persists as JSONL under `<home>/reflections/<kind>/<tag>.jsonl`
//! and renders to an Obsidian note at `<vault>/<subdir>/{Daily,Yearly}/<tag>.md`.
//! Builders compose a record from the period's top operator topics. Same
//! deterministic, offline, free rationale as the weekly reflection — no LLM, no
//! network, so the nightly + year-end passes run unattended even with the cloud
//! quota exhausted.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

use cap_std::fs::Dir;
use sha2::{Digest as _, Sha256};

pub const MAX_DAILY_ADMISSION_ARCHIVE_BYTES: usize = 256 * 1024;
pub const MAX_DAILY_ADMISSION_ARCHIVE_LINES: usize = 64;
/// Version of the physical Daily archive/note retention policy.
pub const DAILY_RETENTION_CONFIG_VERSION: u16 = 1;
/// The Gold calendar boundary is the migration-safe default. Historical valid
/// `reflect_topics.yaml` files request no more than ninety whole UTC dates;
/// an unattested historical note remains explicit retention debt until the
/// authority-backed migration can verify and retire it safely.
pub const DEFAULT_DAILY_RETENTION_DAYS: u16 = 90;
pub const MAX_DAILY_RETENTION_DAYS: u16 = 90;
const MAX_DAILY_ADMISSION_MARKER_BYTES: usize = 64;
const MAX_OBSIDIAN_SUBDIR_COMPONENTS: usize = 16;
const MAX_OBSIDIAN_SUBDIR_BYTES: usize = 512;
const MAX_OBSIDIAN_SUBDIR_COMPONENT_BYTES: usize = 128;
// A normal at-ceiling history has at most 90 retained date tags (today plus
// eighty-nine prior dates). Historical migrations run in small deterministic
// batches, while the capability-relative validation inventory stays bounded
// enough to tolerate multiple years without becoming an unbounded scan.
const MAX_DAILY_RETENTION_ENTRIES: usize = 4_096;
const MAX_DAILY_RETENTION_BATCH_ENTRIES: usize = 64;
// This is the combined archive + managed-note input budget; a refusal is
// safer than turning a damaged vault into an unbounded memory inventory.
const MAX_DAILY_RETENTION_TOTAL_BYTES: usize = 96 * 1024 * 1024;
// Markdown renders topics in frontmatter, body, and a list, so an exact
// managed note can legitimately be larger than its bounded JSON archive.
const MAX_DAILY_RETENTION_NOTE_BYTES: usize = MAX_DAILY_ADMISSION_ARCHIVE_BYTES * 3;

/// Exhaustive production inventory. These are the only daily producers; both
/// call [`settle_daily_admission`], which owns the sole
/// [`DailyArchiveTransaction::append_once`] path. Keep this list and its
/// contract test in lockstep with any new producer.
pub const DAILY_PRODUCTION_WRITERS: &[&str] = &[
    "cli::reflect::run_reflect",
    "daemon::reflection_cron::run_period_reflection_tick_once",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DailyArchiveStatus {
    Missing,
    Matching,
}

/// Versioned physical-retention policy carried by `reflect_topics.yaml`.
/// There is intentionally no `enabled` switch: a future authority-backed
/// executor must not silently disable the bounded Gold ceiling policy.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DailyRetentionConfig {
    pub version: u16,
    pub retention_days: u16,
}

impl Default for DailyRetentionConfig {
    fn default() -> Self {
        Self {
            version: DAILY_RETENTION_CONFIG_VERSION,
            retention_days: DEFAULT_DAILY_RETENTION_DAYS,
        }
    }
}

impl DailyRetentionConfig {
    pub fn validate(&self) -> Result<(), DailyRetentionError> {
        if self.version != DAILY_RETENTION_CONFIG_VERSION {
            return Err(DailyRetentionError {
                reason: "unsupported policy version",
            });
        }
        if !(1..=MAX_DAILY_RETENTION_DAYS).contains(&self.retention_days) {
            return Err(DailyRetentionError {
                reason: "invalid retention horizon",
            });
        }
        Ok(())
    }
}

/// Whether this pass had a verified effect authority. Until retention authority
/// v2 supplies an authenticated lease and per-effect receipt, production only
/// inventories input and reports this blocked state; it never opens a
/// DELETE-capable binding or mutates an archive, note, marker, or directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DailyRetentionExecution {
    /// No archive tag is beyond the configured inclusive retention boundary.
    NoExpiredArchives,
    /// Valid expired archive input or historical managed-note debt exists, but
    /// no reviewed retention-authority v2 lease is available for an effect.
    AwaitingRetentionAuthority,
}

/// Counts-only result for one read-only Daily-retention inventory pass. It
/// deliberately carries no archive tag, topic, note content, or vault path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DailyRetentionOutcome {
    pub execution: DailyRetentionExecution,
    pub policy: u16,
    pub archives_deleted: usize,
    /// Validated expired archives intentionally deferred to a later bounded
    /// batch. This is counts-only backlog telemetry, never a tag/path leak.
    pub archives_pending: usize,
    /// Exact historical Daily-note leaves that cannot be authenticated against
    /// a receipt/provenance binding by this pre-v2 read-only pass.
    pub unattested_note_debt: usize,
    pub notes_deleted: usize,
    pub note_temps_deleted: usize,
    pub daily_leaves_removed: usize,
}

impl DailyRetentionOutcome {
    #[must_use]
    pub fn changed(self) -> bool {
        self.archives_deleted != 0
            || self.notes_deleted != 0
            || self.note_temps_deleted != 0
            || self.daily_leaves_removed != 0
    }

    #[must_use]
    pub fn has_pending_archive_backfill(self) -> bool {
        self.archives_pending != 0
    }

    /// True when valid retention work is deferred until retention authority v2
    /// supplies an authenticated effect lease.
    #[must_use]
    pub fn awaiting_retention_authority(self) -> bool {
        self.execution == DailyRetentionExecution::AwaitingRetentionAuthority
    }
}

/// Content-free retention failure.  Inner filesystem/configuration errors may
/// include operator paths or note contents, so they never cross this boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DailyRetentionError {
    reason: &'static str,
}

impl std::fmt::Debug for DailyRetentionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DailyRetentionError")
            .field("reason", &self.reason)
            .finish()
    }
}

impl std::fmt::Display for DailyRetentionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "daily retention failed: {}", self.reason)
    }
}

impl std::error::Error for DailyRetentionError {}

/// The marker can be atomically visible while the parent-directory sync
/// remains unknown. That is a recovery boundary, never a completed settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DailyMarkerDurability {
    Confirmed,
    RecoveryReadRequired,
}

/// The one durable outcome of a daily settlement.  An absent or disabled
/// policy is an explicit compatible `Admitted` decision, never an unscreened
/// append path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DailySettlementOutcome {
    Admitted,
    Suppressed,
    AlreadyCompleted,
}

/// Content-free public failure for both CLI and daemon settlement callers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DailySettlementError {
    reason: &'static str,
}

impl std::fmt::Debug for DailySettlementError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DailySettlementError")
            .field("reason", &self.reason)
            .finish()
    }
}

impl std::fmt::Display for DailySettlementError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "daily admission failed: {}", self.reason)
    }
}

impl std::error::Error for DailySettlementError {}

/// One capability-bound daily archive transaction.  The same retained daily
/// directory capability and namespace binding span inspection, prior-day
/// lookup, and exclusive publication; callers never inspect one ambient
/// directory and publish into a separately rebound one.
pub(crate) struct DailyArchiveTransaction {
    home: cap_std::fs::Dir,
    reflections: cap_std::fs::Dir,
    reflections_binding: crate::skills::store::BoundDirectoryChild,
    reflections_path: PathBuf,
    daily: cap_std::fs::Dir,
    daily_binding: crate::skills::store::BoundDirectoryChild,
    daily_path: PathBuf,
}

/// One retained parent-to-child no-follow capability link. The exact parent,
/// child name, child capability, identity binding, and display path remain
/// together so a nested configured Obsidian subdirectory cannot become a
/// detached tree after an ancestor swap.
struct BoundObsidianDirectoryLink {
    parent: cap_std::fs::Dir,
    name: OsString,
    dir: cap_std::fs::Dir,
    binding: crate::skills::store::BoundDirectoryChild,
    path: PathBuf,
}

/// The visible Daily note target, retained entirely as an ordered no-follow
/// capability chain from the configured vault root through every configured
/// subdirectory component and its `Daily` leaf. Display paths exist solely for
/// reported primitive validation; no write resolves an ambient vault path.
struct BoundObsidianDailyTarget {
    chain: Vec<BoundObsidianDirectoryLink>,
}

/// Read-only capability for an existing private Daily archive. This is
/// intentionally separate from [`DailyArchiveTransaction`]: retention v1 may
/// inspect already-existing input but must not create private namespaces or
/// obtain the retained capability chain used by daily settlement.
struct ReadOnlyDailyArchive {
    daily: cap_std::fs::Dir,
    daily_path: PathBuf,
}

/// Read-only capability for an already-existing configured Obsidian Daily
/// leaf. It has no retained namespace binding and no parent handle, so it
/// cannot be upgraded into a directory-removal capability by this slice.
struct ReadOnlyObsidianDailyTarget {
    daily: cap_std::fs::Dir,
    daily_path: PathBuf,
}

/// One complete Daily archive record from the retained archive namespace.
/// Every record is kept through planning, including retained records, because
/// an Obsidian note is eligible only when it exactly renders that archive.
struct RetentionArchiveRecord {
    reflection: PeriodReflection,
    sha256: String,
    expired: bool,
}

/// A complete read-only archive inventory plus the one bounded local batch
/// selected from it. The selected vector is deterministic migration input for
/// retention authority v2; this pre-v2 planner has no archive-file deletion
/// binding and never asks the OS for a DELETE-capable archive file handle.
struct RetentionArchivePlan {
    records: BTreeMap<String, RetentionArchiveRecord>,
    selected: Vec<RetentionArchiveCandidate>,
}

/// One deterministic candidate submitted to the retention authority. Its
/// date-name and archive digest are validation facts, not delete authority;
/// only the returned signed migration lease may later select it for effects.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RetentionArchiveCandidate {
    tag: String,
    sha256: String,
}

/// Closed decoder used only by retention. `PeriodReflection` intentionally
/// stays evolution-friendly for reporting, while this direct serde decode
/// rejects both unknown and duplicate record fields before they can influence
/// a future authority candidate vector.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictDailyArchiveRecord {
    kind: String,
    tag: String,
    generated_ts_unix: i64,
    topics: Vec<String>,
    body: String,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Clone, Copy)]
enum RetentionNoteLeafKind {
    LegacyNote,
    LegacyTemp,
}

struct RetentionNotePlan {
    // Exact canonical bytes establish only legacy retention debt. The absence
    // of an authenticated archive-to-note receipt means neither a note nor a
    // historical `<YYYY-MM-DD>.md.tmp` leaf becomes a cleanup candidate here.
    unattested_expired_notes: usize,
    unattested_expired_temps: usize,
}

/// Which cadence a [`PeriodReflection`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeriodKind {
    Daily,
    Yearly,
}

impl PeriodKind {
    /// Stable lower-case discriminator (JSONL field + subfolder name).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Yearly => "yearly",
        }
    }
    /// Obsidian subfolder under `<vault>/<subdir>/` (Title-cased).
    pub fn vault_subdir(self) -> &'static str {
        match self {
            Self::Daily => "Daily",
            Self::Yearly => "Yearly",
        }
    }
    /// How many days of episodes the period summarises.
    pub fn window_days(self) -> i64 {
        match self {
            Self::Daily => 1,
            Self::Yearly => 365,
        }
    }
}

/// German one-line summary template per cadence (mirrors the weekly
/// `REFLECTION_BODY_TEMPLATE`). `{topics}` is replaced with the phrase.
fn body_template(kind: PeriodKind) -> &'static str {
    match kind {
        PeriodKind::Daily => "Heute hast du an {topics} gearbeitet.",
        PeriodKind::Yearly => "Dieses Jahr drehte sich viel um {topics}.",
    }
}

/// One archived daily/yearly reflection. Serde-stable — any new field MUST be
/// `#[serde(default)]` so historical records survive schema evolution.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PeriodReflection {
    /// `"daily"` | `"yearly"`.
    pub kind: String,
    /// `"YYYY-MM-DD"` (daily) or `"YYYY"` (yearly). The dedup discriminator.
    pub tag: String,
    pub generated_ts_unix: i64,
    pub topics: Vec<String>,
    pub body: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl PeriodReflection {
    /// Render to Obsidian markdown — YAML frontmatter + H1 + ## Body + ## Topics.
    /// Field order pinned for Dataview stability (matches WeeklyReflection).
    pub fn to_obsidian_md(&self) -> String {
        let title_kind = if self.kind == "yearly" {
            "Yearly"
        } else {
            "Daily"
        };
        let yaml_list = |key: &str, items: &[String]| -> String {
            if items.is_empty() {
                format!("{key}: []")
            } else {
                let inner = items
                    .iter()
                    .map(|t| format!("\"{}\"", escape_yaml(t)))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{key}: [{inner}]")
            }
        };
        let topics_body = if self.topics.is_empty() {
            "(no topics)\n".to_string()
        } else {
            self.topics
                .iter()
                .map(|t| format!("- {t}\n"))
                .collect::<String>()
        };
        format!(
            "---\n\
             kind: \"{kind}\"\n\
             tag: \"{tag}\"\n\
             generated_unix: {ts}\n\
             {yaml_topics}\n\
             {yaml_tags}\n\
             ---\n\n\
             # {title_kind} reflection {tag}\n\n\
             ## Body\n\n\
             {body}\n\n\
             ## Topics\n\n\
             {topics_body}",
            kind = escape_yaml(&self.kind),
            tag = escape_yaml(&self.tag),
            ts = self.generated_ts_unix,
            yaml_topics = yaml_list("topics", &self.topics),
            yaml_tags = yaml_list("tags", &self.tags),
            body = self.body,
        )
    }
}

fn escape_yaml(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// `"YYYY-MM-DD"` for a unix timestamp (UTC).
pub fn date_tag_from_unix(ts_unix: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts_unix, 0)
        .unwrap_or_else(|| chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap())
        .format("%Y-%m-%d")
        .to_string()
}

/// `"YYYY"` for a unix timestamp (UTC).
pub fn year_tag_from_unix(ts_unix: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts_unix, 0)
        .unwrap_or_else(|| chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap())
        .format("%Y")
        .to_string()
}

/// Compose a [`PeriodReflection`] from extracted topics. `None` on empty topics
/// (no vacuous note), matching `build_weekly_reflection`.
pub fn build_reflection(
    kind: PeriodKind,
    tag: &str,
    topics: &[String],
    generated_ts_unix: i64,
) -> Option<PeriodReflection> {
    if topics.is_empty() {
        return None;
    }
    let body = body_template(kind).replace("{topics}", &format_topics_phrase(topics));
    Some(PeriodReflection {
        kind: kind.as_str().to_string(),
        tag: tag.to_string(),
        generated_ts_unix,
        topics: topics.to_vec(),
        body,
        tags: Vec::new(),
    })
}

/// German "X, Y und Z" phrase (matches the weekly reflection's helper).
fn format_topics_phrase(topics: &[String]) -> String {
    match topics.len() {
        0 => String::new(),
        1 => topics[0].clone(),
        2 => format!("{} und {}", topics[0], topics[1]),
        _ => {
            let head = topics[..topics.len() - 1].join(", ");
            format!("{}, und {}", head, topics[topics.len() - 1])
        }
    }
}

/// `<home>/reflections/<kind>/`.
pub fn periodic_dir(home: &Path, kind: PeriodKind) -> PathBuf {
    home.join("reflections").join(kind.as_str())
}

/// `<home>/reflections/<kind>/<tag>.jsonl`.
pub fn jsonl_file(home: &Path, kind: PeriodKind, tag: &str) -> PathBuf {
    periodic_dir(home, kind).join(format!("{tag}.jsonl"))
}

/// Append one reflection to its per-tag JSONL (creates the dir on demand).
pub fn append(home: &Path, reflection: &PeriodReflection) -> std::io::Result<()> {
    if reflection.kind == "daily" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "daily reflection requires settlement",
        ));
    }
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    let kind = match reflection.kind.as_str() {
        "yearly" => PeriodKind::Yearly,
        // Daily returned through the transaction above; every other spelling
        // must fail rather than accidentally taking the legacy daily append.
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unsupported reflection period",
            ));
        }
    };
    fs::create_dir_all(periodic_dir(home, kind))?;
    let path = jsonl_file(home, kind, &reflection.tag);
    let mut line = serde_json::to_vec(reflection).map_err(std::io::Error::other)?;
    line.push(b'\n');
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    f.write_all(&line)?;
    f.flush()?;
    Ok(())
}

fn daily_archive_error(reason: &'static str) -> std::io::Error {
    std::io::Error::other(format!("daily admission archive {reason}"))
}

pub(crate) fn open_daily_archive_transaction(
    home: &Path,
) -> std::io::Result<DailyArchiveTransaction> {
    crate::reflection::hygiene_store::prepare_daily_admission_namespace(home)
        .map_err(std::io::Error::other)?;
    let home_dir =
        crate::skills::store::open_absolute_bound_directory(home, false, "daily admission home")
            .map_err(std::io::Error::other)?
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "daily admission home missing")
            })?;
    let reflections_path = home.join("reflections");
    let reflections = crate::skills::store::open_or_create_private_child_dir(
        &home_dir.dir,
        OsStr::new("reflections"),
        &reflections_path,
    )
    .map_err(std::io::Error::other)?;
    let (reflections, reflections_binding) = crate::skills::store::bind_retained_real_child_dir(
        &home_dir.dir,
        OsStr::new("reflections"),
        &reflections_path,
        reflections,
    )
    .map_err(std::io::Error::other)?;
    let daily_path = periodic_dir(home, PeriodKind::Daily);
    let daily = crate::skills::store::open_or_create_private_child_dir(
        &reflections,
        OsStr::new("daily"),
        &daily_path,
    )
    .map_err(std::io::Error::other)?;
    let (daily, daily_binding) = crate::skills::store::bind_retained_real_child_dir(
        &reflections,
        OsStr::new("daily"),
        &daily_path,
        daily,
    )
    .map_err(std::io::Error::other)?;
    Ok(DailyArchiveTransaction {
        home: home_dir.dir,
        reflections,
        reflections_binding,
        reflections_path,
        daily,
        daily_binding,
        daily_path,
    })
}

/// Open an optional direct directory child through a read-only, no-follow
/// capability. Retention uses this instead of the settlement mutation helper:
/// an absent child is a clean no-op, while a file, link, junction, reparse
/// point, or metadata failure is a hard refusal.
fn open_existing_read_only_child(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> std::io::Result<Option<Dir>> {
    crate::skills::store::open_real_child_dir_if_present(parent, name, display_path)
        .map_err(std::io::Error::other)
}

/// Open the existing Daily archive without preparing the admission namespace,
/// taking the admission lock, creating a directory, or binding an object for
/// DELETE. A reviewed authority v2 executor will intentionally use a separate
/// mutation-capable path after it has authenticated an effect lease.
fn open_existing_daily_retention_archive(
    home: &Path,
) -> std::io::Result<Option<ReadOnlyDailyArchive>> {
    let Some(home_dir) =
        crate::skills::store::open_absolute_bound_directory(home, false, "daily retention home")
            .map_err(std::io::Error::other)?
    else {
        return Ok(None);
    };
    let reflections_path = home.join("reflections");
    let Some(reflections) =
        open_existing_read_only_child(&home_dir.dir, OsStr::new("reflections"), &reflections_path)?
    else {
        return Ok(None);
    };
    let daily_path = periodic_dir(home, PeriodKind::Daily);
    let Some(daily) =
        open_existing_read_only_child(&reflections, OsStr::new("daily"), &daily_path)?
    else {
        return Ok(None);
    };
    Ok(Some(ReadOnlyDailyArchive { daily, daily_path }))
}

fn validate_obsidian_subdir(subdir: &str) -> std::io::Result<Vec<OsString>> {
    if subdir.is_empty() || subdir.len() > MAX_OBSIDIAN_SUBDIR_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid Obsidian subdirectory",
        ));
    }
    let path = Path::new(subdir);
    if path.is_absolute() || path.has_root() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid Obsidian subdirectory",
        ));
    }
    let components: Vec<OsString> = path
        .components()
        .map(|component| match component {
            Component::Normal(name) if name.len() <= MAX_OBSIDIAN_SUBDIR_COMPONENT_BYTES => {
                Ok(name.to_os_string())
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid Obsidian subdirectory",
            )),
        })
        .collect::<std::io::Result<_>>()?;
    if components.is_empty() || components.len() > MAX_OBSIDIAN_SUBDIR_COMPONENTS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid Obsidian subdirectory",
        ));
    }
    Ok(components)
}

impl ReadOnlyObsidianDailyTarget {
    /// Read the configured Daily leaf through an all-read-only capability
    /// chain. This does not create a vault component, retain a namespace
    /// identity for removal, or expose a parent capable of deleting `Daily`.
    fn open_existing(vault_path: &Path, subdir: &str) -> std::io::Result<Option<Self>> {
        let components = validate_obsidian_subdir(subdir)?;
        let vault_parent_path = vault_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid Obsidian vault")
            })?
            .to_path_buf();
        let vault_name = vault_path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid Obsidian vault")
            })?
            .to_os_string();
        let Some(vault_parent) = crate::skills::store::open_absolute_bound_directory(
            &vault_parent_path,
            false,
            "Obsidian vault parent",
        )
        .map_err(std::io::Error::other)?
        else {
            return Ok(None);
        };
        let Some(mut current) =
            open_existing_read_only_child(&vault_parent.dir, &vault_name, vault_path)?
        else {
            return Ok(None);
        };
        let mut current_path = vault_path.to_path_buf();
        for component in components {
            let child_path = current_path.join(&component);
            let Some(child) = open_existing_read_only_child(&current, &component, &child_path)?
            else {
                return Ok(None);
            };
            current = child;
            current_path = child_path;
        }
        let daily_name = OsString::from(PeriodKind::Daily.vault_subdir());
        let daily_path = current_path.join(&daily_name);
        let Some(daily) = open_existing_read_only_child(&current, &daily_name, &daily_path)? else {
            return Ok(None);
        };
        Ok(Some(Self { daily, daily_path }))
    }
}

impl BoundObsidianDailyTarget {
    fn open(vault_path: &Path, subdir: &str) -> std::io::Result<Self> {
        let components = validate_obsidian_subdir(subdir)?;
        let vault_parent_path = vault_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid Obsidian vault")
            })?
            .to_path_buf();
        let vault_name = vault_path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid Obsidian vault")
            })?
            .to_os_string();
        let vault_parent = crate::skills::store::open_absolute_bound_directory(
            &vault_parent_path,
            false,
            "Obsidian vault parent",
        )
        .map_err(std::io::Error::other)?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Obsidian vault parent missing",
            )
        })?;
        let (vault, vault_binding) = crate::skills::store::open_bound_real_child_dir(
            &vault_parent.dir,
            &vault_name,
            vault_path,
        )
        .map_err(std::io::Error::other)?;
        let mut chain = vec![BoundObsidianDirectoryLink {
            parent: vault_parent.dir,
            name: vault_name,
            dir: vault,
            binding: vault_binding,
            path: vault_path.to_path_buf(),
        }];
        let mut current_path = vault_path.to_path_buf();
        for component in components {
            let parent = chain
                .last()
                .expect("vault root is always the first bound target link")
                .dir
                .try_clone()?;
            let child_path = current_path.join(&component);
            let child = crate::skills::store::open_or_create_private_child_dir(
                &parent,
                &component,
                &child_path,
            )
            .map_err(std::io::Error::other)?;
            let (child, binding) = crate::skills::store::bind_retained_real_child_dir(
                &parent,
                &component,
                &child_path,
                child,
            )
            .map_err(std::io::Error::other)?;
            chain.push(BoundObsidianDirectoryLink {
                parent,
                name: component,
                dir: child,
                binding,
                path: child_path.clone(),
            });
            current_path = child_path;
        }
        let parent = chain
            .last()
            .expect("validated Obsidian subdirectory chain is nonempty")
            .dir
            .try_clone()?;
        let daily_name = OsString::from(PeriodKind::Daily.vault_subdir());
        let daily_path = current_path.join(&daily_name);
        let daily = crate::skills::store::open_or_create_private_child_dir(
            &parent,
            &daily_name,
            &daily_path,
        )
        .map_err(std::io::Error::other)?;
        let (daily, binding) = crate::skills::store::bind_retained_real_child_dir(
            &parent,
            &daily_name,
            &daily_path,
            daily,
        )
        .map_err(std::io::Error::other)?;
        chain.push(BoundObsidianDirectoryLink {
            parent,
            name: daily_name,
            dir: daily,
            binding,
            path: daily_path,
        });
        Ok(Self { chain })
    }

    fn revalidate(&self) -> std::io::Result<()> {
        for link in &self.chain {
            link.dir.dir_metadata()?;
            if !link
                .binding
                .matches_directory_child(&link.parent, &link.name, &link.path)
                .map_err(std::io::Error::other)?
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Obsidian target binding changed",
                ));
            }
        }
        Ok(())
    }

    fn write_exact(&self, expected: &PeriodReflection) -> std::io::Result<PeriodSyncOutcome> {
        self.revalidate()?;
        let name = OsString::from(format!("{}.md", expected.tag));
        let daily = self
            .chain
            .last()
            .expect("Daily leaf is always retained in an Obsidian target");
        let target_path = daily.path.join(&name);
        let body = expected.to_obsidian_md();
        self.revalidate()?;
        match crate::skills::store::atomic_write_private_child_reported(
            &daily.dir,
            &name,
            &target_path,
            body.as_bytes(),
        ) {
            Ok(crate::skills::store::PrivateChildCommit::PublishedAndSynced) => {
                self.revalidate()?
            }
            Ok(crate::skills::store::PrivateChildCommit::PublishedDurabilityUnknown(_)) => {
                return Err(std::io::Error::other("Obsidian note durability is unknown"));
            }
            Err(error) => return Err(std::io::Error::other(error)),
        }
        Ok(PeriodSyncOutcome {
            tag: expected.tag.clone(),
            written: true,
            target_path,
            reflection_count: 1,
            bytes_written: body.len(),
        })
    }
}

impl DailyArchiveTransaction {
    fn revalidate(&self) -> std::io::Result<()> {
        if !self
            .reflections_binding
            .matches_directory_child(
                &self.home,
                OsStr::new("reflections"),
                &self.reflections_path,
            )
            .map_err(std::io::Error::other)?
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "daily admission reflections binding changed",
            ));
        }
        if self
            .daily_binding
            .matches_directory_child(&self.reflections, OsStr::new("daily"), &self.daily_path)
            .map_err(std::io::Error::other)?
        {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "daily admission archive binding changed",
            ))
        }
    }

    pub(crate) fn inspect(
        &self,
        expected: &PeriodReflection,
    ) -> std::io::Result<DailyArchiveStatus> {
        self.revalidate()?;
        let path = self.daily_path.join(format!("{}.jsonl", expected.tag));
        let name = format!("{}.jsonl", expected.tag);
        let bytes = match crate::skills::store::read_regular_file_bounded(
            &self.daily,
            OsStr::new(&name),
            &path,
            MAX_DAILY_ADMISSION_ARCHIVE_BYTES,
        ) {
            Ok(bytes) => bytes,
            Err(error)
                if error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(DailyArchiveStatus::Missing);
            }
            Err(error) => return Err(std::io::Error::other(error)),
        };
        parse_expected_daily_archive(&bytes, expected)
    }

    pub(crate) fn load_previous(&self, tag: &str) -> std::io::Result<Option<PeriodReflection>> {
        self.load_record(tag)
            .map(|record| record.map(|(reflection, _)| reflection))
    }

    /// Read exactly one current-tag record from the retained Daily directory
    /// and return a SHA-256 digest of the exact validated bytes. Same-tag
    /// recovery must use this durable record, never a newly rebuilt candidate.
    fn load_record(&self, tag: &str) -> std::io::Result<Option<(PeriodReflection, String)>> {
        self.revalidate()?;
        let name = format!("{tag}.jsonl");
        let path = self.daily_path.join(&name);
        let bytes = match crate::skills::store::read_regular_file_bounded(
            &self.daily,
            OsStr::new(&name),
            &path,
            MAX_DAILY_ADMISSION_ARCHIVE_BYTES,
        ) {
            Ok(bytes) => bytes,
            Err(error)
                if error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(std::io::Error::other(error)),
        };
        if !bytes.ends_with(b"\n") || bytes.iter().filter(|byte| **byte == b'\n').count() != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "daily archive has invalid record framing",
            ));
        }
        let reflection: PeriodReflection = serde_json::from_slice(&bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "daily archive contains malformed record",
            )
        })?;
        if reflection.kind != "daily" || reflection.tag != tag {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "daily archive conflicts with requested tag",
            ));
        }
        let digest = hex::encode(Sha256::digest(&bytes));
        Ok(Some((reflection, digest)))
    }

    fn marker_path(&self) -> PathBuf {
        self.reflections_path.join("daily-last.txt")
    }

    fn marker_matches_exact(&self, tag: &str) -> std::io::Result<bool> {
        self.revalidate()?;
        let path = self.marker_path();
        let bytes = match crate::skills::store::read_regular_file_bounded(
            &self.reflections,
            OsStr::new("daily-last.txt"),
            &path,
            MAX_DAILY_ADMISSION_MARKER_BYTES,
        ) {
            Ok(bytes) => bytes,
            Err(error)
                if error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(std::io::Error::other(error)),
        };
        Ok(bytes == tag.as_bytes())
    }

    fn publish_marker(
        &self,
        expected: &PeriodReflection,
        outcome: DailySettlementOutcome,
    ) -> std::io::Result<DailyMarkerDurability> {
        self.verify_settlement(expected, outcome)?;
        // Final retained-capability checks before the marker is published.
        self.revalidate()?;
        match crate::skills::store::atomic_write_private_child_reported(
            &self.reflections,
            OsStr::new("daily-last.txt"),
            &self.marker_path(),
            expected.tag.as_bytes(),
        ) {
            Ok(crate::skills::store::PrivateChildCommit::PublishedAndSynced) => {
                self.revalidate()?;
                Ok(DailyMarkerDurability::Confirmed)
            }
            Ok(crate::skills::store::PrivateChildCommit::PublishedDurabilityUnknown(_)) => {
                Ok(DailyMarkerDurability::RecoveryReadRequired)
            }
            Err(error) => Err(std::io::Error::other(error)),
        }
    }

    pub(crate) fn append_once(
        &self,
        expected: &PeriodReflection,
    ) -> std::io::Result<DailyArchiveStatus> {
        match self.inspect(expected)? {
            DailyArchiveStatus::Matching => return Ok(DailyArchiveStatus::Matching),
            DailyArchiveStatus::Missing => {}
        }
        self.revalidate()?;
        let path = self.daily_path.join(format!("{}.jsonl", expected.tag));
        let mut line = serde_json::to_vec(expected).map_err(std::io::Error::other)?;
        line.push(b'\n');
        let name = format!("{}.jsonl", expected.tag);
        match crate::skills::store::atomic_write_private_child_create_new_reported(
            &self.daily,
            OsStr::new(&name),
            &path,
            &line,
        ) {
            Ok(crate::skills::store::PrivateChildCommit::PublishedAndSynced) => {
                self.revalidate()?;
                Ok(DailyArchiveStatus::Matching)
            }
            Ok(crate::skills::store::PrivateChildCommit::PublishedDurabilityUnknown(error)) => {
                Err(std::io::Error::other(error))
            }
            Err(error)
                if error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists) =>
            {
                self.inspect(expected)
            }
            Err(error) => Err(std::io::Error::other(error)),
        }
    }

    fn verify_settlement(
        &self,
        expected: &PeriodReflection,
        outcome: DailySettlementOutcome,
    ) -> std::io::Result<()> {
        match (outcome, self.inspect(expected)?) {
            (DailySettlementOutcome::Admitted, DailyArchiveStatus::Matching)
            | (DailySettlementOutcome::Suppressed, DailyArchiveStatus::Missing) => Ok(()),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "daily admission settlement conflicts with archive",
            )),
        }
    }

    fn sync_expected_to_obsidian(
        &self,
        vault_root: &Path,
        subdir: &str,
        expected: &PeriodReflection,
    ) -> std::io::Result<BoundObsidianDailyTarget> {
        // Do not reload ambient JSONL. The exact validated expected record is
        // the only permitted content for a settlement-side visible note.
        self.verify_settlement(expected, DailySettlementOutcome::Admitted)?;
        let target = BoundObsidianDailyTarget::open(vault_root, subdir)?;
        // Revalidate the retained daily capability and exact archive bytes as
        // the final check immediately before the visible side effect.
        self.verify_settlement(expected, DailySettlementOutcome::Admitted)?;
        target.write_exact(expected)?;
        Ok(target)
    }
}

/// Settle the entire Daily archive/state/visible-note/marker transaction.
/// This is synchronous by design and is the sole production entry point for
/// the daemon and `reflect digest --daily`.
pub fn settle_daily_admission(
    home: &Path,
    expected: &PeriodReflection,
    config: Option<&crate::reflection::hygiene::DailyAdmissionConfig>,
    obsidian: Option<(&Path, &str)>,
) -> Result<DailySettlementOutcome, DailySettlementError> {
    use crate::reflection::hygiene::{DailyAdmissionDecision, decide_daily_admission};
    use crate::reflection::hygiene_store::{
        DailyAdmissionOutcome, HygieneDurability, lock_daily_admission,
    };

    if expected.kind != "daily" {
        return Err(DailySettlementError {
            reason: "invalid daily reflection",
        });
    }
    // Acquire process + OS admission before opening the retained archive
    // transaction. That keeps the full archive/state/note/marker settlement
    // serial with the future authority v2 scan-plan-cleanup executor.
    let gate = lock_daily_admission(home).map_err(|_| DailySettlementError {
        reason: "gate unavailable",
    })?;
    let archive = open_daily_archive_transaction(home).map_err(|_| DailySettlementError {
        reason: "archive unavailable",
    })?;
    let existing = gate.load().map_err(|_| DailySettlementError {
        reason: "state unavailable",
    })?;
    let revision = existing.as_ref().map_or(0, |state| state.revision);
    // Archive-first recovery is intentionally before policy evaluation. A
    // state write can fail after an archive publish; that exact bounded record
    // is the only authority for the retry, even if today's candidate changed.
    let current_archive = archive
        .load_record(&expected.tag)
        .map_err(|_| DailySettlementError {
            reason: "current archive recovery failed",
        })?;

    let (outcome, settled) = if let Some(state) =
        existing.as_ref().filter(|state| state.tag == expected.tag)
    {
        match state.outcome {
            DailyAdmissionOutcome::Admitted => {
                let (persisted, sha256) = current_archive.clone().ok_or(DailySettlementError {
                    reason: "admitted archive is missing",
                })?;
                if state.archive_sha256.as_deref() != Some(sha256.as_str()) {
                    return Err(DailySettlementError {
                        reason: "admitted archive digest conflicts with state",
                    });
                }
                (DailySettlementOutcome::Admitted, persisted)
            }
            DailyAdmissionOutcome::Suppressed => {
                archive
                    .verify_settlement(expected, DailySettlementOutcome::Suppressed)
                    .map_err(|_| DailySettlementError {
                        reason: "suppression conflicts with archive",
                    })?;
                (DailySettlementOutcome::Suppressed, expected.clone())
            }
        }
    } else if let Some((persisted, sha256)) = current_archive {
        match gate
            .compare_and_set(
                revision,
                &expected.tag,
                DailyAdmissionOutcome::Admitted,
                Some(&sha256),
            )
            .map_err(|_| DailySettlementError {
                reason: "recovered state compare-and-set failed",
            })? {
            HygieneDurability::Confirmed => {}
            HygieneDurability::RecoveryReadRequired => {
                return Err(DailySettlementError {
                    reason: "state durability is unknown; recovery required",
                });
            }
        }
        (DailySettlementOutcome::Admitted, persisted)
    } else {
        let outcome = if config.is_none_or(|policy| !policy.enabled) {
            DailySettlementOutcome::Admitted
        } else {
            let config = config.expect("enabled policy was checked above");
            let previous_tag =
                date_tag_from_unix(expected.generated_ts_unix.saturating_sub(86_400));
            let previous_topics = archive
                .load_previous(&previous_tag)
                .map_err(|_| DailySettlementError {
                    reason: "previous archive inspection failed",
                })?
                .map(|item| item.topics)
                .unwrap_or_default();
            match decide_daily_admission(&expected.topics, &previous_topics, config).map_err(
                |_| DailySettlementError {
                    reason: "policy invalid",
                },
            )? {
                DailyAdmissionDecision::Admit { .. } => DailySettlementOutcome::Admitted,
                DailyAdmissionDecision::Suppress { .. } => DailySettlementOutcome::Suppressed,
            }
        };
        let (settled, sha256) = if outcome == DailySettlementOutcome::Admitted {
            archive
                .append_once(expected)
                .map_err(|_| DailySettlementError {
                    reason: "archive append failed",
                })?;
            let (persisted, sha256) = archive
                .load_record(&expected.tag)
                .map_err(|_| DailySettlementError {
                    reason: "admitted archive digest read failed",
                })?
                .ok_or(DailySettlementError {
                    reason: "admitted archive is missing",
                })?;
            if persisted != *expected {
                return Err(DailySettlementError {
                    reason: "admitted archive conflicts with candidate",
                });
            }
            (persisted, Some(sha256))
        } else {
            (expected.clone(), None)
        };
        let persisted = match outcome {
            DailySettlementOutcome::Admitted => DailyAdmissionOutcome::Admitted,
            DailySettlementOutcome::Suppressed => DailyAdmissionOutcome::Suppressed,
            DailySettlementOutcome::AlreadyCompleted => {
                return Err(DailySettlementError {
                    reason: "invalid completed state transition",
                });
            }
        };
        match gate
            .compare_and_set(revision, &expected.tag, persisted, sha256.as_deref())
            .map_err(|_| DailySettlementError {
                reason: "state compare-and-set failed",
            })? {
            HygieneDurability::Confirmed => {}
            HygieneDurability::RecoveryReadRequired => {
                return Err(DailySettlementError {
                    reason: "state durability is unknown; recovery required",
                });
            }
        }
        (outcome, settled)
    };

    // A marker is completion evidence only after the state/archive decision
    // above has been freshly verified through the retained capabilities. Do
    // not rewrite an already completed note or marker on ordinary intervals.
    if archive
        .marker_matches_exact(&settled.tag)
        .map_err(|_| DailySettlementError {
            reason: "marker inspection failed",
        })?
    {
        return Ok(DailySettlementOutcome::AlreadyCompleted);
    }

    let obsidian_target = if outcome == DailySettlementOutcome::Admitted {
        if let Some((vault, subdir)) = obsidian {
            Some(
                archive
                    .sync_expected_to_obsidian(vault, subdir, &settled)
                    .map_err(|_| DailySettlementError {
                        reason: "Obsidian sync failed",
                    })?,
            )
        } else {
            None
        }
    } else {
        None
    };
    // Marker is deliberately last, after the exact expected archive is
    // revalidated again and after the optional visible note has converged.
    if let Some(target) = obsidian_target.as_ref() {
        target.revalidate().map_err(|_| DailySettlementError {
            reason: "Obsidian binding changed before marker",
        })?;
    }
    match archive
        .publish_marker(&settled, outcome)
        .map_err(|_| DailySettlementError {
            reason: "settlement verification failed",
        })? {
        DailyMarkerDurability::Confirmed => {}
        DailyMarkerDurability::RecoveryReadRequired => {
            return Err(DailySettlementError {
                reason: "marker durability is unknown; recovery required",
            });
        }
    }
    Ok(outcome)
}

fn parse_expected_daily_archive(
    bytes: &[u8],
    expected: &PeriodReflection,
) -> std::io::Result<DailyArchiveStatus> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "daily archive is not UTF-8",
        )
    })?;
    let mut count = 0usize;
    for line in text.lines() {
        count += 1;
        if count > MAX_DAILY_ADMISSION_ARCHIVE_LINES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "daily archive has too many records",
            ));
        }
        let actual: PeriodReflection = serde_json::from_str(line).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "daily archive contains malformed record",
            )
        })?;
        if actual.kind != "daily" || actual.tag != expected.tag || actual != *expected {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "daily archive conflicts with admission candidate",
            ));
        }
    }
    if count != 1 || !bytes.ends_with(b"\n") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "daily archive has invalid record framing",
        ));
    }
    Ok(DailyArchiveStatus::Matching)
}

/// Parse one exact Daily JSONL leaf. Retention treats this as a closed record
/// schema instead of accepting arbitrary or duplicate fields silently: such
/// archive input is a safety stop, not a cleanup decision.
fn parse_daily_archive_record(bytes: &[u8], tag: &str) -> std::io::Result<PeriodReflection> {
    if !bytes.ends_with(b"\n") || bytes.iter().filter(|byte| **byte == b'\n').count() != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "daily archive has invalid record framing",
        ));
    }
    let record: StrictDailyArchiveRecord = serde_json::from_slice(bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "daily archive contains malformed record",
        )
    })?;
    let reflection = PeriodReflection {
        kind: record.kind,
        tag: record.tag,
        generated_ts_unix: record.generated_ts_unix,
        topics: record.topics,
        body: record.body,
        tags: record.tags,
    };
    if reflection.kind != "daily" || reflection.tag != tag {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "daily archive conflicts with requested tag",
        ));
    }
    Ok(reflection)
}

fn daily_retention_tags(
    now_unix: i64,
    policy: &DailyRetentionConfig,
) -> std::io::Result<(String, String)> {
    // The returned boundary is inclusive for expiration. With a 90-day
    // policy, this retains the current UTC date plus exactly 89 prior date
    // tags; the date at `now - 90 days` and every older tag are expired.
    let expired_through_unix = now_unix
        .checked_sub(i64::from(policy.retention_days).saturating_mul(86_400))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "daily retention clock is invalid",
            )
        })?;
    let current =
        chrono::DateTime::<chrono::Utc>::from_timestamp(now_unix, 0).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "daily retention clock is invalid",
            )
        })?;
    let expired_through = chrono::DateTime::<chrono::Utc>::from_timestamp(expired_through_unix, 0)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "daily retention clock is invalid",
            )
        })?;
    let current_tag = current.format("%Y-%m-%d").to_string();
    let expired_through_tag = expired_through.format("%Y-%m-%d").to_string();
    if !is_exact_daily_tag(&current_tag) || !is_exact_daily_tag(&expired_through_tag) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "daily retention clock is outside the supported date range",
        ));
    }
    Ok((current_tag, expired_through_tag))
}

fn is_exact_daily_tag(tag: &str) -> bool {
    if tag.len() != 10
        || tag.as_bytes()[4] != b'-'
        || tag.as_bytes()[7] != b'-'
        || !tag
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
        || tag.starts_with("0000")
    {
        return false;
    }
    chrono::NaiveDate::parse_from_str(tag, "%Y-%m-%d")
        .map(|date| date.format("%Y-%m-%d").to_string() == tag)
        .unwrap_or(false)
}

/// Produce the exact oldest-first candidate vector offered to the retention
/// authority. A resumed batch is strictly *after* the prior terminal
/// candidate, never merely at-or-after its start tag, so a crash/retry cannot
/// replay a previously terminalized archive. The caller must have already
/// capability-validated every candidate's leaf and digest.
fn select_deterministic_retention_batch(
    mut candidates: Vec<RetentionArchiveCandidate>,
    after_tag: Option<&str>,
    batch_limit: usize,
) -> std::io::Result<Vec<RetentionArchiveCandidate>> {
    if !(1..=MAX_DAILY_RETENTION_BATCH_ENTRIES).contains(&batch_limit) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "daily retention batch limit is invalid",
        ));
    }
    if let Some(after_tag) = after_tag
        && !is_exact_daily_tag(after_tag)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "daily retention batch cursor is invalid",
        ));
    }
    candidates.sort_by(|left, right| left.tag.cmp(&right.tag));
    let mut previous = None::<&str>;
    for candidate in &candidates {
        if !is_exact_daily_tag(&candidate.tag)
            || candidate.sha256.len() != 64
            || !candidate
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "daily retention candidate is invalid",
            ));
        }
        if previous.is_some_and(|previous| previous >= candidate.tag.as_str()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "daily retention candidates are not unique",
            ));
        }
        previous = Some(candidate.tag.as_str());
    }
    Ok(candidates
        .into_iter()
        .filter(|candidate| after_tag.is_none_or(|after_tag| candidate.tag.as_str() > after_tag))
        .take(batch_limit)
        .collect())
}

const BOUND_DELETE_TOMBSTONE_PREFIX: &str = ".neoth-bound-delete-";

/// Match only the exact Unix `BoundChildObject::remove_bound_file` tombstone
/// shape. Recognition is a blocked-recovery diagnosis, not provenance: an
/// attacker can create the same name, and no pre-v2 path may unlink, rename,
/// restore, or otherwise act on it without a signed pending-effect receipt.
fn is_pending_bound_delete_tombstone(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(uuid) = name.strip_prefix(BOUND_DELETE_TOMBSTONE_PREFIX) else {
        return false;
    };
    uuid.len() == 32
        && uuid
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// A crash between a capability-bound rename and unlink leaves an exact
/// tombstone. The durable identity/receipt that could prove it belongs to a
/// particular effect is unavailable in this slice, so stop explicitly rather
/// than treating the tombstone as an unknown leaf forever or guessing cleanup.
fn has_pending_retention_effect_tombstone(archive: &ReadOnlyDailyArchive) -> std::io::Result<bool> {
    Ok(
        bounded_retention_child_names(&archive.daily, MAX_DAILY_RETENTION_ENTRIES)?
            .iter()
            .any(|name| is_pending_bound_delete_tombstone(name)),
    )
}

fn archive_tag_from_retention_leaf(name: &OsStr) -> std::io::Result<String> {
    let name = name.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "daily retention archive leaf is not UTF-8",
        )
    })?;
    let tag = name.strip_suffix(".jsonl").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "daily retention archive leaf is unknown",
        )
    })?;
    if !is_exact_daily_tag(tag) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "daily retention archive leaf has an invalid tag",
        ));
    }
    Ok(tag.to_string())
}

fn note_leaf_from_retention_name(name: &OsStr) -> std::io::Result<(String, RetentionNoteLeafKind)> {
    let name = name.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "daily retention note leaf is not UTF-8",
        )
    })?;
    if let Some(tag) = name.strip_suffix(".md")
        && is_exact_daily_tag(tag)
    {
        return Ok((tag.to_string(), RetentionNoteLeafKind::LegacyNote));
    }
    // The earliest target-derived write path left exactly
    // `<YYYY-MM-DD>.md.tmp`. It is recognized only to retain it as explicit
    // debt after its bytes are compared below; the name and canonical bytes do
    // not prove a receipt/provenance binding and therefore never authorize a
    // deletion on their own.
    if let Some(tag) = name.strip_suffix(".md.tmp")
        && is_exact_daily_tag(tag)
    {
        return Ok((tag.to_string(), RetentionNoteLeafKind::LegacyTemp));
    }
    // Only accept the old target-derived atomic-write names. Generic private
    // stages (for example `.neoth-atomic-*`) do not encode a date target and
    // are intentionally unknown rather than being guessed into deletion.
    let valid_temp = name.len() > 18
        && name.is_char_boundary(10)
        && name.is_char_boundary(14)
        && name.ends_with(".tmp")
        && &name.as_bytes()[10..14] == b".md."
        && is_exact_daily_tag(&name[..10]);
    if valid_temp {
        let nonce = &name[14..name.len() - 4];
        let decimal = !nonce.is_empty() && nonce.bytes().all(|byte| byte.is_ascii_digit());
        let windows_nonce = nonce.len() == 32
            && nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
        if decimal || windows_nonce {
            return Ok((name[..10].to_string(), RetentionNoteLeafKind::LegacyTemp));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "daily retention note leaf is unknown",
    ))
}

fn bounded_retention_child_names(parent: &Dir, limit: usize) -> std::io::Result<Vec<OsString>> {
    let entries = parent.entries()?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry?;
        if names.len() == limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "daily retention inventory exceeds its entry limit",
            ));
        }
        names.push(entry.file_name());
    }
    names.sort();
    Ok(names)
}

fn charge_retention_bytes(total: &mut usize, added: usize) -> std::io::Result<()> {
    *total = total.checked_add(added).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "daily retention inventory exceeds its byte limit",
        )
    })?;
    if *total > MAX_DAILY_RETENTION_TOTAL_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "daily retention inventory exceeds its byte limit",
        ));
    }
    Ok(())
}

/// Read one direct retention leaf through a no-follow capability without
/// acquiring deletion authority. Inventory (including legacy note debt) must
/// remain read-only until reviewed retention authority v2 supplies an
/// authenticated effect lease and receipt.
fn read_retention_file(
    parent: &Dir,
    name: &OsStr,
    path: &Path,
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    crate::skills::store::read_regular_file_bounded(parent, name, path, max_bytes)
        .map_err(std::io::Error::other)
}

fn plan_daily_archive_retention(
    archive: &ReadOnlyDailyArchive,
    current_tag: &str,
    expired_through_tag: &str,
    total_bytes: &mut usize,
) -> std::io::Result<RetentionArchivePlan> {
    let mut records = BTreeMap::new();
    for name in bounded_retention_child_names(&archive.daily, MAX_DAILY_RETENTION_ENTRIES)? {
        let tag = archive_tag_from_retention_leaf(&name)?;
        if tag.as_str() > current_tag {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "daily retention archive contains a future tag",
            ));
        }
        let path = archive.daily_path.join(&name);
        let bytes = read_retention_file(
            &archive.daily,
            &name,
            &path,
            MAX_DAILY_ADMISSION_ARCHIVE_BYTES,
        )?;
        charge_retention_bytes(total_bytes, bytes.len())?;
        let reflection = parse_daily_archive_record(&bytes, &tag)?;
        let expired = tag.as_str() <= expired_through_tag;
        let sha256 = hex::encode(Sha256::digest(&bytes));
        let record = RetentionArchiveRecord {
            reflection,
            sha256,
            expired,
        };
        if records.insert(tag, record).is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "daily retention archive has duplicate tags",
            ));
        }
    }
    // The filesystem is an unordered namespace. Derive a deterministic
    // oldest-first vector only after every bounded direct child was parsed;
    // a later authority-backed pass will sign precisely this vector rather
    // than acting on `Dir::entries()` order. This executor intentionally does
    // not bind any deletion handle while constructing the inventory.
    let candidates = records
        .iter()
        .filter(|(_, record)| record.expired)
        .map(|(tag, record)| RetentionArchiveCandidate {
            tag: tag.clone(),
            sha256: record.sha256.clone(),
        })
        .collect();
    let selected =
        select_deterministic_retention_batch(candidates, None, MAX_DAILY_RETENTION_BATCH_ENTRIES)?;
    Ok(RetentionArchivePlan { records, selected })
}

fn plan_managed_daily_note_retention(
    target: &ReadOnlyObsidianDailyTarget,
    archives: &BTreeMap<String, RetentionArchiveRecord>,
    total_bytes: &mut usize,
) -> std::io::Result<RetentionNotePlan> {
    let mut plan = RetentionNotePlan {
        unattested_expired_notes: 0,
        unattested_expired_temps: 0,
    };
    for name in bounded_retention_child_names(&target.daily, MAX_DAILY_RETENTION_ENTRIES)? {
        let (tag, kind) = note_leaf_from_retention_name(&name)?;
        let record = archives.get(&tag).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "daily retention note has no matching archive",
            )
        })?;
        let path = target.daily_path.join(&name);
        let bytes =
            read_retention_file(&target.daily, &name, &path, MAX_DAILY_RETENTION_NOTE_BYTES)?;
        charge_retention_bytes(total_bytes, bytes.len())?;
        if bytes != record.reflection.to_obsidian_md().as_bytes() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "daily retention note is not an exact managed rendering",
            ));
        }
        if record.expired {
            match kind {
                RetentionNoteLeafKind::LegacyNote => {
                    plan.unattested_expired_notes = plan.unattested_expired_notes.saturating_add(1);
                }
                RetentionNoteLeafKind::LegacyTemp => {
                    plan.unattested_expired_temps = plan.unattested_expired_temps.saturating_add(1);
                }
            }
        }
    }
    Ok(plan)
}

/// Count exact historical Daily note/temp leaves when their archive history is
/// absent. Without the canonical archive bytes there is no provenance proof,
/// so each bounded regular leaf remains explicit authority migration debt.
fn count_unattested_daily_note_debt_without_archive(
    target: &ReadOnlyObsidianDailyTarget,
    total_bytes: &mut usize,
) -> std::io::Result<usize> {
    let mut debt = 0usize;
    for name in bounded_retention_child_names(&target.daily, MAX_DAILY_RETENTION_ENTRIES)? {
        let _ = note_leaf_from_retention_name(&name)?;
        let path = target.daily_path.join(&name);
        let bytes =
            read_retention_file(&target.daily, &name, &path, MAX_DAILY_RETENTION_NOTE_BYTES)?;
        charge_retention_bytes(total_bytes, bytes.len())?;
        debt = debt.saturating_add(1);
    }
    Ok(debt)
}

/// Inventory the configured physical Daily-retention policy boundary without
/// taking an effect capability. This deliberately stops before the admission guard,
/// any DELETE binding, any namespace mutation, or an empty-Daily removal: those
/// operations require the reviewed retention-authority v2 lease/receipt state
/// machine. The deterministic candidate vector remains private integration
/// input for that future executor, never an unsigned delete plan. It makes no
/// liveness or trusted-clock safety claim before the authority is integrated.
pub fn enforce_daily_retention(
    home: &Path,
    now_unix: i64,
    policy: &DailyRetentionConfig,
    obsidian: Option<(&Path, &str)>,
) -> Result<DailyRetentionOutcome, DailyRetentionError> {
    policy.validate()?;
    let (current_tag, expired_through_tag) =
        daily_retention_tags(now_unix, policy).map_err(|_| DailyRetentionError {
            reason: "clock unavailable",
        })?;
    let note_target = match obsidian {
        Some((vault, subdir)) => ReadOnlyObsidianDailyTarget::open_existing(vault, subdir)
            .map_err(|_| DailyRetentionError {
                reason: "managed note target is unavailable",
            })?,
        None => None,
    };
    let mut total_bytes = 0usize;
    let Some(archive) =
        open_existing_daily_retention_archive(home).map_err(|_| DailyRetentionError {
            reason: "archive inventory is invalid",
        })?
    else {
        let unattested_note_debt = note_target
            .as_ref()
            .map(|target| {
                count_unattested_daily_note_debt_without_archive(target, &mut total_bytes)
            })
            .transpose()
            .map_err(|_| DailyRetentionError {
                reason: "managed note inventory is invalid",
            })?
            .unwrap_or(0);
        return Ok(DailyRetentionOutcome {
            execution: if unattested_note_debt == 0 {
                DailyRetentionExecution::NoExpiredArchives
            } else {
                DailyRetentionExecution::AwaitingRetentionAuthority
            },
            policy: policy.retention_days,
            archives_deleted: 0,
            archives_pending: 0,
            unattested_note_debt,
            notes_deleted: 0,
            note_temps_deleted: 0,
            daily_leaves_removed: 0,
        });
    };
    if has_pending_retention_effect_tombstone(&archive).map_err(|_| DailyRetentionError {
        reason: "archive inventory is invalid",
    })? {
        // This is deliberately an explicit blocked recovery condition instead
        // of an unsigned unlink attempt. Retention authority v2 must bind the
        // tombstone identity to its original signed effect/terminal receipt.
        return Err(DailyRetentionError {
            reason: "retention pending-effect recovery required",
        });
    }
    let RetentionArchivePlan {
        records: archives,
        selected,
    } = plan_daily_archive_retention(
        &archive,
        &current_tag,
        &expired_through_tag,
        &mut total_bytes,
    )
    .map_err(|_| DailyRetentionError {
        reason: "archive inventory is invalid",
    })?;

    let note_plan = if let Some(target) = note_target.as_ref() {
        plan_managed_daily_note_retention(target, &archives, &mut total_bytes).map_err(|_| {
            DailyRetentionError {
                reason: "managed note inventory is invalid",
            }
        })?
    } else {
        RetentionNotePlan {
            unattested_expired_notes: 0,
            unattested_expired_temps: 0,
        }
    };

    let archives_pending = archives.values().filter(|record| record.expired).count();
    let unattested_note_debt = note_plan
        .unattested_expired_notes
        .saturating_add(note_plan.unattested_expired_temps);
    // A legacy exact rendering or target-derived `.tmp` name is diagnosed
    // retention debt, never an implied cleanup permit.  Surface it as
    // authority-blocked so an intact input set is not misreported as meeting
    // the configured ceiling before v2 has authenticated an effect lease.
    let execution = if selected.is_empty() && unattested_note_debt == 0 {
        DailyRetentionExecution::NoExpiredArchives
    } else {
        DailyRetentionExecution::AwaitingRetentionAuthority
    };
    Ok(DailyRetentionOutcome {
        execution,
        policy: policy.retention_days,
        archives_deleted: 0,
        archives_pending,
        unattested_note_debt,
        notes_deleted: 0,
        note_temps_deleted: 0,
        daily_leaves_removed: 0,
    })
}

/// Inspect the exact daily archive without accepting partial or ambiguous
/// history.  The caller supplies the one expected record; a matching prior
/// append is recovery evidence, while malformed input or a different same-tag
/// record is a hard stop that leaves the original bytes untouched.
pub fn inspect_daily_archive(
    home: &Path,
    expected: &PeriodReflection,
) -> std::io::Result<DailyArchiveStatus> {
    open_daily_archive_transaction(home)
        .and_then(|archive| archive.inspect(expected))
        .map_err(|_| daily_archive_error("inspection failed"))
}

/// Strict bounded read of the one prior daily record used by the admission
/// comparison.  Unlike the historical best-effort loader, corruption is not
/// silently interpreted as an empty previous topic set.
pub fn load_daily_archive_for_admission(
    home: &Path,
    tag: &str,
) -> std::io::Result<Option<PeriodReflection>> {
    open_daily_archive_transaction(home)
        .and_then(|archive| archive.load_previous(tag))
        .map_err(|_| daily_archive_error("prior-record inspection failed"))
}

/// Archive once with a read-before-append recovery edge.  Durability of the
/// append is acknowledged only after `sync_all`; callers still keep the marker
/// last and use `inspect_daily_archive` after crashes.
#[cfg(test)]
pub(crate) fn append_daily_admission_once(
    home: &Path,
    expected: &PeriodReflection,
) -> std::io::Result<DailyArchiveStatus> {
    open_daily_archive_transaction(home)
        .and_then(|archive| archive.append_once(expected))
        .map_err(|_| daily_archive_error("publication failed"))
}

/// Strict bounded Daily read for reporting. Generic reporting loaders may not
/// bypass the Daily transaction's no-follow framing and duplicate checks.
pub fn load_daily_archive_for_reporting(
    home: &Path,
    tag: &str,
) -> std::io::Result<Option<PeriodReflection>> {
    open_daily_archive_transaction(home)
        .and_then(|archive| {
            archive
                .load_record(tag)
                .map(|record| record.map(|(item, _)| item))
        })
        .map_err(|_| daily_archive_error("reporting inspection failed"))
}

/// Load non-Daily reflection records for legacy/reporting consumers. Daily is
/// deliberately refused because it must remain strict, bounded and
/// capability-relative through [`load_daily_archive_for_reporting`].
pub fn load_for_tag(
    home: &Path,
    kind: PeriodKind,
    tag: &str,
) -> std::io::Result<Vec<PeriodReflection>> {
    if kind == PeriodKind::Daily {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "daily reporting requires strict archive reader",
        ));
    }
    let body = match std::fs::read_to_string(jsonl_file(home, kind, tag)) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    Ok(body
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect())
}

/// Outcome of [`sync_to_obsidian`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeriodSyncOutcome {
    pub tag: String,
    pub written: bool,
    pub target_path: PathBuf,
    pub reflection_count: usize,
    pub bytes_written: usize,
}

/// Render every reflection for `tag` into one Obsidian note at
/// `<vault>/<subdir>/<Daily|Yearly>/<tag>.md` (atomic `.tmp` + rename). Empty →
/// `written: false`, no file (keeps the vault clean for quiet days/years).
pub fn sync_to_obsidian(
    neoth_home: &Path,
    vault_root: &Path,
    subdir: &str,
    kind: PeriodKind,
    tag: &str,
) -> std::io::Result<PeriodSyncOutcome> {
    if kind == PeriodKind::Daily {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "daily Obsidian sync requires settlement",
        ));
    }
    let reflections = load_for_tag(neoth_home, kind, tag)?;
    let dest_dir = vault_root.join(subdir).join(kind.vault_subdir());
    let target_path = dest_dir.join(format!("{tag}.md"));

    if reflections.is_empty() {
        return Ok(PeriodSyncOutcome {
            tag: tag.to_string(),
            written: false,
            target_path,
            reflection_count: 0,
            bytes_written: 0,
        });
    }

    let body: String = reflections
        .iter()
        .map(PeriodReflection::to_obsidian_md)
        .collect::<Vec<_>>()
        .join("\n---\n\n");

    // Canonical crash-safe write: temp + fsync + atomic rename-replace (std
    // rename is atomic-replace on Windows too — no remove-then-rename gap, which
    // is the bug the hand-rolled pattern had). Creates the parent dir.
    crate::util::atomic_write::atomic_write(&target_path, body.as_bytes())?;

    Ok(PeriodSyncOutcome {
        tag: tag.to_string(),
        written: true,
        target_path,
        reflection_count: reflections.len(),
        bytes_written: body.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(unix, windows))]
    use tempfile::TempDir as RawTempDir;

    /// The admission boundary intentionally rejects ambient 0755 temporary
    /// directories. Keep every test home representative of a real private
    /// NEOTH_HOME without weakening that production guard.
    struct TempDir {
        _root: crate::test_env::CanonicalTempDir,
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> std::io::Result<Self> {
            let root = crate::test_env::canonical_tempdir()?;
            #[cfg(unix)]
            let path = {
                use std::os::unix::fs::DirBuilderExt as _;

                let path = root.path().join("private-home");
                std::fs::DirBuilder::new().mode(0o700).create(&path)?;
                path
            };
            #[cfg(windows)]
            let path = {
                let path = root.path().join("private-home");
                crate::wal::win_native::create_private_directory_new(&path)?;
                path
            };
            #[cfg(not(any(unix, windows)))]
            let path = root.path().to_path_buf();
            Ok(Self { _root: root, path })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    /// Build a direct, exact JSONL archive fixture without exercising the
    /// admission/state writer once per historical date. Retention itself still
    /// scans the real bounded filesystem namespace through its read-only path.
    fn write_daily_retention_archive_fixture(
        home: &std::path::Path,
        reflection: &PeriodReflection,
    ) -> Vec<u8> {
        let path = jsonl_file(home, PeriodKind::Daily, &reflection.tag);
        let mut bytes = serde_json::to_vec(reflection).unwrap();
        bytes.push(b'\n');
        std::fs::write(path, &bytes).unwrap();
        bytes
    }

    /// Hash the exact bounded archive namespace through the same no-follow
    /// read-only inventory primitives production retention uses. This proves a
    /// deferred pass neither changes an unrepresented historical leaf nor only
    /// preserves the handful of representative files asserted below.
    fn daily_retention_archive_manifest(home: &std::path::Path) -> (usize, Vec<u8>) {
        let archive = open_existing_daily_retention_archive(home)
            .unwrap()
            .expect("fixture Daily archive exists");
        let names = bounded_retention_child_names(&archive.daily, MAX_DAILY_RETENTION_ENTRIES)
            .expect("bounded fixture archive inventory");
        let mut digest = Sha256::new();
        for name in &names {
            let path = archive.daily_path.join(name);
            let bytes = read_retention_file(
                &archive.daily,
                name,
                &path,
                MAX_DAILY_ADMISSION_ARCHIVE_BYTES,
            )
            .expect("read exact fixture archive leaf");
            digest.update(name.to_string_lossy().as_bytes());
            digest.update([0]);
            digest.update(&bytes);
            digest.update([0xff]);
        }
        (names.len(), digest.finalize().to_vec())
    }

    #[test]
    fn daily_admission_archive_recovery_is_byte_preserving_and_conflicts_fail_closed() {
        let home = TempDir::new().unwrap();
        let expected = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["rust".into()],
            1_777_000_000,
        )
        .unwrap();
        assert_eq!(
            append_daily_admission_once(home.path(), &expected).unwrap(),
            DailyArchiveStatus::Matching
        );
        let path = jsonl_file(home.path(), PeriodKind::Daily, &expected.tag);
        let before = std::fs::read(&path).unwrap();
        assert_eq!(
            append_daily_admission_once(home.path(), &expected).unwrap(),
            DailyArchiveStatus::Matching
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "recovery must not duplicate bytes"
        );
        std::fs::write(&path, b"not-json\n").unwrap();
        assert!(inspect_daily_archive(home.path(), &expected).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"not-json\n");
    }

    #[test]
    fn daily_writer_inventory_routes_the_compatibility_path_through_the_gate() {
        assert_eq!(
            DAILY_PRODUCTION_WRITERS,
            [
                "cli::reflect::run_reflect",
                "daemon::reflection_cron::run_period_reflection_tick_once",
            ]
        );
        let home = TempDir::new().unwrap();
        let reflection = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["gate".into()],
            1_777_000_000,
        )
        .unwrap();
        assert!(
            append(home.path(), &reflection).is_err(),
            "direct daily append is forbidden"
        );
        assert!(load_for_tag(home.path(), PeriodKind::Daily, &reflection.tag).is_err());
        let cli_source = include_str!("../cli/reflect.rs");
        let cron_source = include_str!("../daemon/reflection_cron.rs");
        // The inventory names the complete production surface.  A future
        // writer cannot use an ambient append primitive in either entry point:
        // CLI must use the central compatibility gate and cron must enter the
        // admission transaction before it can publish a daily record.
        assert!(cli_source.contains("periodic::settle_daily_admission("));
        assert!(cron_source.contains("run_daily_admission_tick(home, &refl"));
        assert!(!cli_source.contains("OpenOptions::new().create(true).append(true)"));
        assert!(!cron_source.contains("OpenOptions::new().create(true).append(true)"));

        let mut unknown = reflection.clone();
        unknown.kind = "not-a-daily-writer".into();
        unknown.tag = "unknown-period".into();
        assert!(append(home.path(), &unknown).is_err());
        assert!(!jsonl_file(home.path(), PeriodKind::Daily, &unknown.tag).exists());
    }

    #[cfg(unix)]
    #[test]
    fn daily_archive_refuses_a_symlinked_bound_directory() {
        use std::os::unix::fs::symlink;

        let home = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let secret = "ALIAS_TOPIC_BODY_PATH_SHOULD_NOT_LEAK";
        std::fs::create_dir(home.path().join("reflections")).unwrap();
        symlink(outside.path(), home.path().join("reflections/daily")).unwrap();
        let reflection =
            build_reflection(PeriodKind::Daily, secret, &["bound".into()], 1_777_000_000).unwrap();
        assert!(open_daily_archive_transaction(home.path()).is_err());
        assert!(
            !outside
                .path()
                .join(format!("{}.jsonl", reflection.tag))
                .exists()
        );
        assert!(!jsonl_file(home.path(), PeriodKind::Daily, &reflection.tag).is_file());
        let error = append_daily_admission_once(home.path(), &reflection).unwrap_err();
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));
    }

    #[test]
    fn stale_stage_and_partial_target_never_poison_or_truncate_daily_recovery() {
        let home = TempDir::new().unwrap();
        let reflection = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["atomic".into()],
            1_777_000_000,
        )
        .unwrap();
        let archive = open_daily_archive_transaction(home.path()).unwrap();
        std::fs::write(archive.daily_path.join(".neoth-atomic-stale"), b"stale").unwrap();
        let target = archive.daily_path.join("2026-08-27.jsonl");
        std::fs::write(&target, b"partial").unwrap();
        assert!(archive.append_once(&reflection).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"partial");
        std::fs::remove_file(&target).unwrap();
        assert_eq!(
            archive.append_once(&reflection).unwrap(),
            DailyArchiveStatus::Matching
        );
        assert_eq!(
            archive.inspect(&reflection).unwrap(),
            DailyArchiveStatus::Matching
        );
        assert_eq!(
            std::fs::read(archive.daily_path.join(".neoth-atomic-stale")).unwrap(),
            b"stale"
        );
    }

    #[cfg(test)]
    #[test]
    fn published_unknown_create_new_requires_a_fresh_recovery_read_without_duplicate() {
        let home = TempDir::new().unwrap();
        let reflection = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["durability".into()],
            1_777_000_000,
        )
        .unwrap();
        let target = jsonl_file(home.path(), PeriodKind::Daily, &reflection.tag);
        // Opening first establishes the exact bound parent used by the hook's
        // capability-relative create-new publication.
        let archive = open_daily_archive_transaction(home.path()).unwrap();
        crate::skills::store::fail_private_child_post_commit_validation_for_test(&target);
        assert!(archive.append_once(&reflection).is_err());
        let published = std::fs::read(&target).unwrap();
        drop(archive);
        assert_eq!(
            append_daily_admission_once(home.path(), &reflection).unwrap(),
            DailyArchiveStatus::Matching
        );
        assert_eq!(std::fs::read(&target).unwrap(), published);
    }

    #[test]
    fn settlement_suppresses_cli_equivalently_without_archive_or_note() {
        let home = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let mut config = crate::reflection::hygiene::DailyAdmissionConfig::default();
        config.enabled = true;
        let prior = build_reflection(
            PeriodKind::Daily,
            "2026-08-26",
            &["same".into()],
            1_787_702_400,
        )
        .unwrap();
        settle_daily_admission(home.path(), &prior, Some(&config), None).unwrap();
        let current = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["same".into()],
            1_787_788_800,
        )
        .unwrap();
        assert_eq!(
            settle_daily_admission(
                home.path(),
                &current,
                Some(&config),
                Some((vault.path(), "NEOTH")),
            )
            .unwrap(),
            DailySettlementOutcome::Suppressed
        );
        assert!(!jsonl_file(home.path(), PeriodKind::Daily, &current.tag).exists());
        assert_eq!(
            std::fs::read_to_string(home.path().join("reflections/daily-last.txt")).unwrap(),
            current.tag
        );
        assert!(!vault.path().join("NEOTH/Daily/2026-08-27.md").exists());
    }

    #[test]
    fn settlement_retries_obsidian_without_reappend_and_keeps_marker_last() {
        let home = TempDir::new().unwrap();
        let vault = home.path().join("vault-is-a-file");
        std::fs::write(&vault, b"not a directory").unwrap();
        let reflection = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["retry".into()],
            1_787_788_800,
        )
        .unwrap();
        assert!(
            settle_daily_admission(home.path(), &reflection, None, Some((&vault, "NEOTH")),)
                .is_err()
        );
        let archive =
            std::fs::read(jsonl_file(home.path(), PeriodKind::Daily, &reflection.tag)).unwrap();
        assert!(!home.path().join("reflections/daily-last.txt").exists());
        std::fs::remove_file(&vault).unwrap();
        std::fs::create_dir(&vault).unwrap();
        assert_eq!(
            settle_daily_admission(home.path(), &reflection, None, Some((&vault, "NEOTH")),)
                .unwrap(),
            DailySettlementOutcome::Admitted
        );
        assert_eq!(
            std::fs::read(jsonl_file(home.path(), PeriodKind::Daily, &reflection.tag)).unwrap(),
            archive
        );
        assert!(vault.join("NEOTH/Daily/2026-08-27.md").exists());
        assert_eq!(
            std::fs::read_to_string(home.path().join("reflections/daily-last.txt")).unwrap(),
            reflection.tag
        );
    }

    #[test]
    fn same_tag_admitted_recovery_uses_the_persisted_record_not_a_new_candidate() {
        let home = TempDir::new().unwrap();
        let vault = home.path().join("vault-is-a-file");
        std::fs::write(&vault, b"not a directory").unwrap();
        let original = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["original-topic".into()],
            1_787_788_800,
        )
        .unwrap();
        assert!(
            settle_daily_admission(home.path(), &original, None, Some((&vault, "NEOTH")),).is_err()
        );
        let archive_path = jsonl_file(home.path(), PeriodKind::Daily, &original.tag);
        let archived = std::fs::read(&archive_path).unwrap();
        assert!(!home.path().join("reflections/daily-last.txt").exists());

        // A retry may construct a different reflection later on the same UTC
        // day. The state fingerprint makes the existing archive authoritative.
        let rebuilt = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["replacement-topic".into()],
            1_787_792_000,
        )
        .unwrap();
        std::fs::remove_file(&vault).unwrap();
        std::fs::create_dir(&vault).unwrap();
        assert_eq!(
            settle_daily_admission(home.path(), &rebuilt, None, Some((&vault, "NEOTH")),).unwrap(),
            DailySettlementOutcome::Admitted
        );
        assert_eq!(std::fs::read(&archive_path).unwrap(), archived);
        assert_eq!(
            std::fs::read_to_string(vault.join("NEOTH/Daily/2026-08-27.md")).unwrap(),
            original.to_obsidian_md(),
        );
        assert_eq!(
            std::fs::read_to_string(home.path().join("reflections/daily-last.txt")).unwrap(),
            original.tag,
        );
    }

    #[test]
    fn no_state_archive_recovery_precedes_policy_and_rejects_digest_tampering() {
        let home = TempDir::new().unwrap();
        let original = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["archive-first".into()],
            1_787_788_800,
        )
        .unwrap();
        open_daily_archive_transaction(home.path())
            .unwrap()
            .append_once(&original)
            .unwrap();
        let rebuilt = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["policy-would-differ".into()],
            1_787_792_000,
        )
        .unwrap();
        let mut policy = crate::reflection::hygiene::DailyAdmissionConfig::default();
        policy.enabled = true;
        assert_eq!(
            settle_daily_admission(home.path(), &rebuilt, Some(&policy), None).unwrap(),
            DailySettlementOutcome::Admitted,
        );
        let state = crate::reflection::hygiene_store::lock_daily_admission(home.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(state.tag, original.tag);
        assert!(state.archive_sha256.is_some());
        let archive_path = jsonl_file(home.path(), PeriodKind::Daily, &original.tag);
        let altered = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["valid-but-altered".into()],
            1_787_793_000,
        )
        .unwrap();
        let mut altered_bytes = serde_json::to_vec(&altered).unwrap();
        altered_bytes.push(b'\n');
        std::fs::write(&archive_path, altered_bytes).unwrap();
        std::fs::remove_file(home.path().join("reflections/daily-last.txt")).unwrap();
        assert!(settle_daily_admission(home.path(), &rebuilt, Some(&policy), None).is_err());
        assert!(!home.path().join("reflections/daily-last.txt").exists());
    }

    #[test]
    fn completed_daily_settlement_does_not_rewrite_bound_note_or_marker() {
        let home = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let original = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["first-record".into()],
            1_777_000_000,
        )
        .unwrap();
        assert_eq!(
            settle_daily_admission(home.path(), &original, None, Some((vault.path(), "NEOTH")),)
                .unwrap(),
            DailySettlementOutcome::Admitted,
        );
        let note_path = vault.path().join("NEOTH/Daily/2026-08-27.md");
        let marker_path = home.path().join("reflections/daily-last.txt");
        let note_before = std::fs::read(&note_path).unwrap();
        let marker_before = std::fs::read(&marker_path).unwrap();

        let rebuilt = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["later-candidate".into()],
            1_777_003_600,
        )
        .unwrap();
        assert_eq!(
            settle_daily_admission(home.path(), &rebuilt, None, Some((vault.path(), "NEOTH")),)
                .unwrap(),
            DailySettlementOutcome::AlreadyCompleted,
        );
        assert_eq!(std::fs::read(&note_path).unwrap(), note_before);
        assert_eq!(std::fs::read(&marker_path).unwrap(), marker_before);
    }

    #[cfg(unix)]
    #[test]
    fn nested_obsidian_ancestor_swap_refuses_detached_note_and_marker() {
        let home = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let reflection = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["nested-binding".into()],
            1_777_000_000,
        )
        .unwrap();
        let archive = open_daily_archive_transaction(home.path()).unwrap();
        archive.append_once(&reflection).unwrap();
        let target = BoundObsidianDailyTarget::open(vault.path(), "NEOTH/Inner").unwrap();
        let old = vault.path().join("old-NEOTH");
        std::fs::rename(vault.path().join("NEOTH"), &old).unwrap();
        std::fs::create_dir(vault.path().join("NEOTH")).unwrap();
        std::fs::create_dir_all(vault.path().join("NEOTH/Inner")).unwrap();

        assert!(target.write_exact(&reflection).is_err());
        assert!(
            !vault
                .path()
                .join("NEOTH/Inner/Daily/2026-08-27.md")
                .exists()
        );
        assert!(!home.path().join("reflections/daily-last.txt").exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_retained_obsidian_directory_capability_blocks_ancestor_swap() {
        let home = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let reflection = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["nested-binding".into()],
            1_777_000_000,
        )
        .unwrap();
        let archive = open_daily_archive_transaction(home.path()).unwrap();
        archive.append_once(&reflection).unwrap();
        let _target = BoundObsidianDailyTarget::open(vault.path(), "NEOTH/Inner").unwrap();
        let old = vault.path().join("old-NEOTH");
        assert!(
            std::fs::rename(vault.path().join("NEOTH"), &old).is_err(),
            "the retained cap-std directory capability must withhold delete sharing"
        );
        assert!(!old.exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_direct_missing_tag_daily_transaction_publishes_from_private_capabilities() {
        let home = TempDir::new().unwrap();
        let reflection = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["windows-direct-archive".into()],
            1_777_000_000,
        )
        .unwrap();

        let archive = open_daily_archive_transaction(home.path()).unwrap();
        crate::wal::win_native::verify_private_directory_handle_dacl(&archive.home)
            .expect("private test home must retain its TokenUser DACL");
        crate::wal::win_native::verify_private_directory_handle_dacl(&archive.reflections)
            .expect("private reflections capability must retain its TokenUser DACL");
        crate::wal::win_native::verify_private_directory_handle_dacl(&archive.daily)
            .expect("private Daily capability must retain its TokenUser DACL");
        let lock_path = home
            .path()
            .join("reflections/daily-admission/state-v1.lock");
        assert!(
            !lock_path.exists(),
            "the exact direct transaction regression intentionally has no admission lock leaf"
        );

        assert_eq!(
            archive.inspect(&reflection).unwrap(),
            DailyArchiveStatus::Missing,
            "the exact direct transaction topology starts without a target leaf"
        );
        assert_eq!(
            archive.append_once(&reflection).unwrap(),
            DailyArchiveStatus::Matching,
            "the staged handle must publish through the retained cap-std Daily capability"
        );
        assert_eq!(
            archive.inspect(&reflection).unwrap(),
            DailyArchiveStatus::Matching,
        );
        assert!(!lock_path.exists());
        assert!(!crate::reflection::hygiene_store::daily_admission_state_path(home.path()).exists());
    }

    #[test]
    fn invalid_obsidian_subdirectories_fail_before_note_or_marker() {
        let invalid = ["", ".", "..", "../outside", "/rooted"];
        for subdir in invalid {
            let home = TempDir::new().unwrap();
            let vault = TempDir::new().unwrap();
            let reflection = build_reflection(
                PeriodKind::Daily,
                "2026-08-27",
                &["vault-bound".into()],
                1_787_788_800,
            )
            .unwrap();
            assert!(
                settle_daily_admission(
                    home.path(),
                    &reflection,
                    None,
                    Some((vault.path(), subdir)),
                )
                .is_err()
            );
            assert!(!home.path().join("reflections/daily-last.txt").exists());
            assert!(!vault.path().join("outside").exists());
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_prefixed_obsidian_subdirectory_is_refused() {
        assert!(validate_obsidian_subdir(r"C:\outside").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_non_directory_or_reparse_vault_is_refused_before_marker() {
        let home = TempDir::new().unwrap();
        let vault = home.path().join("vault-reparse-refusal");
        std::fs::write(&vault, b"not a directory").unwrap();
        let reflection = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["windows-vault".into()],
            1_787_788_800,
        )
        .unwrap();
        assert!(
            settle_daily_admission(home.path(), &reflection, None, Some((&vault, "NEOTH")))
                .is_err()
        );
        assert!(!home.path().join("reflections/daily-last.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_obsidian_vault_is_refused_without_outside_note_or_marker() {
        use std::os::unix::fs::symlink;

        let home = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let linked = home.path().join("vault-link");
        symlink(outside.path(), &linked).unwrap();
        let reflection = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["vault-link".into()],
            1_787_788_800,
        )
        .unwrap();
        assert!(
            settle_daily_admission(home.path(), &reflection, None, Some((&linked, "NEOTH")))
                .is_err()
        );
        assert!(!outside.path().join("NEOTH/Daily/2026-08-27.md").exists());
        assert!(!home.path().join("reflections/daily-last.txt").exists());
    }

    #[cfg(test)]
    #[test]
    fn marker_durability_unknown_requires_recovery_before_completion() {
        let home = TempDir::new().unwrap();
        let original = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["marker-original".into()],
            1_787_788_800,
        )
        .unwrap();
        let marker = home.path().join("reflections/daily-last.txt");
        crate::skills::store::fail_private_child_post_commit_validation_for_test(&marker);
        assert!(settle_daily_admission(home.path(), &original, None, None).is_err());
        let archive_path = jsonl_file(home.path(), PeriodKind::Daily, &original.tag);
        let archived = std::fs::read(&archive_path).unwrap();

        let rebuilt = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["marker-rebuilt".into()],
            1_787_792_000,
        )
        .unwrap();
        assert_eq!(
            settle_daily_admission(home.path(), &rebuilt, None, None).unwrap(),
            DailySettlementOutcome::AlreadyCompleted
        );
        assert_eq!(std::fs::read(&archive_path).unwrap(), archived);
        assert_eq!(std::fs::read_to_string(marker).unwrap(), original.tag);
    }

    #[test]
    fn corrupt_or_swapped_archive_refuses_visible_sync_and_marker() {
        let home = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let reflection = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["verified".into()],
            1_787_788_800,
        )
        .unwrap();
        let archive = open_daily_archive_transaction(home.path()).unwrap();
        archive.append_once(&reflection).unwrap();
        std::fs::write(archive.daily_path.join("2026-08-27.jsonl"), b"corrupt\n").unwrap();
        assert!(
            archive
                .sync_expected_to_obsidian(vault.path(), "NEOTH", &reflection)
                .is_err()
        );
        assert!(!vault.path().join("NEOTH/Daily/2026-08-27.md").exists());
        assert!(!home.path().join("reflections/daily-last.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn swapped_daily_directory_is_revalidated_before_visible_sync() {
        let home = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let reflection = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["swap".into()],
            1_787_788_800,
        )
        .unwrap();
        let archive = open_daily_archive_transaction(home.path()).unwrap();
        archive.append_once(&reflection).unwrap();
        let old = home.path().join("reflections/daily-old");
        std::fs::rename(home.path().join("reflections/daily"), &old).unwrap();
        std::fs::create_dir(home.path().join("reflections/daily")).unwrap();
        assert!(
            archive
                .sync_expected_to_obsidian(vault.path(), "NEOTH", &reflection)
                .is_err()
        );
        assert!(!vault.path().join("NEOTH/Daily/2026-08-27.md").exists());
        assert!(!home.path().join("reflections/daily-last.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn swapped_reflections_namespace_is_revalidated_before_marker_publication() {
        let home = TempDir::new().unwrap();
        let reflection = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["marker-swap".into()],
            1_787_788_800,
        )
        .unwrap();
        let archive = open_daily_archive_transaction(home.path()).unwrap();
        archive.append_once(&reflection).unwrap();
        let old = home.path().join("reflections-old");
        std::fs::rename(home.path().join("reflections"), &old).unwrap();
        std::fs::create_dir(home.path().join("reflections")).unwrap();
        assert!(
            archive
                .publish_marker(&reflection, DailySettlementOutcome::Admitted)
                .is_err()
        );
        assert!(!home.path().join("reflections/daily-last.txt").exists());
        assert!(!old.join("daily-last.txt").exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_reflections_non_directory_is_refused_before_marker_publication() {
        // This exercises the same bound-parent refusal path used for junctions
        // and other reparse objects without requiring developer-mode symlink
        // privilege in the Windows test runner.
        let home = TempDir::new().unwrap();
        std::fs::write(home.path().join("reflections"), b"not-a-directory").unwrap();
        let reflection = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["windows-bound".into()],
            1_787_788_800,
        )
        .unwrap();
        assert!(open_daily_archive_transaction(home.path()).is_err());
        assert!(!home.path().join("reflections/daily-last.txt").exists());
        assert!(append_daily_admission_once(home.path(), &reflection).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_retained_reflections_handle_blocks_namespace_swap_before_marker() {
        let home = TempDir::new().unwrap();
        let reflection = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["windows-swap".into()],
            1_787_788_800,
        )
        .unwrap();
        let archive = open_daily_archive_transaction(home.path()).unwrap();
        archive.append_once(&reflection).unwrap();
        // The retained cap-std directory capability normally denies replacement
        // on Windows. If a filesystem permits it, the identity check below must
        // still reject publication into the replacement namespace.
        let swapped = std::fs::rename(
            home.path().join("reflections"),
            home.path().join("reflections-swapped"),
        );
        match swapped {
            Ok(()) => {
                std::fs::create_dir(home.path().join("reflections")).unwrap();
                assert!(
                    archive
                        .publish_marker(&reflection, DailySettlementOutcome::Admitted)
                        .is_err()
                );
            }
            Err(_) => {
                assert!(!home.path().join("reflections/daily-last.txt").exists());
                assert_eq!(
                    archive
                        .publish_marker(&reflection, DailySettlementOutcome::Admitted)
                        .unwrap(),
                    DailyMarkerDurability::Confirmed,
                );
            }
        }
    }

    #[test]
    fn date_and_year_tags_format() {
        let ts = 1_767_225_600; // 2026-01-01 00:00:00 UTC
        assert_eq!(date_tag_from_unix(ts), "2026-01-01");
        assert_eq!(year_tag_from_unix(ts), "2026");
    }

    #[test]
    fn build_reflection_none_on_empty_topics() {
        assert!(build_reflection(PeriodKind::Daily, "2026-06-16", &[], 1).is_none());
        let r = build_reflection(
            PeriodKind::Daily,
            "2026-06-16",
            &["rust".into(), "slint".into()],
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(r.kind, "daily");
        assert!(r.body.contains("rust"));
        let y = build_reflection(PeriodKind::Yearly, "2026", &["neoth".into()], 1).unwrap();
        assert_eq!(y.kind, "yearly");
        assert!(y.body.contains("Jahr"));
    }

    #[test]
    fn obsidian_md_has_frontmatter_and_title() {
        let r = build_reflection(
            PeriodKind::Daily,
            "2026-06-16",
            &["webgpu".into()],
            1_700_000_000,
        )
        .unwrap();
        let md = r.to_obsidian_md();
        assert!(md.starts_with("---\nkind: \"daily\"\n"));
        assert!(md.contains("tag: \"2026-06-16\""));
        assert!(md.contains("# Daily reflection 2026-06-16"));
        assert!(md.contains("topics: [\"webgpu\"]"));
        assert!(md.contains("- webgpu\n"));
    }

    #[test]
    fn daily_retention_keeps_today_plus_eighty_nine_prior_dates_and_expires_day_ninety() {
        let now = 1_787_788_800_i64;
        let policy = DailyRetentionConfig::default();
        let (current_tag, expired_through_tag) = daily_retention_tags(now, &policy).unwrap();

        assert_eq!(current_tag, date_tag_from_unix(now));
        assert_eq!(expired_through_tag, date_tag_from_unix(now - 90 * 86_400));
        assert!(
            date_tag_from_unix(now - 89 * 86_400) > expired_through_tag,
            "the oldest retained date is the eighty-ninth prior calendar date"
        );
        assert!(
            date_tag_from_unix(now - 90 * 86_400) <= expired_through_tag,
            "the boundary itself is expired"
        );
        assert!(
            date_tag_from_unix(now - 91 * 86_400) <= expired_through_tag,
            "older history stays expired"
        );
    }

    #[test]
    fn daily_retention_rejects_invalid_policy_bounds_and_clock_underflow() {
        assert_eq!(
            DailyRetentionConfig {
                version: DAILY_RETENTION_CONFIG_VERSION,
                retention_days: 0,
            }
            .validate()
            .unwrap_err(),
            DailyRetentionError {
                reason: "invalid retention horizon",
            }
        );
        assert_eq!(
            DailyRetentionConfig {
                version: DAILY_RETENTION_CONFIG_VERSION,
                retention_days: MAX_DAILY_RETENTION_DAYS.saturating_add(1),
            }
            .validate()
            .unwrap_err(),
            DailyRetentionError {
                reason: "invalid retention horizon",
            }
        );
        assert_eq!(
            DailyRetentionConfig {
                version: DAILY_RETENTION_CONFIG_VERSION.saturating_add(1),
                retention_days: DEFAULT_DAILY_RETENTION_DAYS,
            }
            .validate()
            .unwrap_err(),
            DailyRetentionError {
                reason: "unsupported policy version",
            }
        );
        assert!(daily_retention_tags(i64::MIN, &DailyRetentionConfig::default()).is_err());
    }

    #[test]
    fn deterministic_retention_batches_resume_strictly_after_the_last_terminal_candidate() {
        let now = 1_787_788_800_i64;
        let all = (0..365)
            .map(|index| RetentionArchiveCandidate {
                tag: date_tag_from_unix(now - i64::from(365 - index) * 86_400),
                sha256: "a".repeat(64),
            })
            .collect::<Vec<_>>();

        let mut after = None;
        let mut recovered = Vec::new();
        loop {
            let batch =
                select_deterministic_retention_batch(all.clone(), after.as_deref(), 64).unwrap();
            if batch.is_empty() {
                break;
            }
            assert!(batch.windows(2).all(|pair| pair[0].tag < pair[1].tag));
            if let Some(previous) = after.as_deref() {
                assert!(batch[0].tag.as_str() > previous);
            }
            after = batch.last().map(|candidate| candidate.tag.clone());
            recovered.extend(batch);
        }

        assert_eq!(recovered.len(), 365, "257+ and multiyear histories batch");
        assert_eq!(
            recovered, all,
            "each retry continues after the exact prior terminal candidate"
        );
    }

    #[test]
    fn deterministic_retention_batches_cover_multiyear_history_without_starvation() {
        let now = 1_787_788_800_i64;
        let all = (0..(365 * 3))
            .map(|index| RetentionArchiveCandidate {
                tag: date_tag_from_unix(now - i64::from(365 * 3 - index) * 86_400),
                sha256: "b".repeat(64),
            })
            .collect::<Vec<_>>();

        let mut after = None;
        let mut recovered = Vec::new();
        loop {
            let batch = select_deterministic_retention_batch(
                all.clone(),
                after.as_deref(),
                MAX_DAILY_RETENTION_BATCH_ENTRIES,
            )
            .unwrap();
            let Some(last) = batch.last() else {
                break;
            };
            if let Some(previous) = after.as_deref() {
                assert!(batch[0].tag.as_str() > previous);
            }
            after = Some(last.tag.clone());
            recovered.extend(batch);
        }

        assert_eq!(recovered, all);
    }

    #[test]
    fn daily_retention_inventories_257_expired_archives_without_unsigned_cleanup() {
        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        for age in (90..=346).rev() {
            let tag = date_tag_from_unix(now - i64::from(age) * 86_400);
            let reflection = build_reflection(
                PeriodKind::Daily,
                &tag,
                &[format!("backfill-{age}")],
                now - i64::from(age) * 86_400,
            )
            .unwrap();
            settle_daily_admission(home.path(), &reflection, None, None).unwrap();
        }
        let current_tag = date_tag_from_unix(now);
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["current-retained".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &current, None, None).unwrap();

        let first =
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None)
                .unwrap();
        let retry =
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None)
                .unwrap();

        assert_eq!(
            first.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        assert_eq!(first.archives_deleted, 0);
        assert_eq!(first.archives_pending, 257);
        assert_eq!(retry, first, "a retry cannot advance an unsigned batch");
        assert!(
            jsonl_file(
                home.path(),
                PeriodKind::Daily,
                &date_tag_from_unix(now - 346 * 86_400),
            )
            .exists()
        );
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &current_tag).exists());
    }

    #[test]
    fn daily_retention_accepts_exactly_4096_archives_and_never_selects_or_emits_over_64() {
        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        std::fs::create_dir_all(periodic_dir(home.path(), PeriodKind::Daily)).unwrap();
        for age in 0..MAX_DAILY_RETENTION_ENTRIES {
            let age = i64::try_from(age).unwrap();
            let tag = date_tag_from_unix(now - age * 86_400);
            let reflection = build_reflection(
                PeriodKind::Daily,
                &tag,
                &[format!("inventory-cap-{age}")],
                now - age * 86_400,
            )
            .unwrap();
            let _archive_bytes = write_daily_retention_archive_fixture(home.path(), &reflection);
        }

        let policy = DailyRetentionConfig::default();
        let (current_tag, expired_through_tag) = daily_retention_tags(now, &policy).unwrap();
        let archive = open_existing_daily_retention_archive(home.path())
            .unwrap()
            .expect("exact-cap fixture archive exists");
        let manifest_before = daily_retention_archive_manifest(home.path());
        assert_eq!(manifest_before.0, MAX_DAILY_RETENTION_ENTRIES);

        let mut total_bytes = 0;
        let plan = plan_daily_archive_retention(
            &archive,
            &current_tag,
            &expired_through_tag,
            &mut total_bytes,
        )
        .unwrap();
        assert_eq!(plan.records.len(), MAX_DAILY_RETENTION_ENTRIES);
        assert_eq!(plan.selected.len(), MAX_DAILY_RETENTION_BATCH_ENTRIES);
        assert!(plan.selected.len() <= MAX_DAILY_RETENTION_BATCH_ENTRIES);

        let candidates = plan
            .records
            .iter()
            .filter(|(_, record)| record.expired)
            .map(|(tag, record)| RetentionArchiveCandidate {
                tag: tag.clone(),
                sha256: record.sha256.clone(),
            })
            .collect::<Vec<_>>();
        let emitted = select_deterministic_retention_batch(
            candidates.clone(),
            None,
            MAX_DAILY_RETENTION_BATCH_ENTRIES,
        )
        .unwrap();
        assert_eq!(emitted.len(), MAX_DAILY_RETENTION_BATCH_ENTRIES);
        assert!(emitted.len() <= MAX_DAILY_RETENTION_BATCH_ENTRIES);
        assert!(
            select_deterministic_retention_batch(
                candidates,
                None,
                MAX_DAILY_RETENTION_BATCH_ENTRIES + 1,
            )
            .is_err()
        );

        let outcome = enforce_daily_retention(home.path(), now, &policy, None).unwrap();
        assert_eq!(
            outcome.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        assert_eq!(
            outcome.archives_pending,
            MAX_DAILY_RETENTION_ENTRIES - usize::from(DEFAULT_DAILY_RETENTION_DAYS)
        );
        assert_eq!(outcome.archives_deleted, 0);
        assert_eq!(
            daily_retention_archive_manifest(home.path()),
            manifest_before
        );
    }

    #[test]
    fn daily_retention_rejects_4097_archive_entries_before_any_effect() {
        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let daily = periodic_dir(home.path(), PeriodKind::Daily);
        std::fs::create_dir_all(&daily).unwrap();
        let mut first = None;
        let mut last = None;
        for age in 0..=MAX_DAILY_RETENTION_ENTRIES {
            let age = i64::try_from(age).unwrap();
            let tag = date_tag_from_unix(now - age * 86_400);
            let path = daily.join(format!("{tag}.jsonl"));
            let reflection = build_reflection(
                PeriodKind::Daily,
                &tag,
                &[format!("inventory-over-cap-{age}")],
                now - age * 86_400,
            )
            .unwrap();
            let bytes = write_daily_retention_archive_fixture(home.path(), &reflection);
            if age == 0 {
                first = Some((path, bytes));
            } else if age == i64::try_from(MAX_DAILY_RETENTION_ENTRIES).unwrap() {
                last = Some((path, bytes));
            }
        }

        let archive = open_existing_daily_retention_archive(home.path())
            .unwrap()
            .expect("over-cap fixture archive exists");
        let capacity_error =
            bounded_retention_child_names(&archive.daily, MAX_DAILY_RETENTION_ENTRIES).unwrap_err();
        assert_eq!(capacity_error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            capacity_error.to_string(),
            "daily retention inventory exceeds its entry limit"
        );
        assert!(
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None,)
                .is_err()
        );
        for (path, bytes) in [
            first.expect("first fixture bytes"),
            last.expect("last fixture bytes"),
        ] {
            assert_eq!(std::fs::read(path).unwrap(), bytes);
        }
        assert_eq!(
            std::fs::read_dir(&daily).unwrap().count(),
            MAX_DAILY_RETENTION_ENTRIES + 1
        );
    }

    #[test]
    fn daily_retention_defers_365_real_archive_files_without_effects() {
        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        std::fs::create_dir_all(periodic_dir(home.path(), PeriodKind::Daily)).unwrap();
        let mut representatives = Vec::new();
        for age in 90..=454 {
            let tag = date_tag_from_unix(now - i64::from(age) * 86_400);
            let reflection = build_reflection(
                PeriodKind::Daily,
                &tag,
                &[format!("filesystem-365-{age}")],
                now - i64::from(age) * 86_400,
            )
            .unwrap();
            let bytes = write_daily_retention_archive_fixture(home.path(), &reflection);
            if matches!(age, 90 | 365 | 454) {
                representatives.push((tag, bytes));
            }
        }
        let current_tag = date_tag_from_unix(now);
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["filesystem-365-current".into()],
            now,
        )
        .unwrap();
        let current_bytes = write_daily_retention_archive_fixture(home.path(), &current);
        let manifest_before = daily_retention_archive_manifest(home.path());
        assert_eq!(manifest_before.0, 366);

        let outcome =
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None)
                .unwrap();

        assert_eq!(
            outcome.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        assert_eq!(outcome.archives_pending, 365);
        assert_eq!(outcome.unattested_note_debt, 0);
        assert_eq!(outcome.archives_deleted, 0);
        assert_eq!(outcome.notes_deleted, 0);
        assert_eq!(outcome.note_temps_deleted, 0);
        assert_eq!(outcome.daily_leaves_removed, 0);
        assert!(!outcome.changed());
        assert!(!home.path().join("reflections/daily-last.txt").exists());
        assert!(
            !crate::reflection::hygiene_store::daily_admission_state_path(home.path()).exists()
        );
        for (tag, bytes) in representatives {
            assert_eq!(
                std::fs::read(jsonl_file(home.path(), PeriodKind::Daily, &tag)).unwrap(),
                bytes
            );
        }
        assert_eq!(
            std::fs::read(jsonl_file(home.path(), PeriodKind::Daily, &current_tag)).unwrap(),
            current_bytes
        );
        assert_eq!(
            daily_retention_archive_manifest(home.path()),
            manifest_before
        );
    }

    #[test]
    fn daily_retention_defers_bounded_cross_year_history_without_effects() {
        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        std::fs::create_dir_all(periodic_dir(home.path(), PeriodKind::Daily)).unwrap();
        let mut representatives = Vec::new();
        for age in 90..=820 {
            let tag = date_tag_from_unix(now - i64::from(age) * 86_400);
            let reflection = build_reflection(
                PeriodKind::Daily,
                &tag,
                &[format!("cross-year-{age}")],
                now - i64::from(age) * 86_400,
            )
            .unwrap();
            let bytes = write_daily_retention_archive_fixture(home.path(), &reflection);
            if matches!(age, 90 | 365 | 730 | 820) {
                representatives.push((tag, bytes));
            }
        }
        let current_tag = date_tag_from_unix(now);
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["cross-year-current".into()],
            now,
        )
        .unwrap();
        let current_bytes = write_daily_retention_archive_fixture(home.path(), &current);
        let manifest_before = daily_retention_archive_manifest(home.path());
        assert_eq!(manifest_before.0, 732);

        let outcome =
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None)
                .unwrap();

        assert_ne!(
            &representatives[3].0[..4],
            &current_tag[..4],
            "fixture must span multiple UTC calendar years"
        );
        assert_eq!(
            outcome.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        assert_eq!(outcome.archives_pending, 731);
        assert_eq!(outcome.unattested_note_debt, 0);
        assert_eq!(outcome.archives_deleted, 0);
        assert_eq!(outcome.notes_deleted, 0);
        assert_eq!(outcome.note_temps_deleted, 0);
        assert_eq!(outcome.daily_leaves_removed, 0);
        assert!(!outcome.changed());
        assert!(!home.path().join("reflections/daily-last.txt").exists());
        assert!(
            !crate::reflection::hygiene_store::daily_admission_state_path(home.path()).exists()
        );
        for (tag, bytes) in representatives {
            assert_eq!(
                std::fs::read(jsonl_file(home.path(), PeriodKind::Daily, &tag)).unwrap(),
                bytes
            );
        }
        assert_eq!(
            std::fs::read(jsonl_file(home.path(), PeriodKind::Daily, &current_tag)).unwrap(),
            current_bytes
        );
        assert_eq!(
            daily_retention_archive_manifest(home.path()),
            manifest_before
        );
    }

    #[test]
    fn retention_retry_does_not_advance_or_delete_without_an_authority_terminal_receipt() {
        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        for age in (90..=154).rev() {
            let tag = date_tag_from_unix(now - i64::from(age) * 86_400);
            let reflection = build_reflection(
                PeriodKind::Daily,
                &tag,
                &[format!("crash-retry-{age}")],
                now - i64::from(age) * 86_400,
            )
            .unwrap();
            settle_daily_admission(home.path(), &reflection, None, None).unwrap();
        }
        let current_tag = date_tag_from_unix(now);
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["crash-retry-current".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &current, None, None).unwrap();

        let first =
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None)
                .unwrap();
        let retry =
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None)
                .unwrap();

        assert_eq!(
            first.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        assert_eq!(first.archives_deleted, 0);
        assert_eq!(first.archives_pending, 65);
        assert_eq!(retry, first);
        for age in 90..=154 {
            let tag = date_tag_from_unix(now - i64::from(age) * 86_400);
            assert!(jsonl_file(home.path(), PeriodKind::Daily, &tag).exists());
        }
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &current_tag).exists());
    }

    #[test]
    fn legacy_daily_note_and_historical_tmp_are_unattested_retention_debt() {
        let home = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 90 * 86_400);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["legacy-managed".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, Some((vault.path(), "NEOTH"))).unwrap();
        let historical_tmp = vault.path().join(format!("NEOTH/Daily/{stale_tag}.md.tmp"));
        std::fs::write(&historical_tmp, stale.to_obsidian_md()).unwrap();

        let outcome = enforce_daily_retention(
            home.path(),
            now,
            &DailyRetentionConfig::default(),
            Some((vault.path(), "NEOTH")),
        )
        .unwrap();

        assert_eq!(
            outcome.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        assert_eq!(outcome.unattested_note_debt, 2);
        assert_eq!(outcome.archives_deleted, 0);
        assert_eq!(outcome.notes_deleted, 0);
        assert_eq!(outcome.note_temps_deleted, 0);
        assert_eq!(outcome.daily_leaves_removed, 0);
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &stale_tag).exists());
        assert!(
            vault
                .path()
                .join(format!("NEOTH/Daily/{stale_tag}.md"))
                .exists()
        );
        assert!(historical_tmp.exists());
    }

    #[test]
    fn changed_canonical_looking_legacy_note_blocks_the_entire_retention_pass() {
        let home = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 90 * 86_400);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["legacy-note-swap".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, Some((vault.path(), "NEOTH"))).unwrap();
        let note = vault.path().join(format!("NEOTH/Daily/{stale_tag}.md"));
        std::fs::write(&note, b"same-name replacement after settlement\n").unwrap();

        let error = enforce_daily_retention(
            home.path(),
            now,
            &DailyRetentionConfig::default(),
            Some((vault.path(), "NEOTH")),
        )
        .unwrap_err();

        assert_eq!(
            error,
            DailyRetentionError {
                reason: "managed note inventory is invalid",
            }
        );
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &stale_tag).exists());
        assert_eq!(
            std::fs::read(&note).unwrap(),
            b"same-name replacement after settlement\n"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn reparse_or_symlink_daily_archive_leaf_blocks_retention_without_touching_target() {
        let home = TempDir::new().unwrap();
        let outside = RawTempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 90 * 86_400);
        let current_tag = date_tag_from_unix(now);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["reparse-stale".into()],
            now - 90 * 86_400,
        )
        .unwrap();
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["reparse-current".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, None).unwrap();
        settle_daily_admission(home.path(), &current, None, None).unwrap();

        let archive = jsonl_file(home.path(), PeriodKind::Daily, &stale_tag);
        let outside_archive = outside.path().join("outside-stale.jsonl");
        std::fs::write(&outside_archive, std::fs::read(&archive).unwrap()).unwrap();
        std::fs::remove_file(&archive).unwrap();
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&outside_archive, &archive).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(&outside_archive, &archive).is_ok();
        if !linked {
            return;
        }

        assert!(
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None,)
                .is_err()
        );
        assert!(archive.exists(), "the reparse leaf itself remains");
        assert!(
            outside_archive.exists(),
            "cleanup never followed the target"
        );
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &current_tag).exists());
    }

    #[test]
    fn daily_retention_uses_archive_tags_and_defers_the_inclusive_ninety_day_boundary() {
        use crate::reflection::hygiene_store::lock_daily_admission;

        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let older_expired_tag = date_tag_from_unix(now - 91 * 86_400);
        let stale_tag = date_tag_from_unix(now - 90 * 86_400);
        let oldest_retained_tag = date_tag_from_unix(now - 89 * 86_400);
        let current_tag = date_tag_from_unix(now);
        // Both expired records deliberately carry a current generated
        // timestamp: retention must use the archive tags, not rebuild time.
        let older_expired = build_reflection(
            PeriodKind::Daily,
            &older_expired_tag,
            &["older-expired-managed".into()],
            now,
        )
        .unwrap();
        let stale =
            build_reflection(PeriodKind::Daily, &stale_tag, &["old-managed".into()], now).unwrap();
        let oldest_retained = build_reflection(
            PeriodKind::Daily,
            &oldest_retained_tag,
            &["oldest-retained-managed".into()],
            now,
        )
        .unwrap();
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["current-managed".into()],
            now,
        )
        .unwrap();

        settle_daily_admission(home.path(), &older_expired, None, None).unwrap();
        settle_daily_admission(home.path(), &stale, None, None).unwrap();
        settle_daily_admission(home.path(), &oldest_retained, None, None).unwrap();
        settle_daily_admission(home.path(), &current, None, None).unwrap();

        let outcome =
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None)
                .unwrap();
        assert_eq!(
            outcome.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        assert_eq!(outcome.archives_deleted, 0);
        assert_eq!(outcome.archives_pending, 2);
        assert_eq!(outcome.unattested_note_debt, 0);
        assert_eq!(outcome.notes_deleted, 0);
        assert_eq!(outcome.note_temps_deleted, 0);
        assert_eq!(outcome.daily_leaves_removed, 0);
        assert!(!outcome.changed());
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &older_expired_tag).exists());
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &stale_tag).exists());
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &oldest_retained_tag).exists());
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &current_tag).exists());
        let state = lock_daily_admission(home.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(state.tag, current_tag);
        assert_eq!(
            std::fs::read_to_string(home.path().join("reflections/daily-last.txt")).unwrap(),
            current.tag
        );
    }

    #[test]
    fn daily_retention_keeps_current_admission_archive_when_authority_is_absent() {
        use crate::reflection::hygiene_store::lock_daily_admission;

        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 90 * 86_400);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["old-admission".into()],
            now - 90 * 86_400,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, None).unwrap();

        let outcome =
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None)
                .unwrap();

        assert_eq!(
            outcome.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        assert_eq!(outcome.archives_deleted, 0);
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &stale_tag).exists());
        let state = lock_daily_admission(home.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(state.tag, stale_tag);
        assert_eq!(
            std::fs::read_to_string(home.path().join("reflections/daily-last.txt")).unwrap(),
            stale.tag
        );
    }

    #[test]
    fn admission_state_revision_change_cannot_enable_an_unsigned_retention_effect() {
        use crate::reflection::hygiene_store::lock_daily_admission;

        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 90 * 86_400);
        let current_tag = date_tag_from_unix(now);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["control-plane-expired".into()],
            now - 90 * 86_400,
        )
        .unwrap();
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["control-plane-current".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, None).unwrap();
        settle_daily_admission(home.path(), &current, None, None).unwrap();

        let gate = lock_daily_admission(home.path()).unwrap();
        let state = gate.load().unwrap().unwrap();
        gate.compare_and_set(
            state.revision,
            &state.tag,
            state.outcome,
            state.archive_sha256.as_deref(),
        )
        .unwrap();

        let outcome =
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None)
                .unwrap();
        assert_eq!(
            outcome.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        assert_eq!(outcome.archives_deleted, 0);
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &stale_tag).exists());
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &current_tag).exists());
    }

    #[test]
    fn legacy_daily_leaf_is_explicit_debt_without_a_receipt_owned_permit() {
        let home = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 90 * 86_400);
        let current_tag = date_tag_from_unix(now);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["old-managed".into()],
            now - 90 * 86_400,
        )
        .unwrap();
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["current-managed".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, Some((vault.path(), "NEOTH"))).unwrap();
        // Keep the current archive/state, but leave the Daily leaf containing
        // only the old canonical note. Content equality alone must not let a
        // retention pass infer ownership of the configured `Daily` leaf.
        settle_daily_admission(home.path(), &current, None, None).unwrap();

        let outcome = enforce_daily_retention(
            home.path(),
            now,
            &DailyRetentionConfig::default(),
            Some((vault.path(), "NEOTH")),
        )
        .unwrap();
        assert_eq!(
            outcome.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        assert_eq!(outcome.unattested_note_debt, 1);
        assert_eq!(outcome.archives_deleted, 0);
        assert_eq!(outcome.notes_deleted, 0);
        assert_eq!(outcome.note_temps_deleted, 0);
        assert_eq!(outcome.daily_leaves_removed, 0);
        assert!(vault.path().join("NEOTH/Daily").is_dir());
        assert!(vault.path().join("NEOTH").is_dir());
        assert!(vault.path().is_dir());
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &stale_tag).exists());
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &current_tag).exists());
    }

    #[test]
    fn no_authority_has_no_delete_capable_retention_effect_path() {
        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 90 * 86_400);
        let current_tag = date_tag_from_unix(now);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["no-authority-stale".into()],
            now - 90 * 86_400,
        )
        .unwrap();
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["no-authority-current".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, None).unwrap();
        settle_daily_admission(home.path(), &current, None, None).unwrap();

        // `enforce_daily_retention` intentionally accepts no lease, receipt,
        // or ambient authority input. Its pre-v2 public path can therefore
        // only inventory and report the pending bounded candidate set.
        let outcome =
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None)
                .unwrap();

        assert_eq!(
            outcome.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        assert_eq!(outcome.archives_pending, 1);
        assert!(!outcome.changed());
        assert_eq!(outcome.archives_deleted, 0);
        assert_eq!(outcome.notes_deleted, 0);
        assert_eq!(outcome.note_temps_deleted, 0);
        assert_eq!(outcome.daily_leaves_removed, 0);
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &stale_tag).exists());
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &current_tag).exists());
    }

    #[test]
    fn forged_or_stale_authority_placeholders_cannot_enable_retention_effects() {
        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 90 * 86_400);
        let current_tag = date_tag_from_unix(now);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["forged-authority-stale".into()],
            now - 90 * 86_400,
        )
        .unwrap();
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["forged-authority-current".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, None).unwrap();
        settle_daily_admission(home.path(), &current, None, None).unwrap();

        // A v2 authority will own a fixed authenticated state location. These
        // attacker-controlled placeholder bytes are deliberately not an input
        // to this pre-v2 read-only planner.
        let placeholder_dir = home.path().join("retention-authority-v2");
        std::fs::create_dir_all(&placeholder_dir).unwrap();
        let forged = placeholder_dir.join("forged-lease.json");
        let stale_receipt = placeholder_dir.join("stale-terminal-receipt.json");
        std::fs::write(&forged, b"forged authority lease").unwrap();
        std::fs::write(&stale_receipt, b"stale authority receipt").unwrap();

        let outcome =
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None)
                .unwrap();

        assert_eq!(
            outcome.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        assert!(!outcome.changed());
        assert_eq!(outcome.archives_deleted, 0);
        assert_eq!(std::fs::read(&forged).unwrap(), b"forged authority lease");
        assert_eq!(
            std::fs::read(&stale_receipt).unwrap(),
            b"stale authority receipt"
        );
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &stale_tag).exists());
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &current_tag).exists());
    }

    #[test]
    fn empty_daily_leaf_remains_unreachable_without_a_receipt_bound_v2_effect() {
        let home = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 90 * 86_400);
        let current_tag = date_tag_from_unix(now);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["empty-daily-leaf-stale".into()],
            now - 90 * 86_400,
        )
        .unwrap();
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["empty-daily-leaf-current".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, None).unwrap();
        settle_daily_admission(home.path(), &current, None, None).unwrap();
        let daily_leaf = vault.path().join("NEOTH/Daily");
        std::fs::create_dir_all(&daily_leaf).unwrap();

        let outcome = enforce_daily_retention(
            home.path(),
            now,
            &DailyRetentionConfig::default(),
            Some((vault.path(), "NEOTH")),
        )
        .unwrap();

        assert_eq!(
            outcome.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        assert_eq!(outcome.daily_leaves_removed, 0);
        assert!(daily_leaf.is_dir());
        assert!(vault.path().join("NEOTH").is_dir());
        assert!(vault.path().is_dir());
    }

    #[test]
    fn historical_daily_target_without_an_archive_is_explicit_authority_debt() {
        let home = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let legacy_leaf = vault.path().join("NEOTH/Daily/2024-01-01.md.tmp");
        std::fs::create_dir_all(legacy_leaf.parent().unwrap()).unwrap();
        std::fs::write(&legacy_leaf, b"historical unattested daily note").unwrap();

        let outcome = enforce_daily_retention(
            home.path(),
            now,
            &DailyRetentionConfig::default(),
            Some((vault.path(), "NEOTH")),
        )
        .unwrap();

        assert_eq!(
            outcome.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        assert_eq!(outcome.unattested_note_debt, 1);
        assert!(!outcome.changed());
        assert_eq!(
            std::fs::read(&legacy_leaf).unwrap(),
            b"historical unattested daily note"
        );
    }

    #[test]
    fn pending_bound_delete_tombstone_is_blocked_for_v2_receipt_recovery() {
        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 90 * 86_400);
        let current_tag = date_tag_from_unix(now);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["tombstone-stale".into()],
            now - 90 * 86_400,
        )
        .unwrap();
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["tombstone-current".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, None).unwrap();
        settle_daily_admission(home.path(), &current, None, None).unwrap();

        // Model a crash after Unix rename-to-tombstone and before unlink. The
        // pre-v2 planner must preserve the bytes, not guess which original
        // receipt/identity authorized this pending effect.
        let stale_path = jsonl_file(home.path(), PeriodKind::Daily, &stale_tag);
        let stale_bytes = std::fs::read(&stale_path).unwrap();
        let tombstone = periodic_dir(home.path(), PeriodKind::Daily)
            .join(".neoth-bound-delete-0123456789abcdef0123456789abcdef");
        std::fs::rename(&stale_path, &tombstone).unwrap();

        assert_eq!(
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None,)
                .unwrap_err(),
            DailyRetentionError {
                reason: "retention pending-effect recovery required",
            }
        );
        assert_eq!(std::fs::read(&tombstone).unwrap(), stale_bytes);
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &current_tag).exists());
    }

    #[test]
    fn daily_retention_rejects_an_unknown_archive_leaf_before_any_authority_effect() {
        let home = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 91 * 86_400);
        let current_tag = date_tag_from_unix(now);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["old-managed".into()],
            now - 91 * 86_400,
        )
        .unwrap();
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["current-managed".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, Some((vault.path(), "NEOTH"))).unwrap();
        settle_daily_admission(home.path(), &current, None, None).unwrap();
        std::fs::write(
            periodic_dir(home.path(), PeriodKind::Daily).join("unrelated.bin"),
            b"x",
        )
        .unwrap();

        assert!(
            enforce_daily_retention(
                home.path(),
                now,
                &DailyRetentionConfig::default(),
                Some((vault.path(), "NEOTH")),
            )
            .is_err()
        );
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &stale_tag).exists());
        assert!(
            vault
                .path()
                .join(format!("NEOTH/Daily/{stale_tag}.md"))
                .exists()
        );
    }

    #[test]
    fn daily_retention_rejects_a_future_archive_before_any_authority_effect() {
        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 90 * 86_400);
        let current_tag = date_tag_from_unix(now);
        let future_tag = date_tag_from_unix(now + 86_400);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["expired-before-future-check".into()],
            now - 90 * 86_400,
        )
        .unwrap();
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["current-before-future-check".into()],
            now,
        )
        .unwrap();
        let future = build_reflection(
            PeriodKind::Daily,
            &future_tag,
            &["future-input".into()],
            now + 86_400,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, None).unwrap();
        settle_daily_admission(home.path(), &current, None, None).unwrap();
        let mut future_bytes = serde_json::to_vec(&future).unwrap();
        future_bytes.push(b'\n');
        std::fs::write(
            jsonl_file(home.path(), PeriodKind::Daily, &future_tag),
            future_bytes,
        )
        .unwrap();

        assert_eq!(
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None,)
                .unwrap_err(),
            DailyRetentionError {
                reason: "archive inventory is invalid",
            }
        );
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &stale_tag).exists());
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &current_tag).exists());
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &future_tag).exists());
    }

    #[test]
    fn daily_retention_rejects_an_oversized_archive_before_any_authority_effect() {
        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 90 * 86_400);
        let current_tag = date_tag_from_unix(now);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["oversized-before-cleanup".into()],
            now - 90 * 86_400,
        )
        .unwrap();
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["current-before-oversize".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, None).unwrap();
        settle_daily_admission(home.path(), &current, None, None).unwrap();
        let stale_archive = jsonl_file(home.path(), PeriodKind::Daily, &stale_tag);
        let oversized = vec![b'x'; MAX_DAILY_ADMISSION_ARCHIVE_BYTES + 1];
        std::fs::write(&stale_archive, &oversized).unwrap();

        assert_eq!(
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None,)
                .unwrap_err(),
            DailyRetentionError {
                reason: "archive inventory is invalid",
            }
        );
        assert_eq!(std::fs::read(&stale_archive).unwrap(), oversized);
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &current_tag).exists());
    }

    #[test]
    fn read_only_retention_rescan_rejects_an_in_place_archive_byte_swap() {
        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 90 * 86_400);
        let current_tag = date_tag_from_unix(now);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["planned-byte-swap".into()],
            now - 90 * 86_400,
        )
        .unwrap();
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["retained-while-swap".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, None).unwrap();
        settle_daily_admission(home.path(), &current, None, None).unwrap();

        let first =
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None)
                .unwrap();
        assert_eq!(
            first.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        let stale_path = jsonl_file(home.path(), PeriodKind::Daily, &stale_tag);
        let swapped = b"same-name bytes after retention planning\n";
        std::fs::write(&stale_path, swapped).unwrap();

        assert_eq!(
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None,)
                .unwrap_err(),
            DailyRetentionError {
                reason: "archive inventory is invalid",
            }
        );
        assert_eq!(std::fs::read(&stale_path).unwrap(), swapped);
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &current_tag).exists());
    }

    #[test]
    fn read_only_retention_rescan_rejects_a_late_unknown_leaf() {
        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 90 * 86_400);
        let current_tag = date_tag_from_unix(now);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["late-leaf-expired".into()],
            now - 90 * 86_400,
        )
        .unwrap();
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["late-leaf-current".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, None).unwrap();
        settle_daily_admission(home.path(), &current, None, None).unwrap();

        let first =
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None)
                .unwrap();
        assert_eq!(
            first.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        std::fs::write(
            periodic_dir(home.path(), PeriodKind::Daily).join("late-unmanaged.bin"),
            b"late input",
        )
        .unwrap();

        assert_eq!(
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None,)
                .unwrap_err(),
            DailyRetentionError {
                reason: "archive inventory is invalid",
            }
        );
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &stale_tag).exists());
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &current_tag).exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_retention_reads_through_a_handle_withholding_delete_share() {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
        use cap_std::fs::{OpenOptions, OpenOptionsExt as _};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        use crate::reflection::hygiene_store::{daily_admission_state_path, lock_daily_admission};

        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 90 * 86_400);
        let current_tag = date_tag_from_unix(now);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["delete-access-denied".into()],
            now - 90 * 86_400,
        )
        .unwrap();
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["current-with-delete-denial".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, None).unwrap();
        settle_daily_admission(home.path(), &current, None, None).unwrap();

        let stale_path = jsonl_file(home.path(), PeriodKind::Daily, &stale_tag);
        let current_path = jsonl_file(home.path(), PeriodKind::Daily, &current_tag);
        let stale_before = std::fs::read(&stale_path).unwrap();
        let current_before = std::fs::read(&current_path).unwrap();
        let marker_path = home.path().join("reflections/daily-last.txt");
        let marker_before = std::fs::read(&marker_path).unwrap();
        let state_path = daily_admission_state_path(home.path());
        let state_bytes_before = std::fs::read(&state_path).unwrap();
        let state_before = {
            let gate = lock_daily_admission(home.path()).unwrap();
            gate.load().unwrap().unwrap()
        };

        // An ordinary reader that withholds FILE_SHARE_DELETE permits another
        // reader but makes any DELETE request against this leaf fail. The
        // production path must still reach its deferred result, proving it
        // did not ask Windows for delete access before authority v2.
        let archive = open_existing_daily_retention_archive(home.path())
            .unwrap()
            .expect("settled archive remains available for the read-only handle");
        let stale_name = OsString::from(format!("{stale_tag}.jsonl"));
        let mut options = OpenOptions::new();
        options
            .read(true)
            .follow(FollowSymlinks::No)
            .access_mode(FILE_GENERIC_READ)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        let retained_non_delete_handle = archive.daily.open_with(&stale_name, &options).unwrap();

        let outcome =
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None)
                .unwrap();
        assert_eq!(
            outcome.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        assert_eq!(outcome.archives_pending, 1);
        assert_eq!(outcome.unattested_note_debt, 0);
        assert_eq!(outcome.archives_deleted, 0);
        assert_eq!(outcome.notes_deleted, 0);
        assert_eq!(outcome.note_temps_deleted, 0);
        assert_eq!(outcome.daily_leaves_removed, 0);
        assert!(!outcome.changed());
        assert_eq!(std::fs::read(&stale_path).unwrap(), stale_before);
        assert_eq!(std::fs::read(&current_path).unwrap(), current_before);
        assert_eq!(std::fs::read(&marker_path).unwrap(), marker_before);
        assert_eq!(std::fs::read(&state_path).unwrap(), state_bytes_before);
        let state_after = {
            let gate = lock_daily_admission(home.path()).unwrap();
            gate.load().unwrap().unwrap()
        };
        assert_eq!(state_after, state_before);
        drop(retained_non_delete_handle);
    }

    #[test]
    fn daily_retention_rejects_a_duplicate_archive_record_before_any_authority_effect() {
        let home = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 91 * 86_400);
        let current_tag = date_tag_from_unix(now);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["old-managed".into()],
            now - 91 * 86_400,
        )
        .unwrap();
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["current-managed".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, Some((vault.path(), "NEOTH"))).unwrap();
        settle_daily_admission(home.path(), &current, None, None).unwrap();
        let stale_archive = jsonl_file(home.path(), PeriodKind::Daily, &stale_tag);
        let serialized = String::from_utf8(std::fs::read(&stale_archive).unwrap()).unwrap();
        let duplicate = serialized.replacen(
            "\"kind\":\"daily\"",
            "\"kind\":\"daily\",\"kind\":\"daily\"",
            1,
        );
        assert_ne!(
            duplicate, serialized,
            "fixture must contain the daily kind field"
        );
        std::fs::write(&stale_archive, duplicate).unwrap();

        assert!(
            enforce_daily_retention(
                home.path(),
                now,
                &DailyRetentionConfig::default(),
                Some((vault.path(), "NEOTH")),
            )
            .is_err()
        );
        assert!(stale_archive.exists());
        assert!(
            vault
                .path()
                .join(format!("NEOTH/Daily/{stale_tag}.md"))
                .exists()
        );
    }

    #[test]
    fn daily_retention_leaves_a_conflicting_marker_untouched_without_authority() {
        let home = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 91 * 86_400);
        let current_tag = date_tag_from_unix(now);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["old-managed".into()],
            now - 91 * 86_400,
        )
        .unwrap();
        let current = build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["current-managed".into()],
            now,
        )
        .unwrap();
        settle_daily_admission(home.path(), &stale, None, Some((vault.path(), "NEOTH"))).unwrap();
        settle_daily_admission(home.path(), &current, None, None).unwrap();
        std::fs::write(
            home.path().join("reflections/daily-last.txt"),
            "not-a-managed-daily-tag",
        )
        .unwrap();

        let outcome = enforce_daily_retention(
            home.path(),
            now,
            &DailyRetentionConfig::default(),
            Some((vault.path(), "NEOTH")),
        )
        .unwrap();
        assert_eq!(
            outcome.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        assert_eq!(outcome.archives_deleted, 0);
        assert_eq!(outcome.notes_deleted, 0);
        assert_eq!(outcome.note_temps_deleted, 0);
        assert_eq!(outcome.daily_leaves_removed, 0);
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &stale_tag).exists());
        assert!(
            vault
                .path()
                .join(format!("NEOTH/Daily/{stale_tag}.md"))
                .exists()
        );
        assert_eq!(
            std::fs::read_to_string(home.path().join("reflections/daily-last.txt")).unwrap(),
            "not-a-managed-daily-tag"
        );
    }

    #[test]
    fn daily_retention_defers_a_suppressed_history_without_mutating_its_marker() {
        let home = TempDir::new().unwrap();
        let now = 1_787_788_800_i64;
        let stale_tag = date_tag_from_unix(now - 91 * 86_400);
        let prior_tag = date_tag_from_unix(now - 86_400);
        let current_tag = date_tag_from_unix(now);
        let stale = build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["old-managed".into()],
            now - 91 * 86_400,
        )
        .unwrap();
        let prior = build_reflection(
            PeriodKind::Daily,
            &prior_tag,
            &["same".into()],
            now - 86_400,
        )
        .unwrap();
        let current =
            build_reflection(PeriodKind::Daily, &current_tag, &["same".into()], now).unwrap();
        let mut admission = crate::reflection::hygiene::DailyAdmissionConfig::default();
        admission.enabled = true;

        settle_daily_admission(home.path(), &stale, None, None).unwrap();
        settle_daily_admission(home.path(), &prior, Some(&admission), None).unwrap();
        assert_eq!(
            settle_daily_admission(home.path(), &current, Some(&admission), None,).unwrap(),
            DailySettlementOutcome::Suppressed
        );

        let outcome =
            enforce_daily_retention(home.path(), now, &DailyRetentionConfig::default(), None)
                .unwrap();
        assert_eq!(
            outcome.execution,
            DailyRetentionExecution::AwaitingRetentionAuthority
        );
        assert_eq!(outcome.archives_deleted, 0);
        assert_eq!(outcome.notes_deleted, 0);
        assert_eq!(outcome.note_temps_deleted, 0);
        assert_eq!(outcome.daily_leaves_removed, 0);
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &stale_tag).exists());
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &prior_tag).exists());
        assert!(!jsonl_file(home.path(), PeriodKind::Daily, &current_tag).exists());
        assert_eq!(
            std::fs::read_to_string(home.path().join("reflections/daily-last.txt")).unwrap(),
            current_tag
        );
    }

    #[test]
    fn append_load_and_sync_roundtrip() {
        let home = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let r = build_reflection(PeriodKind::Yearly, "2026", &["zig".into()], 1).unwrap();
        append(home.path(), &r).unwrap();
        let loaded = load_for_tag(home.path(), PeriodKind::Yearly, "2026").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], r);

        let out = sync_to_obsidian(
            home.path(),
            vault.path(),
            "NEOTH",
            PeriodKind::Yearly,
            "2026",
        )
        .unwrap();
        assert!(out.written);
        assert!(out.target_path.ends_with("NEOTH/Yearly/2026.md"));
        assert!(out.target_path.exists());

        // Empty tag → no file, written:false.
        let empty = sync_to_obsidian(
            home.path(),
            vault.path(),
            "NEOTH",
            PeriodKind::Daily,
            "1999-01-01",
        );
        assert!(
            empty.is_err(),
            "generic daily sync is forbidden outside settlement"
        );
    }
}
