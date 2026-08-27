//! Daily + yearly self-reflection cadences.
//!
//! Mirrors the weekly OB-02 surface ([`super::WeeklyReflection`]): an archivable
//! record that persists as JSONL under `<home>/reflections/<kind>/<tag>.jsonl`
//! and renders to an Obsidian note at `<vault>/<subdir>/{Daily,Yearly}/<tag>.md`.
//! Builders compose a record from the period's top operator topics. Same
//! deterministic, offline, free rationale as the weekly reflection — no LLM, no
//! network, so the nightly + year-end passes run unattended even with the cloud
//! quota exhausted.

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest as _, Sha256};

pub const MAX_DAILY_ADMISSION_ARCHIVE_BYTES: usize = 256 * 1024;
pub const MAX_DAILY_ADMISSION_ARCHIVE_LINES: usize = 64;
const MAX_DAILY_ADMISSION_MARKER_BYTES: usize = 64;
const MAX_OBSIDIAN_SUBDIR_COMPONENTS: usize = 16;
const MAX_OBSIDIAN_SUBDIR_BYTES: usize = 512;
const MAX_OBSIDIAN_SUBDIR_COMPONENT_BYTES: usize = 128;

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
    reflections_binding: crate::skills::store::BoundChildObject,
    reflections_path: PathBuf,
    daily: cap_std::fs::Dir,
    daily_binding: crate::skills::store::BoundChildObject,
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
    binding: crate::skills::store::BoundChildObject,
    path: PathBuf,
}

/// The visible Daily note target, retained entirely as an ordered no-follow
/// capability chain from the configured vault root through every configured
/// subdirectory component and its `Daily` leaf. Display paths exist solely for
/// reported primitive validation; no write resolves an ambient vault path.
struct BoundObsidianDailyTarget {
    chain: Vec<BoundObsidianDirectoryLink>,
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
        let (vault, vault_binding) = crate::skills::store::open_mutation_bound_real_child_dir(
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
                .matches_child(&link.parent, &link.name, &link.path)
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
            .matches_child(
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
            .matches_child(&self.reflections, OsStr::new("daily"), &self.daily_path)
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
    // Namespace preparation is performed by this transaction before the gate,
    // including safe legacy permissions migration. The exact transaction then
    // remains capability-bound across inspect, publish, visible sync, marker.
    let archive = open_daily_archive_transaction(home).map_err(|_| DailySettlementError {
        reason: "archive unavailable",
    })?;
    let gate = lock_daily_admission(home).map_err(|_| DailySettlementError {
        reason: "gate unavailable",
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
    use tempfile::TempDir;

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
    fn windows_nested_obsidian_ancestor_swap_refuses_detached_note_and_marker() {
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
    fn windows_mutation_capabilities_publish_daily_archive_note_and_marker() {
        let home = TempDir::new().unwrap();
        let vault = TempDir::new().unwrap();
        let reflection = build_reflection(
            PeriodKind::Daily,
            "2026-08-27",
            &["windows-capability".into()],
            1_777_000_000,
        )
        .unwrap();

        assert_eq!(
            settle_daily_admission(
                home.path(),
                &reflection,
                None,
                Some((vault.path(), "NEOTH/Inner")),
            )
            .unwrap(),
            DailySettlementOutcome::Admitted,
        );
        assert!(jsonl_file(home.path(), PeriodKind::Daily, &reflection.tag).exists());
        assert!(
            vault
                .path()
                .join("NEOTH/Inner/Daily/2026-08-27.md")
                .exists()
        );
        assert_eq!(
            std::fs::read_to_string(home.path().join("reflections/daily-last.txt")).unwrap(),
            reflection.tag,
        );
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
        // The retained mutation-capable binding normally denies replacement on
        // Windows. If a filesystem permits it, the identity check below must
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
