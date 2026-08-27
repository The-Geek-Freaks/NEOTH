//! `neoth reflect` — self-reflection surfaces. `tech-news` pulls trending
//! Hacker News topics and flags the ones the operator's installed skills +
//! recent memory don't cover yet (a "tech-currency" gap). The operator tunes
//! the noisy HN signal with per-operator ignore/pin lists (`reflect ignore` /
//! `reflect pin`). The feed adapter lives in `crate::sources::hackernews`.

use std::ffi::OsStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::memory::store;
use crate::reflection::{hygiene::DailyAdmissionConfig, periodic::DailyRetentionConfig};
use crate::sources::hackernews::{self, GapFilter};

/// A deliberately small ceiling for the unattended reflection config.  The
/// interactive topic lists have no reason to grow into an allocation surface.
pub const MAX_REFLECT_TOPICS_CONFIG_BYTES: usize = 64 * 1024;
const REFLECT_TOPICS_CONFIG_FILE: &str = "reflect_topics.yaml";
const REFLECT_TOPICS_UPDATE_LOCK_FILE: &str = "reflect-topics-v1.lock";
const REFLECT_TOPICS_UPDATE_LOCK_WAIT: Duration = Duration::from_secs(5);

// Advisory file-lock reentrancy is platform-specific. Serialize the local
// process first, then retain the bound lockfile identity across processes.
static REFLECT_TOPICS_UPDATE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReflectTopicsLoadError {
    SafeConfigUnavailable,
    InvalidConfig,
}

impl std::fmt::Display for ReflectTopicsLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SafeConfigUnavailable => write!(f, "reflection automation config is unavailable"),
            Self::InvalidConfig => write!(f, "reflection automation config is invalid"),
        }
    }
}

impl std::error::Error for ReflectTopicsLoadError {}

/// A mutator-specific outcome.  A completed write is never reported until the
/// exact newly serialized configuration can be re-read through the same
/// capability-bound directory; callers must not retry an unconfirmed commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReflectTopicsUpdateError {
    SafeConfigUnavailable,
    InvalidConfig,
    ConcurrentUpdate,
    CommitUnconfirmed,
}

impl std::fmt::Display for ReflectTopicsUpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SafeConfigUnavailable => write!(f, "reflection update config is unavailable"),
            Self::InvalidConfig => write!(f, "reflection update config is invalid"),
            Self::ConcurrentUpdate => write!(f, "reflection update config changed concurrently"),
            Self::CommitUnconfirmed => write!(f, "reflection update commit is unconfirmed"),
        }
    }
}

impl std::error::Error for ReflectTopicsUpdateError {}

/// One immutable, capability-bound configuration generation prepared for a
/// compare-and-swap update.  It intentionally has no public constructor: a
/// CLI mutator can only write the byte generation it strictly inspected.
pub struct ReflectTopicsUpdate {
    directory: crate::skills::store::BoundDirectory,
    expected_bytes: Option<Vec<u8>>,
    topics: ReflectTopics,
}

/// A reported configuration write has two materially different outcomes: a
/// confirmed durable publication, or a namespace change whose parent-directory
/// durability cannot be confirmed. The latter must consume the CAS generation
/// but may never be reported to a CLI mutator as a successful update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReflectTopicsWriteDurability {
    Confirmed,
    Unknown,
}

/// A mutex-first, capability-bound lock that serializes one Topics CAS from
/// serialized-replacement validation through replacement and confirmation.
struct ReflectTopicsUpdateLock {
    _process_lock: std::sync::MutexGuard<'static, ()>,
    _os_lock: std::fs::File,
    binding: crate::skills::store::BoundChildObject,
}

impl ReflectTopicsUpdateLock {
    fn acquire(
        directory: &crate::skills::store::BoundDirectory,
    ) -> std::result::Result<Self, ReflectTopicsUpdateError> {
        let process_lock = REFLECT_TOPICS_UPDATE_LOCK
            .lock()
            .map_err(|_| ReflectTopicsUpdateError::SafeConfigUnavailable)?;
        let display_path = directory
            .display_path
            .join(REFLECT_TOPICS_UPDATE_LOCK_FILE);
        let (os_lock, binding) = crate::skills::store::open_or_create_bound_lockfile(
            &directory.dir,
            OsStr::new(REFLECT_TOPICS_UPDATE_LOCK_FILE),
            &display_path,
        )
        .map_err(|_| ReflectTopicsUpdateError::SafeConfigUnavailable)?;
        let started = Instant::now();
        loop {
            match os_lock.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock)
                    if started.elapsed() < REFLECT_TOPICS_UPDATE_LOCK_WAIT =>
                {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => return Err(ReflectTopicsUpdateError::SafeConfigUnavailable),
            }
        }
        let lock = Self {
            _process_lock: process_lock,
            _os_lock: os_lock,
            binding,
        };
        lock.revalidate(directory)?;
        Ok(lock)
    }

    fn revalidate(
        &self,
        directory: &crate::skills::store::BoundDirectory,
    ) -> std::result::Result<(), ReflectTopicsUpdateError> {
        let display_path = directory
            .display_path
            .join(REFLECT_TOPICS_UPDATE_LOCK_FILE);
        if self
            .binding
            .matches_regular_file_child_readonly(
                &directory.dir,
                OsStr::new(REFLECT_TOPICS_UPDATE_LOCK_FILE),
                &display_path,
            )
            .map_err(|_| ReflectTopicsUpdateError::SafeConfigUnavailable)?
        {
            Ok(())
        } else {
            Err(ReflectTopicsUpdateError::SafeConfigUnavailable)
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct ReflectArgs {
    #[command(subcommand)]
    pub action: ReflectAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ReflectAction {
    /// Scan trending Hacker News stories and show which topics your installed
    /// skills + recent memory don't cover yet (tech-currency self-reflection).
    TechNews {
        /// How many top HN stories to scan (capped at 100).
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Maximum gaps to surface.
        #[arg(long, default_value_t = 7)]
        max_gaps: usize,
    },
    /// Stop surfacing a topic as a gap (e.g. one you already follow elsewhere).
    Ignore { term: String },
    /// Always flag a topic when it trends, even if covered or single-mention.
    Pin { term: String },
    /// Remove a topic from BOTH the ignore and pin lists.
    Forget { term: String },
    /// Turn the weekly auto-refresh on (daemon enqueues a tech-currency
    /// reflection once a week). `--off` turns it back off.
    Weekly {
        #[arg(long)]
        off: bool,
    },
    /// Turn the nightly daily self-reflection on (daemon archives a daily
    /// summary + writes an Obsidian daily note). `--off` turns it back off.
    Daily {
        #[arg(long)]
        off: bool,
    },
    /// Turn the yearly self-reflection on (daemon archives a yearly summary +
    /// writes an Obsidian yearly note once a year). `--off` turns it back off.
    Yearly {
        #[arg(long)]
        off: bool,
    },
    /// Compose a daily or yearly reflection NOW (archive + Obsidian if a vault is
    /// configured) without waiting for the cron — handy to test it.
    Digest {
        #[arg(value_enum)]
        period: DigestPeriod,
    },
    /// Show the current per-operator ignore + pin lists + cadence states.
    Topics,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub enum DigestPeriod {
    Daily,
    Yearly,
}

/// Per-operator tuning for the tech-currency gap pass. Stored in its own
/// `<home>/reflect_topics.yaml` (never touches freedom.yaml).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReflectTopics {
    #[serde(default)]
    pub ignore: Vec<String>,
    #[serde(default)]
    pub pin: Vec<String>,
    /// Opt-in: the daemon refreshes the tech-currency reflection once a week
    /// (enqueues it for the operator). Off by default — when on it does a weekly
    /// network fetch to Hacker News; see `crate::daemon::reflection_cron`.
    #[serde(default)]
    pub weekly_refresh: bool,
    /// Opt-in: the daemon composes a nightly daily reflection (top topics of the
    /// day) + writes an Obsidian daily note when a vault is configured.
    #[serde(default)]
    pub daily_notes: bool,
    /// Opt-in: the daemon composes a yearly reflection once a year + writes an
    /// Obsidian yearly summary when a vault is configured.
    #[serde(default)]
    pub yearly_summary: bool,
    /// Absent on historical configurations. This remains intentionally opt-in;
    /// old valid files preserve their admission-decision behaviour, while the
    /// separate physical retention policy defaults to the 90-day boundary.
    #[serde(default)]
    pub daily_admission: Option<DailyAdmissionConfig>,
    /// Versioned physical Daily-retention policy. Historical configurations
    /// default to the 90-day Gold boundary. There is intentionally no disable
    /// switch; until retention authority v2 lands, the production pass only
    /// inventories/defer-reports candidates rather than claiming an effect.
    #[serde(default)]
    pub daily_retention: DailyRetentionConfig,
}

impl ReflectTopics {
    pub fn path(home: &std::path::Path) -> std::path::PathBuf {
        home.join(REFLECT_TOPICS_CONFIG_FILE)
    }

    /// Load config for an unattended automation.  Only a genuinely missing
    /// file maps to the disabled default; malformed YAML, unknown keys,
    /// symlinks/reparse points, directories and oversized files are typed,
    /// fail-closed errors rather than a surprise default.
    pub fn load_for_automation(
        home: &std::path::Path,
    ) -> std::result::Result<Self, ReflectTopicsLoadError> {
        let path = Self::path(home);
        let Some(directory) = crate::skills::store::open_absolute_bound_directory(
            home,
            false,
            "reflection automation home",
        )
        .map_err(|_| ReflectTopicsLoadError::SafeConfigUnavailable)?
        else {
            return Ok(Self::default());
        };
        let Some(bytes) = read_bound_reflect_topics_config(&directory, &path)
            .map_err(|_| ReflectTopicsLoadError::SafeConfigUnavailable)?
        else {
            return Ok(Self::default());
        };
        parse_reflect_topics_config(&bytes)
    }

    /// Strictly snapshot a configuration generation for an interactive
    /// mutation. Unlike the read-only automation loader, this creates a
    /// genuinely missing home directory through a no-follow capability walk,
    /// but never treats an existing malformed, oversized, linked/reparse, or
    /// non-regular config leaf as a default that may be overwritten.
    pub fn load_for_update(
        home: &std::path::Path,
    ) -> std::result::Result<ReflectTopicsUpdate, ReflectTopicsUpdateError> {
        let path = Self::path(home);
        let directory = crate::skills::store::open_absolute_bound_directory(
            home,
            true,
            "reflection update home",
        )
        .map_err(|_| ReflectTopicsUpdateError::SafeConfigUnavailable)?
        .ok_or(ReflectTopicsUpdateError::SafeConfigUnavailable)?;
        let expected_bytes = read_bound_reflect_topics_config(&directory, &path)
            .map_err(|_| ReflectTopicsUpdateError::SafeConfigUnavailable)?;
        let topics = match expected_bytes.as_deref() {
            Some(bytes) => {
                parse_reflect_topics_config(bytes).map_err(ReflectTopicsUpdateError::from)?
            }
            None => Self::default(),
        };
        Ok(ReflectTopicsUpdate {
            directory,
            expected_bytes,
            topics,
        })
    }
}

impl From<ReflectTopicsLoadError> for ReflectTopicsUpdateError {
    fn from(value: ReflectTopicsLoadError) -> Self {
        match value {
            ReflectTopicsLoadError::SafeConfigUnavailable => Self::SafeConfigUnavailable,
            ReflectTopicsLoadError::InvalidConfig => Self::InvalidConfig,
        }
    }
}

impl ReflectTopicsUpdate {
    pub fn topics(&self) -> &ReflectTopics {
        &self.topics
    }

    pub fn topics_mut(&mut self) -> &mut ReflectTopics {
        &mut self.topics
    }

    /// Atomically write this exact inspected generation. A byte-for-byte
    /// re-read confirms a reported durable publication; any durability
    /// uncertainty is unconfirmed and is never reported as success.
    pub fn commit(self) -> std::result::Result<ReflectTopics, ReflectTopicsUpdateError> {
        let replacement = serde_yaml::to_string(&self.topics)
            .map_err(|_| ReflectTopicsUpdateError::InvalidConfig)?
            .into_bytes();
        self.validate_serialized_replacement(&replacement)?;
        let write_lock = ReflectTopicsUpdateLock::acquire(&self.directory)?;
        // `topics_mut` intentionally exposes the complete configuration for
        // narrow CLI mutations. Reparse the exact serialized replacement
        // inside the lease before staging configuration bytes. The first
        // validation above deliberately runs before lockfile creation.
        self.validate_serialized_replacement(&replacement)?;
        self.revalidate_expected_generation(&write_lock)?;
        let path = self.directory.display_path.join(REFLECT_TOPICS_CONFIG_FILE);
        write_lock.revalidate(&self.directory)?;
        let write = match self.expected_bytes.as_deref() {
            Some(expected) => crate::skills::store::replace_existing_regular_file_if_matches_report(
                &self.directory.dir,
                OsStr::new(REFLECT_TOPICS_CONFIG_FILE),
                &path,
                expected,
                &replacement,
            )
            .map(|report| {
                if report.warnings.is_empty() {
                    ReflectTopicsWriteDurability::Confirmed
                } else {
                    ReflectTopicsWriteDurability::Unknown
                }
            }),
            None => crate::skills::store::atomic_write_private_child_create_new_reported(
                &self.directory.dir,
                OsStr::new(REFLECT_TOPICS_CONFIG_FILE),
                &path,
                &replacement,
            )
            .map(|commit| match commit {
                crate::skills::store::PrivateChildCommit::PublishedAndSynced => {
                    ReflectTopicsWriteDurability::Confirmed
                }
                crate::skills::store::PrivateChildCommit::PublishedDurabilityUnknown(_) => {
                    ReflectTopicsWriteDurability::Unknown
                }
            })
            .map_err(anyhow::Error::from),
        };

        match write {
            Ok(ReflectTopicsWriteDurability::Confirmed) => {
                self.confirm_committed_generation(&replacement, &write_lock)
            }
            // Preserve the reported durability boundary even if the immediate
            // exact read sees our bytes: after a parent-sync uncertainty this
            // mutator is unconfirmed and must not claim success or retry.
            Ok(ReflectTopicsWriteDurability::Unknown) => {
                Err(ReflectTopicsUpdateError::CommitUnconfirmed)
            }
            Err(error)
                if error.is::<crate::skills::store::ConditionalReplacePreconditionFailed>() =>
            {
                Err(ReflectTopicsUpdateError::ConcurrentUpdate)
            }
            // A reported creation failure may be a competing exclusive create;
            // a replacement failure can also occur after its namespace commit.
            // In both cases, a fresh exact read separates a known concurrent
            // generation from a possibly committed own generation without a
            // blind retry.
            Err(_) => self.classify_unconfirmed_write(&replacement, &write_lock),
        }
    }

    fn validate_serialized_replacement(
        &self,
        replacement: &[u8],
    ) -> std::result::Result<(), ReflectTopicsUpdateError> {
        if replacement.len() > MAX_REFLECT_TOPICS_CONFIG_BYTES {
            return Err(ReflectTopicsUpdateError::InvalidConfig);
        }
        let reparsed =
            parse_reflect_topics_config(replacement).map_err(ReflectTopicsUpdateError::from)?;
        if reparsed == self.topics {
            Ok(())
        } else {
            Err(ReflectTopicsUpdateError::InvalidConfig)
        }
    }

    /// Recheck the exact strict snapshot while holding the update lease. The
    /// advisory lock prevents two compliant writers from racing through an
    /// underlying compare/read/replace implementation as separate steps.
    fn revalidate_expected_generation(
        &self,
        write_lock: &ReflectTopicsUpdateLock,
    ) -> std::result::Result<(), ReflectTopicsUpdateError> {
        write_lock.revalidate(&self.directory)?;
        let path = self.directory.display_path.join(REFLECT_TOPICS_CONFIG_FILE);
        let current = read_bound_reflect_topics_config(&self.directory, &path)
            .map_err(|_| ReflectTopicsUpdateError::SafeConfigUnavailable)?;
        if current.as_deref() == self.expected_bytes.as_deref() {
            Ok(())
        } else {
            Err(ReflectTopicsUpdateError::ConcurrentUpdate)
        }
    }

    fn confirm_committed_generation(
        &self,
        replacement: &[u8],
        write_lock: &ReflectTopicsUpdateLock,
    ) -> std::result::Result<ReflectTopics, ReflectTopicsUpdateError> {
        if write_lock.revalidate(&self.directory).is_err() {
            return Err(ReflectTopicsUpdateError::CommitUnconfirmed);
        }
        let path = self.directory.display_path.join(REFLECT_TOPICS_CONFIG_FILE);
        match read_bound_reflect_topics_config(&self.directory, &path) {
            Ok(Some(current)) if current == replacement => {
                parse_reflect_topics_config(&current).map_err(ReflectTopicsUpdateError::from)
            }
            Ok(Some(current)) => match parse_reflect_topics_config(&current) {
                Ok(_) => Err(ReflectTopicsUpdateError::ConcurrentUpdate),
                Err(error) => Err(error.into()),
            },
            Ok(None) | Err(_) => Err(ReflectTopicsUpdateError::CommitUnconfirmed),
        }
    }

    fn classify_unconfirmed_write(
        &self,
        replacement: &[u8],
        write_lock: &ReflectTopicsUpdateLock,
    ) -> std::result::Result<ReflectTopics, ReflectTopicsUpdateError> {
        match self.confirm_committed_generation(replacement, write_lock) {
            // The exact bytes may already be visible after a reported write
            // error. They are still not a confirmed successful update.
            Ok(_) => Err(ReflectTopicsUpdateError::CommitUnconfirmed),
            Err(error) => Err(error),
        }
    }
}

fn read_bound_reflect_topics_config(
    directory: &crate::skills::store::BoundDirectory,
    path: &std::path::Path,
) -> std::io::Result<Option<Vec<u8>>> {
    match directory
        .dir
        .symlink_metadata(OsStr::new(REFLECT_TOPICS_CONFIG_FILE))
    {
        Ok(_) => crate::skills::store::read_regular_file_bounded(
            &directory.dir,
            OsStr::new(REFLECT_TOPICS_CONFIG_FILE),
            path,
            MAX_REFLECT_TOPICS_CONFIG_BYTES,
        )
        .map(Some)
        .map_err(std::io::Error::other),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn parse_reflect_topics_config(
    bytes: &[u8],
) -> std::result::Result<ReflectTopics, ReflectTopicsLoadError> {
    let topics: ReflectTopics =
        serde_yaml::from_slice(bytes).map_err(|_| ReflectTopicsLoadError::InvalidConfig)?;
    topics
        .daily_retention
        .validate()
        .map_err(|_| ReflectTopicsLoadError::InvalidConfig)?;
    if let Some(admission) = topics.daily_admission.as_ref() {
        let validation_topic = ["reflection-config-validation".to_string()];
        crate::reflection::hygiene::decide_daily_admission(&validation_topic, &[], admission)
            .map_err(|_| ReflectTopicsLoadError::InvalidConfig)?;
    }
    Ok(topics)
}

pub async fn run_reflect(args: ReflectArgs, output: OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match args.action {
        ReflectAction::TechNews { limit, max_gaps } => {
            tech_news(&home, limit, max_gaps, output).await
        }
        ReflectAction::Ignore { term } => add_topic(&home, &term, true, output),
        ReflectAction::Pin { term } => add_topic(&home, &term, false, output),
        ReflectAction::Forget { term } => forget_topic(&home, &term, output),
        ReflectAction::Weekly { off } => set_weekly(&home, !off, output),
        ReflectAction::Daily { off } => set_cadence(&home, Cadence::Daily, !off, output),
        ReflectAction::Yearly { off } => set_cadence(&home, Cadence::Yearly, !off, output),
        ReflectAction::Digest { period } => digest(&home, period, output),
        ReflectAction::Topics => show_topics(&home, output),
    }
}

#[derive(Clone, Copy)]
enum Cadence {
    Daily,
    Yearly,
}

fn set_cadence(
    home: &std::path::Path,
    cadence: Cadence,
    on: bool,
    output: OutputFormat,
) -> Result<()> {
    let mut update = ReflectTopics::load_for_update(home)?;
    let topics = update.topics_mut();
    let (label, vault_note) = match cadence {
        Cadence::Daily => {
            topics.daily_notes = on;
            ("daily nightly reflection", "Obsidian daily note")
        }
        Cadence::Yearly => {
            topics.yearly_summary = on;
            ("yearly reflection", "Obsidian yearly summary")
        }
    };
    let topics = update.commit()?;
    emit_topics(
        &topics,
        output,
        &if on {
            format!(
                "{label} ENABLED (daemon archives it + writes the {vault_note} if a vault is set)"
            )
        } else {
            format!("{label} disabled")
        },
    );
    Ok(())
}

fn digest(home: &std::path::Path, period: DigestPeriod, output: OutputFormat) -> Result<()> {
    digest_at(home, period, output, crate::time::now_unix_i64())
}

/// The current Daily archive/note/marker transaction completed, but its later
/// read-only retention inventory refused malformed input. Keep that partial
/// result explicit without leaking archive, vault, topic, or body details.
#[derive(Debug)]
struct DailyCommittedRetentionInventoryFailed;

impl std::fmt::Display for DailyCommittedRetentionInventoryFailed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "daily reflection committed=true; retention inventory is unavailable"
        )
    }
}

impl std::error::Error for DailyCommittedRetentionInventoryFailed {}

/// Explicit clock seam keeps daily settlement tests deterministic while the
/// public CLI continues to use the real clock exactly once per invocation.
fn digest_at(
    home: &std::path::Path,
    period: DigestPeriod,
    output: OutputFormat,
    now_unix: i64,
) -> Result<()> {
    use crate::reflection::periodic::{self, PeriodKind, date_tag_from_unix, year_tag_from_unix};

    let now_ns = now_unix.saturating_mul(1_000_000_000);
    let conn = store::open(&home.join("views.db")).context("open views.db")?;
    let (kind, tag, window, n) = match period {
        DigestPeriod::Daily => (PeriodKind::Daily, date_tag_from_unix(now_unix), 1, 5),
        DigestPeriod::Yearly => (PeriodKind::Yearly, year_tag_from_unix(now_unix), 365, 10),
    };
    // GR-fix: idempotency guard mirroring the daemon period-tick. The CLI digest
    // path appended a fresh JSONL record + Obsidian section on EVERY invocation, so
    // two `neoth reflect digest --daily` runs on the same day duplicated the
    // reflection. Share the daemon's marker files so daemon + CLI see each other's
    // completion for this tag.
    let yearly_marker = home.join("reflections").join("yearly-last.txt");
    let already_done = if matches!(period, DigestPeriod::Yearly)
        && yearly_marker
            .try_exists()
            .with_context(|| format!("inspect reflection marker {}", yearly_marker.display()))?
    {
        std::fs::read_to_string(&yearly_marker)
            .with_context(|| format!("read reflection marker {}", yearly_marker.display()))?
            .trim()
            == tag.as_str()
    } else {
        false
    };
    if already_done {
        if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
            println!(
                "{}",
                serde_json::json!({
                    "kind": kind.as_str(),
                    "tag": tag,
                    "written": false,
                    "reason": "already_done",
                })
            );
        } else {
            println!(
                "{} reflection {tag}: already written this period — skipping.",
                kind.vault_subdir()
            );
        }
        return Ok(());
    }
    // Validate the instance-local operator config before creating either the
    // reflection archive record or an Obsidian side effect. Only a genuinely
    // missing config may use compiled defaults.
    let cfg = FreedomConfig::load_from_path_or_default(&home.join("freedom.yaml"))?;
    let daily_admission = if matches!(period, DigestPeriod::Daily) {
        Some(
            ReflectTopics::load_for_automation(home)
                .map_err(anyhow::Error::from)
                .context("load daily admission policy")?,
        )
    } else {
        None
    };
    let topics =
        crate::reflection::top_topics_in_days(&conn, now_ns, window, n).context("topic query")?;
    let Some(refl) = periodic::build_reflection(kind, &tag, &topics, now_unix) else {
        if matches!(period, DigestPeriod::Daily) {
            // A quiet manual digest has no new archive to settle, but it still
            // reads the bounded Daily inventory from the same immutable topics
            // and Freedom snapshots. Effects stay deferred until v2 authority.
            let obsidian = cfg.obsidian_vault.as_deref().map(|vault| {
                (
                    std::path::Path::new(vault),
                    cfg.obsidian_subdir.as_deref().unwrap_or("NEOTH"),
                )
            });
            periodic::enforce_daily_retention(
                home,
                now_unix,
                &daily_admission
                    .as_ref()
                    .expect("Daily digest loaded the strict reflection topics config")
                    .daily_retention,
                obsidian,
            )
            .map_err(anyhow::Error::from)
            .context("enforce daily retention")?;
        }
        if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
            println!(
                "{}",
                serde_json::json!({ "kind": kind.as_str(), "tag": tag, "written": false })
            );
        } else {
            println!(
                "{} reflection {tag}: no topics in the window — nothing to summarise.",
                kind.vault_subdir()
            );
        }
        return Ok(());
    };
    let mut obsidian_path = None;
    if matches!(period, DigestPeriod::Daily) {
        let obsidian = cfg.obsidian_vault.as_deref().map(|vault| {
            (
                std::path::Path::new(vault),
                cfg.obsidian_subdir.as_deref().unwrap_or("NEOTH"),
            )
        });
        let settlement = periodic::settle_daily_admission(
            home,
            &refl,
            daily_admission
                .as_ref()
                .and_then(|topics| topics.daily_admission.as_ref()),
            obsidian,
        )
        .map_err(anyhow::Error::from)
        .context("settle daily reflection")?;
        // The manual writer shares the daemon's bounded retention inventory
        // cadence. The current pre-v2 pass only reports deferred candidates;
        // its later authenticated executor must use this same strict config
        // snapshot rather than silently defaulting malformed control input.
        let retention = periodic::enforce_daily_retention(
            home,
            now_unix,
            &daily_admission
                .as_ref()
                .expect("Daily digest loaded the strict reflection topics config")
                .daily_retention,
            obsidian,
        )
        .map_err(anyhow::Error::from);
        // Archive/note/marker settlement has completed before this bounded
        // inventory. Surface that committed partial result instead of implying
        // a rollback; an AlreadyCompleted retry still reports inventory error
        // normally because it performed no new Daily commit.
        if matches!(settlement, periodic::DailySettlementOutcome::Admitted) && retention.is_err() {
            return Err(anyhow::Error::new(DailyCommittedRetentionInventoryFailed)
                .context("daily reflection committed=true; retention inventory failed"));
        }
        retention.context("enforce daily retention")?;
        match settlement {
            periodic::DailySettlementOutcome::Admitted => {
                if cfg.obsidian_vault.is_some() {
                    // Settlement owns the capability-bound note destination;
                    // the CLI deliberately does not reconstruct its path.
                    obsidian_path = Some("bound daily note".to_string());
                }
            }
            periodic::DailySettlementOutcome::Suppressed => {
                if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
                    println!(
                        "{}",
                        serde_json::json!({
                            "kind": kind.as_str(),
                            "tag": tag,
                            "written": false,
                            "reason": "suppressed",
                        })
                    );
                } else {
                    println!(
                        "Daily reflection {tag}: suppressed by the configured admission policy."
                    );
                }
                return Ok(());
            }
            periodic::DailySettlementOutcome::AlreadyCompleted => {
                if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
                    println!(
                        "{}",
                        serde_json::json!({
                            "kind": kind.as_str(),
                            "tag": tag,
                            "written": false,
                            "reason": "already_done",
                        })
                    );
                } else {
                    println!("Daily reflection {tag}: already settled this period — skipping.");
                }
                return Ok(());
            }
        }
    } else {
        periodic::append(home, &refl).context("archive reflection")?;
        crate::util::atomic_write::atomic_write_private(&yearly_marker, tag.as_bytes())
            .with_context(|| format!("persist reflection marker {}", yearly_marker.display()))?;
        if let Some(vault) = cfg.obsidian_vault.as_deref() {
            let subdir = cfg.obsidian_subdir.as_deref().unwrap_or("NEOTH");
            let o =
                periodic::sync_to_obsidian(home, std::path::Path::new(vault), subdir, kind, &tag)
                    .context("Obsidian sync")?;
            if o.written {
                obsidian_path = Some(o.target_path.display().to_string());
            }
        }
    }

    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "kind": kind.as_str(), "tag": tag, "written": true,
                "topics": refl.topics, "body": refl.body, "obsidian": obsidian_path,
            })
        );
        return Ok(());
    }
    println!("{} reflection {tag} composed:", kind.vault_subdir());
    println!("  {}", refl.body);
    if !refl.topics.is_empty() {
        println!("  topics: {}", refl.topics.join(", "));
    }
    if let Some(p) = obsidian_path {
        println!("  → Obsidian: {p}");
    } else {
        println!("  (archived; no Obsidian vault configured — set freedom.yaml::obsidian_vault)");
    }
    Ok(())
}

fn set_weekly(home: &std::path::Path, on: bool, output: OutputFormat) -> Result<()> {
    let mut update = ReflectTopics::load_for_update(home)?;
    update.topics_mut().weekly_refresh = on;
    let topics = update.commit()?;
    emit_topics(
        &topics,
        output,
        if on {
            "weekly tech-currency refresh ENABLED (daemon enqueues it once a week)"
        } else {
            "weekly tech-currency refresh disabled"
        },
    );
    Ok(())
}

async fn tech_news(
    home: &std::path::Path,
    limit: usize,
    max_gaps: usize,
    output: OutputFormat,
) -> Result<()> {
    let config_path = home.join("freedom.yaml");
    let config = FreedomConfig::load_from_path(&config_path).with_context(|| {
        format!(
            "load active reflection policy from {}",
            config_path.display()
        )
    })?;
    let http =
        crate::tools::external_http::ExternalHttpAuthorizer::interactive(config.autonomy_policy())?;
    let topics = ReflectTopics::load_for_automation(home)?;
    let stories = hackernews::top_stories(&http, limit)
        .await
        .context("fetch Hacker News top stories")?;
    let filter = GapFilter {
        covered: collect_covered(home),
        ignore: topics.ignore.clone(),
        pin: topics.pin.clone(),
    };
    let gaps = hackernews::tech_currency_gaps(&stories, &filter, max_gaps);

    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "scanned": stories.len(),
                "covered_terms": filter.covered.len(),
                "ignored": topics.ignore, "pinned": topics.pin,
                "gaps": gaps,
                "reflection": hackernews::render_tech_currency_reflection(&gaps),
            })
        );
        return Ok(());
    }

    println!(
        "Tech-currency self-reflection ({} HN stories scanned):",
        stories.len()
    );
    if gaps.is_empty() {
        println!("  — keine Lücken: deine Skills/Memory decken die aktuellen Trends ab. ✓");
        return Ok(());
    }
    for g in &gaps {
        let mark = if g.pinned { " 📌" } else { "" };
        println!(
            "  • {}{} ({}×) — z.B. \"{}\"",
            g.term, mark, g.mentions, g.example_title
        );
    }
    if let Some(line) = hackernews::render_tech_currency_reflection(&gaps) {
        println!("\n{line}");
    }
    Ok(())
}

fn add_topic(home: &std::path::Path, term: &str, ignore: bool, output: OutputFormat) -> Result<()> {
    let t = term.trim().to_lowercase();
    if t.is_empty() {
        anyhow::bail!("empty topic");
    }
    let mut update = ReflectTopics::load_for_update(home)?;
    let topics = update.topics_mut();
    let list = if ignore {
        &mut topics.ignore
    } else {
        &mut topics.pin
    };
    if !list.iter().any(|x| x.eq_ignore_ascii_case(&t)) {
        list.push(t.clone());
        list.sort();
    }
    let topics = update.commit()?;
    emit_topics(
        &topics,
        output,
        &format!("{} `{t}`", if ignore { "ignoring" } else { "pinned" }),
    );
    Ok(())
}

fn forget_topic(home: &std::path::Path, term: &str, output: OutputFormat) -> Result<()> {
    let t = term.trim().to_lowercase();
    let mut update = ReflectTopics::load_for_update(home)?;
    let topics = update.topics_mut();
    topics.ignore.retain(|x| !x.eq_ignore_ascii_case(&t));
    topics.pin.retain(|x| !x.eq_ignore_ascii_case(&t));
    let topics = update.commit()?;
    emit_topics(
        &topics,
        output,
        &format!("forgot `{t}` (removed from ignore + pin)"),
    );
    Ok(())
}

fn show_topics(home: &std::path::Path, output: OutputFormat) -> Result<()> {
    let topics = ReflectTopics::load_for_automation(home)?;
    emit_topics(&topics, output, "tech-currency topic lists");
    Ok(())
}

fn emit_topics(topics: &ReflectTopics, output: OutputFormat, headline: &str) {
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) {
        println!(
            "{}",
            serde_json::json!({
                "ignore": topics.ignore, "pin": topics.pin,
                "weekly_refresh": topics.weekly_refresh,
                "daily_notes": topics.daily_notes,
                "yearly_summary": topics.yearly_summary,
                "daily_retention": topics.daily_retention,
            })
        );
        return;
    }
    println!("{headline}");
    println!(
        "  ignore: {}",
        if topics.ignore.is_empty() {
            "—".to_string()
        } else {
            topics.ignore.join(", ")
        }
    );
    println!(
        "  pin   : {}",
        if topics.pin.is_empty() {
            "—".to_string()
        } else {
            topics.pin.join(", ")
        }
    );
    println!(
        "  weekly: {}",
        if topics.weekly_refresh {
            "on"
        } else {
            "off — `neoth reflect weekly`"
        }
    );
    println!(
        "  daily : {}",
        if topics.daily_notes {
            "on"
        } else {
            "off — `neoth reflect daily`"
        }
    );
    println!(
        "  yearly: {}",
        if topics.yearly_summary {
            "on"
        } else {
            "off — `neoth reflect yearly`"
        }
    );
    let retention_status = "awaiting retention authority v2; not physically enforced";
    println!(
        "  retention: {} days (policy v{}; {retention_status})",
        topics.daily_retention.retention_days, topics.daily_retention.version
    );
}

/// The operator's "covered" surface: installed skill dir-names + manifest ids +
/// the top recent conversation topics from `<home>/views.db`. Best-effort — a
/// missing skills dir or views.db just yields fewer covered terms (more gaps
/// surface, never panics). Shared by the CLI + the weekly cron refresh.
pub fn collect_covered(home: &std::path::Path) -> Vec<String> {
    let mut covered = Vec::new();
    let skills_dir = home.join("skills");
    if let Ok(entries) = crate::skills::installer::list_installed(&skills_dir) {
        for entry in entries {
            covered.push(entry.dir_name);
            if let Some(id) = entry.manifest_id {
                covered.push(id);
            }
        }
    }
    if let Ok(conn) = store::open(&home.join("views.db")) {
        let now_ns = crate::time::now_unix_ns_i64();
        if let Ok(topics) = crate::reflection::top_topics_last_7_days(&conn, now_ns, 20) {
            covered.extend(topics);
        }
    }
    covered
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Model a private NEOTH_HOME. `tempfile::tempdir` uses the process umask
    /// on Unix, which is commonly 0755 in CI and correctly rejected by the
    /// production capability boundary.
    struct TestHome {
        _root: crate::test_env::CanonicalTempDir,
        path: std::path::PathBuf,
    }

    impl TestHome {
        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    fn private_test_home() -> TestHome {
        let root = crate::test_env::canonical_tempdir().expect("private test root");
        #[cfg(unix)]
        let path = {
            use std::os::unix::fs::DirBuilderExt as _;

            let path = root.path().join("private-home");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .expect("create private Unix test home");
            path
        };
        #[cfg(windows)]
        let path = {
            let path = root.path().join("private-home");
            crate::wal::win_native::create_private_directory_new(&path)
                .expect("create private Windows test home");
            path
        };
        #[cfg(not(any(unix, windows)))]
        let path = root.path().to_path_buf();
        TestHome { _root: root, path }
    }

    #[test]
    fn automation_config_missing_is_disabled_but_unknown_malformed_and_oversized_fail_closed() {
        let home = private_test_home();
        assert_eq!(
            ReflectTopics::load_for_automation(home.path()).unwrap(),
            ReflectTopics::default()
        );
        std::fs::write(
            home.path().join("reflect_topics.yaml"),
            "unknown_key: true\n",
        )
        .unwrap();
        assert_eq!(
            ReflectTopics::load_for_automation(home.path()).unwrap_err(),
            ReflectTopicsLoadError::InvalidConfig
        );
        std::fs::write(
            home.path().join("reflect_topics.yaml"),
            "daily_notes: [not: yaml\n",
        )
        .unwrap();
        assert_eq!(
            ReflectTopics::load_for_automation(home.path()).unwrap_err(),
            ReflectTopicsLoadError::InvalidConfig
        );
        std::fs::write(
            home.path().join("reflect_topics.yaml"),
            vec![b'x'; MAX_REFLECT_TOPICS_CONFIG_BYTES + 1],
        )
        .unwrap();
        assert_eq!(
            ReflectTopics::load_for_automation(home.path()).unwrap_err(),
            ReflectTopicsLoadError::SafeConfigUnavailable
        );
    }

    #[test]
    fn old_valid_config_preserves_disabled_daily_admission() {
        let home = private_test_home();
        std::fs::write(
            home.path().join("reflect_topics.yaml"),
            "daily_notes: true\n",
        )
        .unwrap();
        let config = ReflectTopics::load_for_automation(home.path()).unwrap();
        assert!(config.daily_notes);
        assert_eq!(config.daily_admission, None);
    }

    #[test]
    fn automation_retention_defaults_to_ninety_days_and_rejects_invalid_bounds() {
        use crate::reflection::periodic::{
            DAILY_RETENTION_CONFIG_VERSION, DEFAULT_DAILY_RETENTION_DAYS,
        };

        let home = private_test_home();
        let default = ReflectTopics::load_for_automation(home.path()).unwrap();
        assert_eq!(default.daily_retention.version, DAILY_RETENTION_CONFIG_VERSION);
        assert_eq!(default.daily_retention.retention_days, DEFAULT_DAILY_RETENTION_DAYS);

        for yaml in [
            "daily_retention:\n  version: 1\n  retention_days: 0\n",
            "daily_retention:\n  version: 1\n  retention_days: 91\n",
            "daily_retention:\n  version: 99\n  retention_days: 90\n",
            "daily_retention:\n  version: 1\n",
            "daily_retention: true\n",
            "daily_retention:\n  version: 1\n  retention_days: 90\n  unknown: true\n",
        ] {
            std::fs::write(home.path().join("reflect_topics.yaml"), yaml).unwrap();
            assert_eq!(
                ReflectTopics::load_for_automation(home.path()).unwrap_err(),
                ReflectTopicsLoadError::InvalidConfig
            );
        }
    }

    #[test]
    fn strict_update_creates_only_from_a_missing_bound_config_and_uses_exact_byte_cas() {
        let root = private_test_home();
        let home = root.path().join("new-neoth-home");

        let mut create = ReflectTopics::load_for_update(&home).unwrap();
        assert_eq!(create.topics(), &ReflectTopics::default());
        create.topics_mut().weekly_refresh = true;
        let committed = create.commit().unwrap();
        assert!(committed.weekly_refresh);

        let path = ReflectTopics::path(&home);
        let mut stale = ReflectTopics::load_for_update(&home).unwrap();
        stale.topics_mut().daily_notes = true;
        let concurrent = b"weekly_refresh: false\ndaily_notes: false\n";
        std::fs::write(&path, concurrent).unwrap();

        assert_eq!(
            stale.commit().unwrap_err(),
            ReflectTopicsUpdateError::ConcurrentUpdate
        );
        assert_eq!(std::fs::read(&path).unwrap(), concurrent);
    }

    #[test]
    fn strict_update_concurrent_mutators_yield_one_conflict_without_silent_overwrite() {
        use std::sync::{Arc, Barrier};

        let home = private_test_home();
        std::fs::write(
            ReflectTopics::path(home.path()),
            "daily_notes: false\nyearly_summary: false\n",
        )
        .unwrap();
        let home_path = Arc::new(home.path().to_path_buf());
        let snapshots_loaded = Arc::new(Barrier::new(3));

        let first_home = Arc::clone(&home_path);
        let first_ready = Arc::clone(&snapshots_loaded);
        let first = std::thread::spawn(move || {
            let mut update = ReflectTopics::load_for_update(first_home.as_ref()).unwrap();
            update.topics_mut().daily_notes = true;
            first_ready.wait();
            update.commit()
        });
        let second_home = Arc::clone(&home_path);
        let second_ready = Arc::clone(&snapshots_loaded);
        let second = std::thread::spawn(move || {
            let mut update = ReflectTopics::load_for_update(second_home.as_ref()).unwrap();
            update.topics_mut().yearly_summary = true;
            second_ready.wait();
            update.commit()
        });

        snapshots_loaded.wait();
        let outcomes = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert!(outcomes.iter().any(|outcome| {
            outcome.as_ref().err() == Some(&ReflectTopicsUpdateError::ConcurrentUpdate)
        }));
        let current = ReflectTopics::load_for_automation(home.path()).unwrap();
        assert!(
            (current.daily_notes && !current.yearly_summary)
                || (!current.daily_notes && current.yearly_summary),
            "one complete generation must win; independent fields may not merge or be lost"
        );
    }

    const REFLECT_TOPICS_CAS_CHILD_HOME: &str = "NEOTH_REFLECT_TOPICS_CAS_CHILD_HOME";
    const REFLECT_TOPICS_CAS_CHILD_READY: &str = "NEOTH_REFLECT_TOPICS_CAS_CHILD_READY";
    const REFLECT_TOPICS_CAS_CHILD_START: &str = "NEOTH_REFLECT_TOPICS_CAS_CHILD_START";
    const REFLECT_TOPICS_CAS_CHILD_RESULT: &str = "NEOTH_REFLECT_TOPICS_CAS_CHILD_RESULT";
    const REFLECT_TOPICS_CAS_CHILD_WORKER: &str = "NEOTH_REFLECT_TOPICS_CAS_CHILD_WORKER";

    fn reflect_topics_cas_helper_test_name() -> String {
        let module = module_path!();
        let prefix = concat!(env!("CARGO_CRATE_NAME"), "::");
        let module = module.strip_prefix(prefix).unwrap_or(module);
        format!("{module}::reflect_topics_cross_process_commit_helper")
    }

    fn spawn_reflect_topics_cas_child(
        home: &std::path::Path,
        ready: &std::path::Path,
        start: &std::path::Path,
        result: &std::path::Path,
        worker: &str,
    ) -> std::io::Result<std::process::Child> {
        std::process::Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg(reflect_topics_cas_helper_test_name())
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(REFLECT_TOPICS_CAS_CHILD_HOME, home)
            .env(REFLECT_TOPICS_CAS_CHILD_READY, ready)
            .env(REFLECT_TOPICS_CAS_CHILD_START, start)
            .env(REFLECT_TOPICS_CAS_CHILD_RESULT, result)
            .env(REFLECT_TOPICS_CAS_CHILD_WORKER, worker)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
    }

    /// Own both subprocesses for the complete test lifecycle. Any assertion,
    /// spawn failure, or timeout drops this guard, which kills and reaps every
    /// child before the control tempdir can disappear.
    struct ReflectTopicsCasChildPair {
        first: Option<std::process::Child>,
        second: Option<std::process::Child>,
        completed: bool,
    }

    impl ReflectTopicsCasChildPair {
        fn spawn(
            home: &std::path::Path,
            first_ready: &std::path::Path,
            start: &std::path::Path,
            first_result: &std::path::Path,
            second_ready: &std::path::Path,
            second_result: &std::path::Path,
        ) -> std::io::Result<Self> {
            let first = spawn_reflect_topics_cas_child(
                home,
                first_ready,
                start,
                first_result,
                "daily",
            )?;
            let mut pair = Self {
                first: Some(first),
                second: None,
                completed: false,
            };
            match spawn_reflect_topics_cas_child(
                home,
                second_ready,
                start,
                second_result,
                "yearly",
            ) {
                Ok(second) => {
                    pair.second = Some(second);
                    Ok(pair)
                }
                Err(error) => {
                    pair.abort_and_reap();
                    Err(error)
                }
            }
        }

        fn release_after_ready(
            &mut self,
            first_ready: &std::path::Path,
            second_ready: &std::path::Path,
            start: &std::path::Path,
        ) -> Result<(), &'static str> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            loop {
                match self.completion_state() {
                    Ok((false, false)) => {}
                    Ok(_) => {
                        self.abort_and_reap();
                        return Err("Topics CAS child exited before loading the common generation");
                    }
                    Err(()) => {
                        self.abort_and_reap();
                        return Err("could not poll Topics CAS child readiness");
                    }
                }
                let first_loaded = match Self::ready_marker_is_loaded(first_ready) {
                    Ok(loaded) => loaded,
                    Err(()) => {
                        self.abort_and_reap();
                        return Err("could not read Topics CAS child readiness");
                    }
                };
                let second_loaded = match Self::ready_marker_is_loaded(second_ready) {
                    Ok(loaded) => loaded,
                    Err(()) => {
                        self.abort_and_reap();
                        return Err("could not read Topics CAS child readiness");
                    }
                };
                if first_loaded && second_loaded {
                    if std::fs::write(start, b"go").is_err() {
                        self.abort_and_reap();
                        return Err("could not release Topics CAS children");
                    }
                    return Ok(());
                }
                if std::time::Instant::now() >= deadline {
                    self.abort_and_reap();
                    return Err("Topics CAS children did not load the common generation within 15s");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }

        /// `std::fs::write` can publish the marker path before all bytes are
        /// visible to a concurrent reader. A missing or partial marker is
        /// therefore still a bounded pending state; other read failures are
        /// genuine readiness errors.
        fn ready_marker_is_loaded(path: &std::path::Path) -> std::result::Result<bool, ()> {
            match std::fs::read(path) {
                Ok(bytes) => Ok(bytes.as_slice() == b"loaded"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(_) => Err(()),
            }
        }

        fn wait_for_completion(&mut self) -> Result<(), &'static str> {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            loop {
                match self.completion_state() {
                    Ok((true, true)) => {
                        self.completed = true;
                        return Ok(());
                    }
                    Ok(_) => {}
                    Err(()) => {
                        self.abort_and_reap();
                        return Err("could not poll Topics CAS child completion");
                    }
                }
                if std::time::Instant::now() >= deadline {
                    self.abort_and_reap();
                    return Err("Topics CAS children did not complete within 15s");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }

        fn completion_state(&mut self) -> Result<(bool, bool), ()> {
            let first = self
                .first
                .as_mut()
                .ok_or(())?
                .try_wait()
                .map_err(|_| ())?
                .is_some();
            let second = self
                .second
                .as_mut()
                .ok_or(())?
                .try_wait()
                .map_err(|_| ())?
                .is_some();
            Ok((first, second))
        }

        fn abort_and_reap(&mut self) {
            if let Some(first) = self.first.as_mut() {
                let _ = first.kill();
            }
            if let Some(second) = self.second.as_mut() {
                let _ = second.kill();
            }
            if let Some(first) = self.first.as_mut() {
                let _ = first.wait();
            }
            if let Some(second) = self.second.as_mut() {
                let _ = second.wait();
            }
        }

        fn take_outputs_after_completion(
            &mut self,
        ) -> Result<[std::process::Output; 2], ()> {
            if !self.completed {
                return Err(());
            }
            let first = self.first.take().ok_or(())?;
            let second = self.second.take().ok_or(())?;
            let first = first.wait_with_output().map_err(|_| ())?;
            let second = second.wait_with_output().map_err(|_| ())?;
            Ok([first, second])
        }
    }

    impl Drop for ReflectTopicsCasChildPair {
        fn drop(&mut self) {
            self.abort_and_reap();
        }
    }

    #[test]
    fn reflect_topics_cross_process_commit_helper() {
        let Some(home) = std::env::var_os(REFLECT_TOPICS_CAS_CHILD_HOME) else {
            return;
        };
        let ready = std::path::PathBuf::from(
            std::env::var_os(REFLECT_TOPICS_CAS_CHILD_READY).expect("child ready path"),
        );
        let start = std::path::PathBuf::from(
            std::env::var_os(REFLECT_TOPICS_CAS_CHILD_START).expect("child start path"),
        );
        let result = std::path::PathBuf::from(
            std::env::var_os(REFLECT_TOPICS_CAS_CHILD_RESULT).expect("child result path"),
        );
        let worker = std::env::var(REFLECT_TOPICS_CAS_CHILD_WORKER).expect("child worker");
        let mut update = ReflectTopics::load_for_update(std::path::Path::new(&home))
            .expect("load common Topics generation");
        match worker.as_str() {
            "daily" => update.topics_mut().daily_notes = true,
            "yearly" => update.topics_mut().yearly_summary = true,
            _ => panic!("unknown Topics CAS child worker"),
        }
        std::fs::write(&ready, b"loaded").expect("publish loaded snapshot");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !start.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "parent did not release Topics CAS child within 15s"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let outcome = match update.commit() {
            Ok(_) => "confirmed",
            Err(ReflectTopicsUpdateError::ConcurrentUpdate) => "concurrent",
            Err(ReflectTopicsUpdateError::SafeConfigUnavailable) => "safe_conflict",
            Err(error) => panic!("unexpected Topics CAS child outcome: {error}"),
        };
        std::fs::write(result, outcome).expect("publish Topics CAS child outcome");
    }

    #[test]
    fn strict_update_cross_process_mutators_preserve_one_complete_generation() {
        let home = private_test_home();
        let initial = b"daily_notes: false\nyearly_summary: false\n";
        std::fs::write(ReflectTopics::path(home.path()), initial).expect("write initial Topics");
        let control = tempfile::tempdir().expect("Topics CAS control directory");
        let start = control.path().join("start");
        let first_ready = control.path().join("first-ready");
        let second_ready = control.path().join("second-ready");
        let first_result = control.path().join("first-result");
        let second_result = control.path().join("second-result");
        let mut children = ReflectTopicsCasChildPair::spawn(
            home.path(),
            &first_ready,
            &start,
            &first_result,
            &second_ready,
            &second_result,
        )
        .unwrap_or_else(|_| panic!("spawn Topics CAS children"));
        children
            .release_after_ready(&first_ready, &second_ready, &start)
            .unwrap_or_else(|reason| panic!("{reason}"));
        children
            .wait_for_completion()
            .unwrap_or_else(|reason| panic!("{reason}"));
        let [first_output, second_output] = children
            .take_outputs_after_completion()
            .unwrap_or_else(|_| panic!("collect completed Topics CAS children"));
        assert!(
            first_output.status.success(),
            "first Topics CAS child exited unsuccessfully"
        );
        assert!(
            second_output.status.success(),
            "second Topics CAS child exited unsuccessfully"
        );

        let outcomes = [
            std::fs::read_to_string(&first_result).expect("first Topics child outcome"),
            std::fs::read_to_string(&second_result).expect("second Topics child outcome"),
        ];
        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.as_str() == "confirmed").count(),
            1,
            "exactly one process may confirm its strict Topics generation"
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome.as_str(), "concurrent" | "safe_conflict"))
                .count(),
            1,
            "the other process must preserve a safe concurrent-update outcome"
        );

        let mut daily = ReflectTopics::default();
        daily.daily_notes = true;
        let mut yearly = ReflectTopics::default();
        yearly.yearly_summary = true;
        let daily_bytes = serde_yaml::to_string(&daily).expect("serialize daily generation");
        let yearly_bytes = serde_yaml::to_string(&yearly).expect("serialize yearly generation");
        let final_bytes = std::fs::read(ReflectTopics::path(home.path())).unwrap();
        assert!(
            final_bytes == daily_bytes.as_bytes() || final_bytes == yearly_bytes.as_bytes(),
            "final Topics bytes must be one complete generation, never a silent overwrite"
        );
    }

    #[test]
    fn strict_update_validates_the_serialized_replacement_before_any_write() {
        let home = private_test_home();
        let path = ReflectTopics::path(home.path());
        let original = b"daily_notes: false\n";
        std::fs::write(&path, original).unwrap();

        let mut update = ReflectTopics::load_for_update(home.path()).unwrap();
        update.topics_mut().daily_retention.retention_days = 0;

        assert_eq!(
            update.commit().unwrap_err(),
            ReflectTopicsUpdateError::InvalidConfig
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            original,
            "invalid in-memory edits must leave the inspected bytes unchanged"
        );
        assert!(
            !home.path().join(REFLECT_TOPICS_UPDATE_LOCK_FILE).exists(),
            "serialized replacement validation must precede lockfile creation"
        );
    }

    #[test]
    fn strict_update_never_reports_parent_sync_unknown_as_success() {
        struct ResetParentSyncFailure;

        impl Drop for ResetParentSyncFailure {
            fn drop(&mut self) {
                crate::skills::store::force_parent_sync_failure_for_test(false);
            }
        }

        let home = private_test_home();
        let path = ReflectTopics::path(home.path());
        std::fs::write(&path, b"daily_notes: false\n").unwrap();

        // Create and durably confirm the advisory leaf before injecting a
        // parent-sync failure, so the hook exercises the configuration
        // publication rather than first-time lockfile creation.
        let mut warmup = ReflectTopics::load_for_update(home.path()).unwrap();
        warmup.topics_mut().weekly_refresh = true;
        warmup.commit().unwrap();
        let mut update = ReflectTopics::load_for_update(home.path()).unwrap();
        update.topics_mut().daily_notes = true;
        crate::skills::store::force_parent_sync_failure_for_test(true);
        let reset_parent_sync_failure = ResetParentSyncFailure;
        let result = update.commit();
        drop(reset_parent_sync_failure);

        assert_eq!(
            result.unwrap_err(),
            ReflectTopicsUpdateError::CommitUnconfirmed,
            "a visible replacement without parent durability confirmation is not success"
        );
    }

    #[test]
    fn strict_update_never_rewrites_malformed_or_non_regular_config() {
        let home = private_test_home();
        let path = ReflectTopics::path(home.path());
        let malformed = b"daily_notes: [unterminated\n";
        std::fs::write(&path, malformed).unwrap();

        assert_eq!(
            ReflectTopics::load_for_update(home.path()).unwrap_err(),
            ReflectTopicsUpdateError::InvalidConfig
        );
        assert!(set_weekly(home.path(), true, OutputFormat::Table).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), malformed);

        std::fs::write(&path, b"unknown_key: true\n").unwrap();
        assert_eq!(
            ReflectTopics::load_for_update(home.path()).unwrap_err(),
            ReflectTopicsUpdateError::InvalidConfig
        );

        let conflicting = b"weekly_refresh: true\nweekly_refresh: false\n";
        std::fs::write(&path, conflicting).unwrap();
        assert_eq!(
            ReflectTopics::load_for_update(home.path()).unwrap_err(),
            ReflectTopicsUpdateError::InvalidConfig
        );
        assert!(set_weekly(home.path(), true, OutputFormat::Table).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), conflicting);

        let oversized = vec![b'x'; MAX_REFLECT_TOPICS_CONFIG_BYTES + 1];
        std::fs::write(&path, &oversized).unwrap();
        assert_eq!(
            ReflectTopics::load_for_update(home.path()).unwrap_err(),
            ReflectTopicsUpdateError::SafeConfigUnavailable
        );
        assert!(set_weekly(home.path(), true, OutputFormat::Table).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), oversized);

        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(
            ReflectTopics::load_for_update(home.path()).unwrap_err(),
            ReflectTopicsUpdateError::SafeConfigUnavailable
        );
        assert!(set_cadence(home.path(), Cadence::Daily, true, OutputFormat::Table).is_err());
        assert!(path.is_dir());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn strict_update_refuses_a_reflect_topics_symlink_or_windows_reparse_leaf() {
        let home = private_test_home();
        let outside = tempfile::tempdir().unwrap();
        let outside_config = outside.path().join("outside-reflect_topics.yaml");
        let outside_bytes = b"weekly_refresh: false\n";
        std::fs::write(&outside_config, outside_bytes).unwrap();
        let link = ReflectTopics::path(home.path());

        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&outside_config, &link).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(&outside_config, &link).is_ok();

        // Windows developer-mode or the local privilege policy can disallow
        // symlink fixtures. Production still fails closed through the store's
        // reparse-safe capability primitive; this test remains portable.
        if !linked {
            return;
        }

        assert_eq!(
            ReflectTopics::load_for_update(home.path()).unwrap_err(),
            ReflectTopicsUpdateError::SafeConfigUnavailable
        );
        assert!(set_weekly(home.path(), true, OutputFormat::Table).is_err());
        assert_eq!(std::fs::read(&outside_config).unwrap(), outside_bytes);
    }

    #[test]
    fn cli_quiet_daily_digest_reaches_but_defers_retention_without_authority() {
        use crate::reflection::periodic::{self, PeriodKind};

        let home = private_test_home();
        let now = 1_787_788_800_i64;
        let stale_tag = periodic::date_tag_from_unix(now - 90 * 86_400);
        let current_tag = periodic::date_tag_from_unix(now);
        let stale = periodic::build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["manual-no-topics-stale".into()],
            now - 90 * 86_400,
        )
        .unwrap();
        let current = periodic::build_reflection(
            PeriodKind::Daily,
            &current_tag,
            &["manual-no-topics-current".into()],
            now,
        )
        .unwrap();
        periodic::settle_daily_admission(home.path(), &stale, None, None).unwrap();
        periodic::settle_daily_admission(home.path(), &current, None, None).unwrap();
        drop(store::open(&home.path().join("views.db")).unwrap());

        digest_at(home.path(), DigestPeriod::Daily, OutputFormat::Table, now).unwrap();

        assert!(
            periodic::jsonl_file(home.path(), PeriodKind::Daily, &stale_tag).exists(),
            "the quiet CLI path must not perform unsigned archive deletion"
        );
        assert!(periodic::jsonl_file(home.path(), PeriodKind::Daily, &current_tag).exists());
    }

    #[test]
    fn cli_daily_commit_reports_retention_inventory_failure_without_duplicate_retry() {
        use crate::reflection::hygiene_store::lock_daily_admission;
        use crate::reflection::periodic::{self, PeriodKind};

        let home = private_test_home();
        let now = 1_787_788_800_i64;
        let stale_tag = periodic::date_tag_from_unix(now - 90 * 86_400);
        let current_tag = periodic::date_tag_from_unix(now);
        let stale = periodic::build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["historical-archive".into()],
            now - 90 * 86_400,
        )
        .unwrap();
        periodic::settle_daily_admission(home.path(), &stale, None, None).unwrap();
        let stale_path = periodic::jsonl_file(home.path(), PeriodKind::Daily, &stale_tag);
        let malformed = b"malformed historical archive\n";
        std::fs::write(&stale_path, malformed).unwrap();

        let now_ns = now.saturating_mul(1_000_000_000);
        let conn = store::open(&home.path().join("views.db")).unwrap();
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                1_i64,
                crate::wal::events::EVENT_TYPE_RAW_TEXT as i64,
                now_ns,
                "retention inventory partial outcome",
                "retention-inventory-partial",
            ],
        )
        .unwrap();
        drop(conn);

        let error = digest_at(home.path(), DigestPeriod::Daily, OutputFormat::Table, now)
            .unwrap_err();
        assert!(
            error
                .downcast_ref::<DailyCommittedRetentionInventoryFailed>()
                .is_some(),
            "the error must explicitly distinguish a completed Daily commit"
        );
        let status = error.to_string();
        assert!(status.contains("daily reflection committed=true"));
        assert!(!status.contains(&stale_tag));

        let current_path = periodic::jsonl_file(home.path(), PeriodKind::Daily, &current_tag);
        let first_current = std::fs::read(&current_path).unwrap();
        assert_eq!(first_current.iter().filter(|byte| **byte == b'\n').count(), 1);
        let record: periodic::PeriodReflection = serde_json::from_slice(&first_current).unwrap();
        assert_eq!(record.kind, "daily");
        assert_eq!(record.tag, current_tag);
        assert_eq!(std::fs::read(&stale_path).unwrap(), malformed);
        assert_eq!(
            std::fs::read_to_string(home.path().join("reflections/daily-last.txt")).unwrap(),
            current_tag
        );
        let state = lock_daily_admission(home.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(state.tag, current_tag);

        let retry = digest_at(home.path(), DigestPeriod::Daily, OutputFormat::Table, now)
            .unwrap_err();
        assert!(
            retry
                .downcast_ref::<DailyCommittedRetentionInventoryFailed>()
                .is_none(),
            "an already-completed retry must not falsely claim a second commit"
        );
        assert_eq!(std::fs::read(&current_path).unwrap(), first_current);
        assert_eq!(std::fs::read(&stale_path).unwrap(), malformed);
    }

    #[test]
    fn cli_daily_digest_first_settlement_honours_enabled_suppression_policy() {
        use crate::reflection::hygiene::DailyAdmissionConfig;
        use crate::reflection::hygiene_store::{DailyAdmissionOutcome, lock_daily_admission};
        use crate::reflection::periodic::{self, PeriodKind};

        let home = private_test_home();
        let now = 1_787_788_800i64;
        let now_ns = now.saturating_mul(1_000_000_000);
        let conn = store::open(&home.path().join("views.db")).unwrap();
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                1i64,
                crate::wal::events::EVENT_TYPE_RAW_TEXT as i64,
                now_ns,
                "rust admission policy",
                "digest-suppression",
            ],
        ).unwrap();
        let topics = crate::reflection::top_topics_in_days(&conn, now_ns, 1, 5).unwrap();
        assert!(!topics.is_empty());
        let mut admission = DailyAdmissionConfig::default();
        admission.enabled = true;
        let stale_tag = periodic::date_tag_from_unix(now.saturating_sub(90 * 86_400));
        let stale = periodic::build_reflection(
            PeriodKind::Daily,
            &stale_tag,
            &["old manual archive".into()],
            now.saturating_sub(90 * 86_400),
        )
        .unwrap();
        periodic::settle_daily_admission(home.path(), &stale, None, None).unwrap();
        let prior = periodic::build_reflection(
            PeriodKind::Daily,
            &periodic::date_tag_from_unix(now.saturating_sub(86_400)),
            &topics,
            now.saturating_sub(86_400),
        )
        .unwrap();
        periodic::settle_daily_admission(home.path(), &prior, Some(&admission), None).unwrap();
        std::fs::write(
            home.path().join("reflect_topics.yaml"),
            "daily_admission:\n  version: 1\n  enabled: true\n  min_jaccard_basis_points: 10000\n",
        )
        .unwrap();

        digest_at(home.path(), DigestPeriod::Daily, OutputFormat::Table, now).unwrap();
        let tag = periodic::date_tag_from_unix(now);
        assert!(!periodic::jsonl_file(home.path(), PeriodKind::Daily, &tag).exists());
        let state = lock_daily_admission(home.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(state.tag, tag);
        assert_eq!(state.outcome, DailyAdmissionOutcome::Suppressed);
        assert_eq!(
            std::fs::read_to_string(home.path().join("reflections/daily-last.txt")).unwrap(),
            tag
        );
        assert!(
            periodic::jsonl_file(home.path(), PeriodKind::Daily, &stale_tag).exists(),
            "the manual daily writer reaches the bounded plan but defers unsigned cleanup"
        );
    }

    #[test]
    fn cli_daily_retry_uses_original_same_tag_record_after_candidate_changes() {
        use crate::reflection::periodic::{self, PeriodKind};

        let home = private_test_home();
        let now = 1_787_788_800i64;
        let now_ns = now.saturating_mul(1_000_000_000);
        let conn = store::open(&home.path().join("views.db")).unwrap();
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                1i64,
                crate::wal::events::EVENT_TYPE_RAW_TEXT as i64,
                now_ns,
                "rust obsidian retry",
                "digest-obsidian",
            ],
        ).unwrap();
        let vault = home.path().join("vault-is-a-file");
        std::fs::write(&vault, b"not a directory").unwrap();
        let config = FreedomConfig {
            obsidian_vault: Some(vault.display().to_string()),
            obsidian_subdir: Some("NEOTH".to_string()),
            ..Default::default()
        };
        std::fs::write(
            home.path().join("freedom.yaml"),
            serde_yaml::to_string(&config).unwrap(),
        )
        .unwrap();

        assert!(digest_at(home.path(), DigestPeriod::Daily, OutputFormat::Table, now).is_err());
        let tag = periodic::date_tag_from_unix(now);
        let archive_path = periodic::jsonl_file(home.path(), PeriodKind::Daily, &tag);
        let archive = std::fs::read(&archive_path).unwrap();
        let original: periodic::PeriodReflection = serde_json::from_slice(&archive).unwrap();
        assert!(!home.path().join("reflections/daily-last.txt").exists());
        let retry_now = now.saturating_add(3_600);
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                2i64,
                crate::wal::events::EVENT_TYPE_RAW_TEXT as i64,
                retry_now.saturating_mul(1_000_000_000),
                "replacement replacement replacement replacement replacement",
                "digest-obsidian-retry",
            ],
        ).unwrap();
        let retry_topics = crate::reflection::top_topics_in_days(
            &conn,
            retry_now.saturating_mul(1_000_000_000),
            1,
            5,
        )
        .unwrap();
        let rebuilt =
            periodic::build_reflection(PeriodKind::Daily, &tag, &retry_topics, retry_now).unwrap();
        assert_ne!(
            rebuilt.topics, original.topics,
            "the retry must exercise distinct same-day topics"
        );
        assert_ne!(
            rebuilt, original,
            "the retry must exercise a distinct same-day candidate"
        );
        std::fs::remove_file(&vault).unwrap();
        std::fs::create_dir(&vault).unwrap();
        digest_at(
            home.path(),
            DigestPeriod::Daily,
            OutputFormat::Table,
            retry_now,
        )
        .unwrap();
        assert_eq!(std::fs::read(&archive_path).unwrap(), archive);
        assert_eq!(
            std::fs::read_to_string(vault.join(format!("NEOTH/Daily/{tag}.md"))).unwrap(),
            original.to_obsidian_md(),
        );
        assert_eq!(
            std::fs::read_to_string(home.path().join("reflections/daily-last.txt")).unwrap(),
            tag
        );
    }

    #[test]
    fn cli_recovers_archive_without_state_before_using_its_new_candidate() {
        use crate::reflection::hygiene_store::lock_daily_admission;
        use crate::reflection::periodic::{self, PeriodKind};

        let home = private_test_home();
        let now = 1_787_788_800i64;
        let conn = store::open(&home.path().join("views.db")).unwrap();
        conn.execute(
            "INSERT INTO idx_episode \
             (event_id, event_type, ts_ns, text, text_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                1i64,
                crate::wal::events::EVENT_TYPE_RAW_TEXT as i64,
                now.saturating_mul(1_000_000_000),
                "cli changed candidate topics",
                "cli-archive-first",
            ],
        ).unwrap();
        let tag = periodic::date_tag_from_unix(now);
        let original = periodic::build_reflection(
            PeriodKind::Daily,
            &tag,
            &["cli-persisted-original".into()],
            now.saturating_sub(60),
        )
        .unwrap();
        periodic::open_daily_archive_transaction(home.path())
            .unwrap()
            .append_once(&original)
            .unwrap();
        digest_at(home.path(), DigestPeriod::Daily, OutputFormat::Table, now).unwrap();
        let archive =
            std::fs::read(periodic::jsonl_file(home.path(), PeriodKind::Daily, &tag)).unwrap();
        assert_eq!(
            serde_json::from_slice::<periodic::PeriodReflection>(&archive).unwrap(),
            original
        );
        let state = lock_daily_admission(home.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert!(state.archive_sha256.is_some());
    }

    #[test]
    fn collect_covered_reads_skills_from_the_supplied_home() {
        let home = private_test_home();
        let skill_dir = home.path().join("skills").join("home-specific");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("skill.yaml"),
            "id: home-specific\n\
             description: Home-specific test skill\n\
             trigger_keywords: [home]\n\
             system_prompt: Use this home.\n",
        )
        .unwrap();

        let covered = collect_covered(home.path());
        assert!(covered.iter().any(|item| item == "home-specific"));
    }
}
