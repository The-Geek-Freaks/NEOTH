//! `neoth updater` — operator-facing view of U-01..U-04 lane.
//!
//! Subcommands:
//!   - `neoth updater status` — correlate versioned FIRED/RESULT pairs across
//!     the complete rotating daemon WAL and render one latest state per task.
//!   - `neoth updater check` — compatibility spelling that delegates to the
//!     canonical, live `neoth update --check` component probe.
//!
//! Status reads the live WAL by default; `--from-jsonl <path>` remains an
//! explicit synthetic/test input.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::wal::events::{
    EVENT_TYPE_BOOT, EVENT_TYPE_UPDATER_TASK_FIRED, EVENT_TYPE_UPDATER_TASK_RESULT,
};
use crate::wal::payloads_u04::{
    ComponentStatus, UpdaterPassIdentity, UpdaterPassLane, UpdaterTaskFiredPayload,
    UpdaterTaskKind, UpdaterTaskResultPayload, UpdaterTerminalOutcome,
    updater_fired_receipt_sha256,
};

// Backward-compatible event-materialization helpers remain explicitly capped.
// The production Status command does not use them: it folds the complete WAL
// stream through `StreamingUpdaterProjection` below.
const MAX_MATERIALIZED_UPDATER_EVENTS: usize = 32_768;
const MAX_MATERIALIZED_UPDATER_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const MAX_UPDATER_STATUS_SINGLE_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_UPDATER_STATUS_COMPONENTS_PER_RESULT: usize = 4_096;
const MAX_MATERIALIZED_UPDATER_JSONL_BYTES: usize = 16 * 1024 * 1024;
const MAX_UPDATER_STATUS_OPEN_PASSES: usize = 4_096;
const UPDATER_STATUS_RECENT_IDENTITY_WINDOW: usize = 8_192;
const UPDATER_STATUS_RETAINED_ANOMALIES: usize = 10;

#[derive(Debug, Clone, Copy)]
struct UpdaterStatusLimits {
    max_events: usize,
    max_total_payload_bytes: usize,
    max_single_payload_bytes: usize,
    max_components_per_result: usize,
    max_jsonl_bytes: usize,
}

impl Default for UpdaterStatusLimits {
    fn default() -> Self {
        Self {
            max_events: MAX_MATERIALIZED_UPDATER_EVENTS,
            max_total_payload_bytes: MAX_MATERIALIZED_UPDATER_PAYLOAD_BYTES,
            max_single_payload_bytes: MAX_UPDATER_STATUS_SINGLE_PAYLOAD_BYTES,
            max_components_per_result: MAX_UPDATER_STATUS_COMPONENTS_PER_RESULT,
            max_jsonl_bytes: MAX_MATERIALIZED_UPDATER_JSONL_BYTES,
        }
    }
}

#[derive(Debug)]
struct UpdaterStatusBudget {
    limits: UpdaterStatusLimits,
    events: usize,
    payload_bytes: usize,
}

impl UpdaterStatusBudget {
    fn new(limits: UpdaterStatusLimits) -> Self {
        Self {
            limits,
            events: 0,
            payload_bytes: 0,
        }
    }

    fn admit_payload(&mut self, payload_bytes: usize) -> Result<()> {
        anyhow::ensure!(
            payload_bytes <= self.limits.max_single_payload_bytes,
            "updater status payload exceeds the {}-byte per-event memory limit",
            self.limits.max_single_payload_bytes
        );
        let next_events = self
            .events
            .checked_add(1)
            .context("updater status event counter overflow")?;
        anyhow::ensure!(
            next_events <= self.limits.max_events,
            "updater status exceeds the {}-event memory limit",
            self.limits.max_events
        );
        let next_payload_bytes = self
            .payload_bytes
            .checked_add(payload_bytes)
            .context("updater status payload-byte counter overflow")?;
        anyhow::ensure!(
            next_payload_bytes <= self.limits.max_total_payload_bytes,
            "updater status exceeds the {}-byte aggregate payload memory limit",
            self.limits.max_total_payload_bytes
        );
        self.events = next_events;
        self.payload_bytes = next_payload_bytes;
        Ok(())
    }
}

#[derive(Args, Debug, Clone)]
pub struct UpdaterArgs {
    #[command(subcommand)]
    pub action: UpdaterAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum UpdaterAction {
    /// Verify and print the latest correlated updater state per concrete lane
    /// and task class.
    ///
    /// Default mode reads the complete rotating live WAL namespace rooted at
    /// `~/.neoth/wal/000001.wal`. Use `--config` for a custom instance home,
    /// `--wal-chain-base` for a custom daemon namespace, `--wal-segment` for
    /// diagnostic single-segment mode, or `--from-jsonl` for a synthetic file.
    Status {
        /// Instance freedom.yaml. Its parent is the authoritative home, using
        /// the same rule as `neoth serve --config`.
        #[arg(
            long,
            value_name = "PATH",
            conflicts_with_all = ["wal_segment", "from_jsonl"]
        )]
        config: Option<PathBuf>,
        /// First segment of the complete rotating namespace to scan. Must be a
        /// canonical direct child of the selected instance home's `wal`
        /// directory. Unlike `--wal-segment`, rotations are followed.
        #[arg(
            long,
            value_name = "PATH",
            conflicts_with_all = ["wal_segment", "from_jsonl"]
        )]
        wal_chain_base: Option<PathBuf>,
        /// Path to one specific WAL segment. This is diagnostic mode and does
        /// not follow rotations. Omit it for the complete canonical home chain.
        #[arg(
            long,
            value_name = "PATH",
            conflicts_with_all = ["wal_chain_base", "from_jsonl"]
        )]
        wal_segment: Option<PathBuf>,
        /// Path to a JSONL file containing one
        /// `UpdaterTaskResultPayload` per line. Overrides the WAL scan when
        /// set; this compatibility/test input cannot prove the persisted FIRED
        /// receipt and is not equivalent to canonical WAL verification.
        #[arg(long, value_name = "PATH")]
        from_jsonl: Option<PathBuf>,
    },
    /// Run the canonical component update check (`neoth update --check`).
    Check,
}

fn canonical_check_args(output: OutputFormat) -> crate::cli::update::UpdateArgs {
    crate::cli::update::UpdateArgs {
        check: true,
        apply: false,
        list: false,
        self_check: false,
        self_repo: None,
        allow_unsigned: false,
        output,
    }
}

pub async fn run_updater(args: UpdaterArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        UpdaterAction::Status {
            config,
            wal_chain_base,
            wal_segment,
            from_jsonl,
        } => {
            let projection = if let Some(path) = from_jsonl {
                project_updater_status_from_jsonl(&path)?
            } else if let Some(segment) = wal_segment {
                project_updater_status_from_wal(&segment).context(concat!(
                    "UPDATER_AUDIT_UNAVAILABLE",
                    ": explicit updater WAL segment could not be verified"
                ))?
            } else {
                let config_path = config.unwrap_or_else(FreedomConfig::default_path);
                let home = config_path
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("."));
                if let Some(base) = wal_chain_base {
                    project_updater_status_from_home_chain(&home, &base).context(concat!(
                        "UPDATER_AUDIT_UNAVAILABLE",
                        ": updater WAL chain could not be verified"
                    ))?
                } else {
                    project_updater_status_from_home(&home).context(concat!(
                        "UPDATER_AUDIT_UNAVAILABLE",
                        ": canonical updater WAL chain could not be verified"
                    ))?
                }
            };
            print!("{}", render_updater_status(&projection));
            Ok(())
        }
        UpdaterAction::Check => crate::cli::update::run_update(canonical_check_args(output)).await,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdaterAuditEvent {
    Fired(UpdaterTaskFiredPayload),
    Result(UpdaterTaskResultPayload),
}

impl UpdaterAuditEvent {
    fn task_kind(&self) -> UpdaterTaskKind {
        match self {
            Self::Fired(payload) => payload.task_kind,
            Self::Result(payload) => payload.task_kind,
        }
    }

    fn identity(&self) -> &UpdaterPassIdentity {
        match self {
            Self::Fired(payload) => &payload.identity,
            Self::Result(payload) => &payload.identity,
        }
    }

    fn ts_unix(&self) -> u64 {
        match self {
            Self::Fired(payload) => payload.ts_unix,
            Self::Result(payload) => payload.ts_unix,
        }
    }
}

/// Scan one explicit WAL segment. This is intentionally diagnostic mode:
/// rotations are not followed. Missing means "no record"; an existing malformed
/// or corrupt segment is an error and never renders as a healthy empty status.
pub fn load_events_from_wal(segment_path: &Path) -> Result<Vec<UpdaterAuditEvent>> {
    load_events_from_wal_with_limits(segment_path, UpdaterStatusLimits::default())
}

fn load_events_from_wal_with_limits(
    segment_path: &Path,
    limits: UpdaterStatusLimits,
) -> Result<Vec<UpdaterAuditEvent>> {
    let Some(bytes) = read_optional_file_bounded(
        segment_path,
        crate::wal::scan::LEGACY_SAFE_MAX_SEGMENT_PHYSICAL_BYTES,
        "updater WAL segment",
    )?
    else {
        return Ok(Vec::new());
    };
    anyhow::ensure!(
        bytes.len() >= crate::wal::segment_header::SEGMENT_HEADER_LEN,
        "updater status refuses headerless WAL segment {}",
        segment_path.display()
    );
    let mut out = Vec::new();
    let mut budget = UpdaterStatusBudget::new(limits);
    for_each_status_frame_bounded(&bytes, |decoded| {
        decode_updater_event(
            decoded.header.event_type,
            decoded.payload,
            &mut budget,
            &mut out,
        )
    })
    .with_context(|| {
        format!(
            "scan updater audit frames from WAL segment {}",
            segment_path.display()
        )
    })?;
    Ok(out)
}

fn for_each_status_frame_bounded<F>(segment: &[u8], mut callback: F) -> Result<()>
where
    F: FnMut(&crate::wal::frame::DecodedFrame<'_>) -> Result<()>,
{
    let logical_limit = crate::wal::scan::HomeWalScanLimits::default().max_segment_logical_bytes;
    let (header_len, logical) =
        crate::wal::compaction::logical_segment_bytes_with_key_capped(segment, None, logical_limit)
            .context("reconstruct bounded updater WAL segment")?;
    let mut cursor = header_len;
    while cursor < logical.len() {
        let decoded = match crate::wal::frame::decode_frame(&logical[cursor..]) {
            Ok(decoded) => decoded,
            Err(crate::wal::error::HeaderParseError::BufferTooShort { .. }) => break,
            Err(error) => {
                anyhow::bail!(
                    "updater status found a tamper-suspect frame at logical offset {cursor}: {error}"
                );
            }
        };
        let frame_len = decoded.header.total_len as usize;
        anyhow::ensure!(
            frame_len != 0,
            "updater status found a zero-length WAL frame at logical offset {cursor}"
        );
        callback(&decoded)?;
        cursor = cursor
            .checked_add(frame_len)
            .context("updater status WAL cursor overflow")?;
    }
    Ok(())
}

fn project_updater_status_from_wal(segment_path: &Path) -> Result<UpdaterStatusProjection> {
    let Some(bytes) = read_optional_file_bounded(
        segment_path,
        crate::wal::scan::LEGACY_SAFE_MAX_SEGMENT_PHYSICAL_BYTES,
        "updater WAL segment",
    )?
    else {
        return StreamingUpdaterProjection::new(StreamingProjectionLimits::default()).finish();
    };
    anyhow::ensure!(
        bytes.len() >= crate::wal::segment_header::SEGMENT_HEADER_LEN,
        "updater status refuses headerless WAL segment {}",
        segment_path.display()
    );
    let mut projection = StreamingUpdaterProjection::new(StreamingProjectionLimits::default());
    for_each_status_frame_bounded(&bytes, |decoded| {
        observe_decoded_status_frame(&mut projection, decoded)
    })
    .with_context(|| {
        format!(
            "stream updater status from WAL segment {}",
            segment_path.display()
        )
    })?;
    projection.finish()
}

fn project_updater_status_from_home(home: &Path) -> Result<UpdaterStatusProjection> {
    project_updater_status_from_home_chain(home, &home.join("wal").join("000001.wal"))
}

fn project_updater_status_from_home_chain(
    home: &Path,
    base: &Path,
) -> Result<UpdaterStatusProjection> {
    let wal_dir = home.join("wal");
    match std::fs::symlink_metadata(&wal_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A home with no WAL directory has never initialized audit
            // storage, so "no pass on record yet" is truthful bootstrap state.
            // Once `wal/` exists, however, the selected canonical base must
            // exist and authenticate; the scanner below enforces that stricter
            // audit contract.
            return StreamingUpdaterProjection::new(StreamingProjectionLimits::default()).finish();
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect updater WAL root {}", wal_dir.display()));
        }
        Ok(_) => {}
    }
    let mut projection = StreamingUpdaterProjection::new(StreamingProjectionLimits::default());
    crate::wal::scan::for_each_frame_in_existing_home_segment_chain(
        home,
        base,
        crate::wal::scan::supported_home_scan_limits(),
        |_, decoded| observe_decoded_status_frame(&mut projection, decoded),
    )
    .with_context(|| {
        format!(
            "tamper-suspect or unreadable canonical updater WAL chain rooted at {}",
            base.display()
        )
    })?;
    projection.finish()
}

fn observe_decoded_status_frame(
    projection: &mut StreamingUpdaterProjection,
    decoded: &crate::wal::frame::DecodedFrame<'_>,
) -> Result<()> {
    if decoded.header.event_type == EVENT_TYPE_BOOT {
        return projection.observe_boot_boundary();
    }
    if let Some(event) = decode_updater_event_value(
        decoded.header.event_type,
        decoded.payload,
        MAX_UPDATER_STATUS_SINGLE_PAYLOAD_BYTES,
        MAX_UPDATER_STATUS_COMPONENTS_PER_RESULT,
    )? {
        if event.identity().correlatable_pass_id().is_some() {
            anyhow::ensure!(
                decoded.header.flags == crate::wal::EventFlags::SYNTHETIC,
                "schema-v3 updater audit record carries forbidden WAL flags {:?}",
                decoded.header.flags
            );
        }
        let fired_receipt_sha256 = matches!(&event, UpdaterAuditEvent::Fired(_))
            .then(|| updater_fired_receipt_sha256(decoded.payload));
        projection.observe_with_fired_receipt(event, fired_receipt_sha256)?;
    }
    Ok(())
}

fn project_updater_status_from_jsonl(path: &Path) -> Result<UpdaterStatusProjection> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return StreamingUpdaterProjection::new(StreamingProjectionLimits::default()).finish();
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("open updater JSONL input {}", path.display()));
        }
    };
    let mut reader = std::io::BufReader::new(file);
    let mut line = Vec::new();
    let mut line_number = 0usize;
    let max_buffered_line = MAX_UPDATER_STATUS_SINGLE_PAYLOAD_BYTES
        .checked_add(2)
        .context("updater JSONL line limit overflow")?;
    let mut projection = StreamingUpdaterProjection::new(StreamingProjectionLimits::default());
    while read_line_bounded(&mut reader, &mut line, max_buffered_line)
        .with_context(|| format!("read updater JSONL input {}", path.display()))?
    {
        line_number = line_number
            .checked_add(1)
            .context("updater JSONL line counter overflow")?;
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let event = decode_updater_event_value(
            EVENT_TYPE_UPDATER_TASK_RESULT,
            &line,
            MAX_UPDATER_STATUS_SINGLE_PAYLOAD_BYTES,
            MAX_UPDATER_STATUS_COMPONENTS_PER_RESULT,
        )
        .with_context(|| format!("decode updater JSONL line {line_number}"))?
        .expect("RESULT event type always decodes an updater event");
        projection.observe(event)?;
    }
    projection.finish()
}

fn read_line_bounded<R: BufRead>(
    reader: &mut R,
    line: &mut Vec<u8>,
    max_buffered_bytes: usize,
) -> Result<bool> {
    line.clear();
    loop {
        let available = reader.fill_buf().context("fill updater JSONL buffer")?;
        if available.is_empty() {
            return Ok(!line.is_empty());
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        let next_len = line
            .len()
            .checked_add(take)
            .context("updater JSONL line length overflow")?;
        anyhow::ensure!(
            next_len <= max_buffered_bytes,
            "updater JSONL line exceeds the {max_buffered_bytes}-byte buffered-line limit"
        );
        let found_newline = available.get(take.saturating_sub(1)) == Some(&b'\n');
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if found_newline {
            return Ok(true);
        }
    }
}

/// Materializing compatibility helper for tests/embedders. It reads the
/// canonical rotating chain but fails closed at the explicit materialization
/// limits above. The production Status command uses the streaming fold.
pub fn load_events_from_home(home: &Path) -> Result<Vec<UpdaterAuditEvent>> {
    load_events_from_home_with_limits(home, UpdaterStatusLimits::default())
}

fn load_events_from_home_with_limits(
    home: &Path,
    limits: UpdaterStatusLimits,
) -> Result<Vec<UpdaterAuditEvent>> {
    let wal_dir = home.join("wal");
    match std::fs::symlink_metadata(&wal_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect updater WAL root {}", wal_dir.display()));
        }
        Ok(_) => {}
    }
    let base = wal_dir.join("000001.wal");
    let mut out = Vec::new();
    let mut budget = UpdaterStatusBudget::new(limits);
    crate::wal::scan::for_each_frame_in_home_segment_chain(
        home,
        &base,
        crate::wal::scan::supported_home_scan_limits(),
        |_, decoded| {
            decode_updater_event(
                decoded.header.event_type,
                decoded.payload,
                &mut budget,
                &mut out,
            )
        },
    )
    .with_context(|| {
        format!(
            "tamper-suspect or unreadable canonical updater WAL chain rooted at {}",
            base.display()
        )
    })?;
    Ok(out)
}

fn decode_updater_event(
    event_type: u8,
    payload: &[u8],
    budget: &mut UpdaterStatusBudget,
    out: &mut Vec<UpdaterAuditEvent>,
) -> Result<()> {
    if matches!(
        event_type,
        EVENT_TYPE_UPDATER_TASK_FIRED | EVENT_TYPE_UPDATER_TASK_RESULT
    ) {
        budget.admit_payload(payload.len())?;
    }
    if let Some(event) = decode_updater_event_value(
        event_type,
        payload,
        budget.limits.max_single_payload_bytes,
        budget.limits.max_components_per_result,
    )? {
        out.push(event);
    }
    Ok(())
}

fn decode_updater_event_value(
    event_type: u8,
    payload: &[u8],
    max_single_payload_bytes: usize,
    max_components_per_result: usize,
) -> Result<Option<UpdaterAuditEvent>> {
    if !matches!(
        event_type,
        EVENT_TYPE_UPDATER_TASK_FIRED | EVENT_TYPE_UPDATER_TASK_RESULT
    ) {
        return Ok(None);
    }
    anyhow::ensure!(
        payload.len() <= max_single_payload_bytes,
        "updater status payload exceeds the {max_single_payload_bytes}-byte per-event memory limit"
    );
    match event_type {
        EVENT_TYPE_UPDATER_TASK_FIRED => {
            let payload = serde_json::from_slice::<UpdaterTaskFiredPayload>(payload)
                .context("decode UPDATER_TASK_FIRED payload")?;
            Ok(Some(UpdaterAuditEvent::Fired(payload)))
        }
        EVENT_TYPE_UPDATER_TASK_RESULT => {
            let payload = serde_json::from_slice::<UpdaterTaskResultPayload>(payload)
                .context("decode UPDATER_TASK_RESULT payload")?;
            anyhow::ensure!(
                payload.components.len() <= max_components_per_result,
                "updater status RESULT exceeds the {}-component memory limit",
                max_components_per_result
            );
            Ok(Some(UpdaterAuditEvent::Result(payload)))
        }
        _ => unreachable!("updater event type was checked above"),
    }
}

/// Backward-compatible result-only diagnostic helper.
pub fn load_results_from_wal(segment_path: &Path) -> Result<Vec<UpdaterTaskResultPayload>> {
    Ok(load_events_from_wal(segment_path)?
        .into_iter()
        .filter_map(|event| match event {
            UpdaterAuditEvent::Result(payload) => Some(payload),
            UpdaterAuditEvent::Fired(_) => None,
        })
        .collect())
}

/// Materializing compatibility helper for synthetic result JSONL. Malformed
/// lines and the explicit materialization limits fail closed. Production
/// Status streams the file line-by-line.
pub fn load_events_from_jsonl(path: &Path) -> Result<Vec<UpdaterAuditEvent>> {
    load_events_from_jsonl_with_limits(path, UpdaterStatusLimits::default())
}

fn load_events_from_jsonl_with_limits(
    path: &Path,
    limits: UpdaterStatusLimits,
) -> Result<Vec<UpdaterAuditEvent>> {
    let Some(body) =
        read_optional_file_bounded(path, limits.max_jsonl_bytes, "updater JSONL input")?
    else {
        return Ok(Vec::new());
    };
    let body = std::str::from_utf8(&body).context("updater JSONL input is not valid UTF-8")?;
    let mut budget = UpdaterStatusBudget::new(limits);
    let mut out = Vec::new();
    for (index, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        budget
            .admit_payload(line.len())
            .with_context(|| format!("admit updater JSONL line {}", index + 1))?;
        let payload = serde_json::from_str::<UpdaterTaskResultPayload>(line)
            .with_context(|| format!("decode updater JSONL line {}", index + 1))?;
        anyhow::ensure!(
            payload.components.len() <= limits.max_components_per_result,
            "updater JSONL line {} exceeds the {}-component memory limit",
            index + 1,
            limits.max_components_per_result
        );
        out.push(UpdaterAuditEvent::Result(payload));
    }
    Ok(out)
}

fn read_optional_file_bounded(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<Option<Vec<u8>>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("open {label} {}", path.display()));
        }
    };
    let read_ceiling = max_bytes
        .checked_add(1)
        .context("updater status input-byte ceiling overflow")?;
    let read_ceiling =
        u64::try_from(read_ceiling).context("updater status input-byte ceiling exceeds u64")?;
    let mut bytes = Vec::with_capacity(max_bytes.min(1024 * 1024));
    file.take(read_ceiling)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label} {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() <= max_bytes,
        "{label} {} exceeds the {max_bytes}-byte input limit",
        path.display()
    );
    Ok(Some(bytes))
}

pub fn load_results_from_jsonl(path: &Path) -> Result<Vec<UpdaterTaskResultPayload>> {
    Ok(load_events_from_jsonl(path)?
        .into_iter()
        .filter_map(|event| match event {
            UpdaterAuditEvent::Result(payload) => Some(payload),
            UpdaterAuditEvent::Fired(_) => None,
        })
        .collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdaterRunPhase {
    Fired,
    Completed,
    Failed,
    SkippedByGate,
    Interrupted,
    Cancelled,
    TimedOut,
    Indeterminate,
}

impl UpdaterRunPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Fired => "fired",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::SkippedByGate => "skipped_by_gate",
            Self::Interrupted => "interrupted",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdaterRunStatus {
    pub task_kind: UpdaterTaskKind,
    pub identity: UpdaterPassIdentity,
    pub phase: UpdaterRunPhase,
    pub ts_unix: u64,
    pub result: Option<UpdaterTaskResultPayload>,
    pub fired_receipt_sha256: Option<String>,
    pub note: String,
    first_ordinal: usize,
    last_ordinal: usize,
}

impl UpdaterRunStatus {
    fn indeterminate(event: UpdaterAuditEvent, ordinal: usize, note: impl Into<String>) -> Self {
        let task_kind = event.task_kind();
        let identity = event.identity().clone();
        let ts_unix = event.ts_unix();
        let fired_receipt_sha256 = match &event {
            UpdaterAuditEvent::Fired(payload) => serde_json::to_vec(payload)
                .ok()
                .map(|body| updater_fired_receipt_sha256(&body)),
            UpdaterAuditEvent::Result(payload) => payload.fired_receipt_sha256.clone(),
        };
        let result = match event {
            UpdaterAuditEvent::Fired(_) => None,
            UpdaterAuditEvent::Result(payload) => Some(payload),
        };
        Self {
            task_kind,
            identity,
            phase: UpdaterRunPhase::Indeterminate,
            ts_unix,
            result,
            fired_receipt_sha256,
            note: note.into(),
            first_ordinal: ordinal,
            last_ordinal: ordinal,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UpdaterStatusProjection {
    /// Exactly one latest observed run/event for each concrete lane/task key.
    /// Legacy records have no lane and therefore retain one task-only key.
    pub latest: Vec<UpdaterRunStatus>,
    /// Correlatable FIRED passes with no terminal RESULT at end of the chain.
    pub open_runs: Vec<UpdaterRunStatus>,
    /// Newest retained FIRED records proven stale by a later serialized pass
    /// or daemon BOOT boundary. `interrupted_run_count` remains complete.
    pub interrupted_runs: Vec<UpdaterRunStatus>,
    /// Complete number of interrupted FIRED records.
    pub interrupted_run_count: usize,
    /// Newest retained legacy, unmatched, duplicated or identity-conflicting
    /// audit records. `indeterminate_run_count` is the complete count.
    pub indeterminate_runs: Vec<UpdaterRunStatus>,
    /// Complete count, including older anomaly details evicted from the view.
    pub indeterminate_run_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct StreamingProjectionLimits {
    max_open_passes: usize,
    recent_identity_window: usize,
    retained_anomalies: usize,
}

impl Default for StreamingProjectionLimits {
    fn default() -> Self {
        Self {
            max_open_passes: MAX_UPDATER_STATUS_OPEN_PASSES,
            recent_identity_window: UPDATER_STATUS_RECENT_IDENTITY_WINDOW,
            retained_anomalies: UPDATER_STATUS_RETAINED_ANOMALIES,
        }
    }
}

#[derive(Debug, Clone)]
struct RecentPass {
    task_kind: UpdaterTaskKind,
    identity: UpdaterPassIdentity,
    ts_unix: u64,
    fired_receipt_sha256: Option<String>,
    first_ordinal: usize,
    last_ordinal: usize,
    poisoned: bool,
}

impl RecentPass {
    fn from_run(run: &UpdaterRunStatus, poisoned: bool) -> Self {
        Self {
            task_kind: run.task_kind,
            identity: run.identity.clone(),
            ts_unix: run.ts_unix,
            fired_receipt_sha256: run.fired_receipt_sha256.clone(),
            first_ordinal: run.first_ordinal,
            last_ordinal: run.last_ordinal,
            poisoned,
        }
    }

    fn indeterminate(&self, note: &str) -> UpdaterRunStatus {
        UpdaterRunStatus {
            task_kind: self.task_kind,
            identity: self.identity.clone(),
            phase: UpdaterRunPhase::Indeterminate,
            ts_unix: self.ts_unix,
            result: None,
            fired_receipt_sha256: self.fired_receipt_sha256.clone(),
            note: note.to_string(),
            first_ordinal: self.first_ordinal,
            last_ordinal: self.last_ordinal,
        }
    }
}

struct StreamingUpdaterProjection {
    limits: StreamingProjectionLimits,
    next_ordinal: usize,
    active: HashMap<String, UpdaterRunStatus>,
    recent: HashMap<String, RecentPass>,
    recent_order: VecDeque<String>,
    latest: BTreeMap<(UpdaterTaskKind, Option<UpdaterPassLane>), UpdaterRunStatus>,
    latest_uncorrelatable: BTreeMap<UpdaterTaskKind, UpdaterRunStatus>,
    correlated_tasks: BTreeSet<UpdaterTaskKind>,
    last_admitted_fired_by_task: BTreeMap<UpdaterTaskKind, usize>,
    interrupted_count: usize,
    interrupted_recent: VecDeque<UpdaterRunStatus>,
    indeterminate_count: usize,
    indeterminate_recent: VecDeque<UpdaterRunStatus>,
}

impl StreamingUpdaterProjection {
    fn new(limits: StreamingProjectionLimits) -> Self {
        Self {
            limits,
            next_ordinal: 0,
            active: HashMap::new(),
            recent: HashMap::new(),
            recent_order: VecDeque::new(),
            latest: BTreeMap::new(),
            latest_uncorrelatable: BTreeMap::new(),
            correlated_tasks: BTreeSet::new(),
            last_admitted_fired_by_task: BTreeMap::new(),
            interrupted_count: 0,
            interrupted_recent: VecDeque::new(),
            indeterminate_count: 0,
            indeterminate_recent: VecDeque::new(),
        }
    }

    fn observe(&mut self, event: UpdaterAuditEvent) -> Result<()> {
        self.observe_with_fired_receipt(event, None)
    }

    fn observe_with_fired_receipt(
        &mut self,
        event: UpdaterAuditEvent,
        durable_fired_receipt_sha256: Option<String>,
    ) -> Result<()> {
        let ordinal = self.next_ordinal;
        self.next_ordinal = self
            .next_ordinal
            .checked_add(1)
            .context("updater status event ordinal overflow")?;
        let task_kind = event.task_kind();
        let Some(pass_id) = event
            .identity()
            .correlatable_pass_id_for(task_kind)
            .map(str::to_owned)
        else {
            let note = format!(
                "schema v{} record is legacy, malformed, or lane/task-inconsistent; FIRED/RESULT pairing is unknown",
                event.identity().schema_version
            );
            let run = UpdaterRunStatus::indeterminate(event, ordinal, note);
            self.set_latest(&run);
            self.record_indeterminate(run)?;
            return Ok(());
        };
        self.correlated_tasks.insert(task_kind);

        match event {
            UpdaterAuditEvent::Fired(payload) => {
                if self.active.contains_key(&pass_id) || self.recent.contains_key(&pass_id) {
                    self.poison_seen_pass(
                        &pass_id,
                        UpdaterAuditEvent::Fired(payload),
                        ordinal,
                        "duplicate pass id observed; correlation is poisoned",
                    )?;
                    return Ok(());
                }
                anyhow::ensure!(
                    self.active.len() < self.limits.max_open_passes,
                    "updater status exceeds the {} simultaneous-open-pass memory limit; no FIRED record was evicted",
                    self.limits.max_open_passes
                );
                let fired_receipt_sha256 = match durable_fired_receipt_sha256 {
                    Some(receipt) => receipt,
                    None => {
                        let fired_body = serde_json::to_vec(&payload)
                            .context("canonicalize updater FIRED receipt for status projection")?;
                        updater_fired_receipt_sha256(&fired_body)
                    }
                };
                let run = UpdaterRunStatus {
                    task_kind: payload.task_kind,
                    identity: payload.identity,
                    phase: UpdaterRunPhase::Fired,
                    ts_unix: payload.ts_unix,
                    result: None,
                    fired_receipt_sha256: Some(fired_receipt_sha256),
                    note: "terminal RESULT not observed".to_string(),
                    first_ordinal: ordinal,
                    last_ordinal: ordinal,
                };
                self.set_latest(&run);
                self.active.insert(pass_id, run);
                self.last_admitted_fired_by_task.insert(task_kind, ordinal);
            }
            UpdaterAuditEvent::Result(payload) => {
                if let Some(mut run) = self.active.remove(&pass_id) {
                    let receipt_matches =
                        run.fired_receipt_sha256.as_deref() == payload.correlatable_fired_receipt();
                    if run.task_kind != payload.task_kind
                        || run.identity != payload.identity
                        || !receipt_matches
                    {
                        self.poison_removed_active(
                            &pass_id,
                            run,
                            UpdaterAuditEvent::Result(payload),
                            ordinal,
                            "RESULT identity or FIRED receipt conflicts with its durable FIRED",
                        )?;
                        return Ok(());
                    }
                    run.phase = match payload
                        .terminal_outcome
                        .expect("correlatable RESULT has a typed terminal outcome")
                    {
                        UpdaterTerminalOutcome::Completed => UpdaterRunPhase::Completed,
                        UpdaterTerminalOutcome::Failed => UpdaterRunPhase::Failed,
                        UpdaterTerminalOutcome::SkippedByGate => UpdaterRunPhase::SkippedByGate,
                        UpdaterTerminalOutcome::Interrupted => UpdaterRunPhase::Interrupted,
                        UpdaterTerminalOutcome::Cancelled => UpdaterRunPhase::Cancelled,
                        UpdaterTerminalOutcome::TimedOut => UpdaterRunPhase::TimedOut,
                        UpdaterTerminalOutcome::Indeterminate => UpdaterRunPhase::Indeterminate,
                    };
                    run.ts_unix = payload.ts_unix;
                    run.result = Some(payload);
                    run.note.clear();
                    run.last_ordinal = ordinal;
                    self.set_latest(&run);
                    self.insert_recent(pass_id, RecentPass::from_run(&run, false));
                } else if self.recent.contains_key(&pass_id) {
                    self.poison_seen_pass(
                        &pass_id,
                        UpdaterAuditEvent::Result(payload),
                        ordinal,
                        "duplicate or identity-conflicting RESULT poisoned correlation",
                    )?;
                } else {
                    let run = UpdaterRunStatus::indeterminate(
                        UpdaterAuditEvent::Result(payload),
                        ordinal,
                        "RESULT has no preceding matching FIRED",
                    );
                    self.set_latest(&run);
                    self.record_indeterminate(run.clone())?;
                    self.insert_recent(pass_id, RecentPass::from_run(&run, true));
                }
            }
        }
        Ok(())
    }

    fn observe_boot_boundary(&mut self) -> Result<()> {
        let ordinal = self.next_ordinal;
        self.next_ordinal = self
            .next_ordinal
            .checked_add(1)
            .context("updater status event ordinal overflow")?;
        let mut interrupted = std::mem::take(&mut self.active)
            .into_iter()
            .collect::<Vec<_>>();
        interrupted.sort_by_key(|(_, run)| (run.last_ordinal, run.first_ordinal));
        for (pass_id, mut run) in interrupted {
            run.phase = UpdaterRunPhase::Interrupted;
            run.note = "no RESULT before a later daemon BOOT boundary".to_string();
            run.last_ordinal = ordinal;
            self.update_latest_state_if_same(&run);
            self.record_interrupted(run.clone())?;
            self.insert_recent(pass_id, RecentPass::from_run(&run, false));
        }
        Ok(())
    }

    fn poison_removed_active(
        &mut self,
        pass_id: &str,
        mut prior: UpdaterRunStatus,
        current: UpdaterAuditEvent,
        ordinal: usize,
        note: &str,
    ) -> Result<()> {
        prior.phase = UpdaterRunPhase::Indeterminate;
        prior.note = note.to_string();
        self.update_latest_state_if_same(&prior);
        self.record_indeterminate(prior.clone())?;
        self.insert_recent(pass_id.to_string(), RecentPass::from_run(&prior, true));
        let current = UpdaterRunStatus::indeterminate(current, ordinal, note);
        self.set_latest(&current);
        self.record_indeterminate(current)
    }

    fn poison_seen_pass(
        &mut self,
        pass_id: &str,
        current: UpdaterAuditEvent,
        ordinal: usize,
        note: &str,
    ) -> Result<()> {
        if let Some(prior) = self.active.remove(pass_id) {
            self.poison_removed_active(pass_id, prior, current, ordinal, note)?;
            return Ok(());
        }

        let prior = self.recent.get(pass_id).cloned();
        if let Some(prior) = prior
            && !prior.poisoned
        {
            let prior_run = prior.indeterminate(note);
            self.update_latest_state_if_same(&prior_run);
            self.record_indeterminate(prior_run)?;
        }
        if let Some(prior) = self.recent.get_mut(pass_id) {
            prior.poisoned = true;
        }
        let current = UpdaterRunStatus::indeterminate(current, ordinal, note);
        self.set_latest(&current);
        self.record_indeterminate(current)
    }

    fn set_latest(&mut self, run: &UpdaterRunStatus) {
        let lane = run
            .identity
            .correlatable_pass_id_for(run.task_kind)
            .and(run.identity.lane);
        if let Some(lane) = lane {
            self.latest.insert((run.task_kind, Some(lane)), run.clone());
        } else {
            self.latest_uncorrelatable
                .insert(run.task_kind, run.clone());
        }
    }

    fn update_latest_state_if_same(&mut self, run: &UpdaterRunStatus) {
        let Some(lane) = run
            .identity
            .correlatable_pass_id_for(run.task_kind)
            .and(run.identity.lane)
        else {
            return;
        };
        if let Some(latest) = self.latest.get_mut(&(run.task_kind, Some(lane)))
            && latest.identity == run.identity
        {
            latest.phase = run.phase;
            latest.note.clone_from(&run.note);
        }
    }

    fn insert_recent(&mut self, pass_id: String, recent: RecentPass) {
        if self.limits.recent_identity_window == 0 {
            return;
        }
        if let Some(existing) = self.recent.get_mut(&pass_id) {
            *existing = recent;
            return;
        }
        while self.recent.len() >= self.limits.recent_identity_window {
            let Some(evicted) = self.recent_order.pop_front() else {
                break;
            };
            self.recent.remove(&evicted);
        }
        self.recent_order.push_back(pass_id.clone());
        self.recent.insert(pass_id, recent);
    }

    fn record_interrupted(&mut self, run: UpdaterRunStatus) -> Result<()> {
        self.interrupted_count = self
            .interrupted_count
            .checked_add(1)
            .context("updater interrupted-run counter overflow")?;
        push_bounded(
            &mut self.interrupted_recent,
            run,
            self.limits.retained_anomalies,
        );
        Ok(())
    }

    fn record_indeterminate(&mut self, run: UpdaterRunStatus) -> Result<()> {
        self.indeterminate_count = self
            .indeterminate_count
            .checked_add(1)
            .context("updater indeterminate-run counter overflow")?;
        push_bounded(
            &mut self.indeterminate_recent,
            run,
            self.limits.retained_anomalies,
        );
        Ok(())
    }

    fn finish(mut self) -> Result<UpdaterStatusProjection> {
        let mut active = std::mem::take(&mut self.active)
            .into_values()
            .collect::<Vec<_>>();
        active.sort_by_key(|run| (run.last_ordinal, run.first_ordinal));
        let mut open_runs = Vec::new();
        for mut run in active {
            if self
                .last_admitted_fired_by_task
                .get(&run.task_kind)
                .is_some_and(|last| *last > run.last_ordinal)
            {
                run.phase = UpdaterRunPhase::Interrupted;
                run.note = "no RESULT before a later pass for the same task".to_string();
                self.update_latest_state_if_same(&run);
                self.record_interrupted(run)?;
            } else {
                open_runs.push(run);
            }
        }
        open_runs.sort_by_key(|run| (run.last_ordinal, run.first_ordinal));

        for (task_kind, run) in self.latest_uncorrelatable {
            if !self.correlated_tasks.contains(&task_kind) {
                self.latest.insert((task_kind, None), run);
            }
        }
        Ok(UpdaterStatusProjection {
            latest: self.latest.into_values().collect(),
            open_runs,
            interrupted_runs: self.interrupted_recent.into_iter().collect(),
            interrupted_run_count: self.interrupted_count,
            indeterminate_runs: self.indeterminate_recent.into_iter().collect(),
            indeterminate_run_count: self.indeterminate_count,
        })
    }
}

fn push_bounded<T>(items: &mut VecDeque<T>, item: T, limit: usize) {
    if limit == 0 {
        return;
    }
    while items.len() >= limit {
        items.pop_front();
    }
    items.push_back(item);
}

/// Deterministic, bounded FIRED/RESULT fold over physical WAL order.
///
/// Timestamp ordering is deliberately ignored: clocks can move backwards.
/// Completed payloads are discarded as soon as a newer lane state replaces
/// them. Every unresolved FIRED remains active until its exact RESULT arrives
/// or end-of-scan proves it interrupted. Recent terminal identities retain a
/// bounded duplicate-detection window; no active FIRED is silently evicted.
pub fn project_updater_status(events: Vec<UpdaterAuditEvent>) -> Result<UpdaterStatusProjection> {
    let mut projection = StreamingUpdaterProjection::new(StreamingProjectionLimits::default());
    for event in events {
        projection.observe(event)?;
    }
    projection.finish()
}

pub fn render_updater_status(projection: &UpdaterStatusProjection) -> String {
    if projection.latest.is_empty() {
        return "neoth updater status — no updater pass on record yet.\n\
                Run `neoth updater check` to bootstrap.\n"
            .to_string();
    }

    let mut out = String::from("neoth updater status\n====================\n");
    for run in &projection.latest {
        render_run(&mut out, run);
    }
    if !projection.open_runs.is_empty() {
        out.push_str(&format!("\nopen runs: {}\n", projection.open_runs.len()));
        for run in &projection.open_runs {
            out.push_str(&format!(
                "  {} run={} lane={} epoch={} policy_sha256={} fired_ts={}\n",
                run.task_kind.as_str(),
                pass_label(&run.identity),
                lane_label(&run.identity),
                epoch_label(&run.identity),
                policy_label(&run.identity),
                run.ts_unix,
            ));
        }
    }
    if projection.interrupted_run_count != 0 {
        out.push_str(&format!(
            "\ninterrupted runs: {} (later pass or daemon BOOT observed; newest 10 shown)\n",
            projection.interrupted_run_count
        ));
        for run in &projection.interrupted_runs {
            out.push_str(&format!(
                "  {} run={} lane={} epoch={} policy_sha256={} fired_ts={}\n",
                run.task_kind.as_str(),
                pass_label(&run.identity),
                lane_label(&run.identity),
                epoch_label(&run.identity),
                policy_label(&run.identity),
                run.ts_unix,
            ));
        }
    }
    if projection.indeterminate_run_count != 0 {
        out.push_str(&format!(
            "\nindeterminate audit records: {} (no guessed pairing; newest 10 shown)\n",
            projection.indeterminate_run_count
        ));
        for run in &projection.indeterminate_runs {
            out.push_str(&format!(
                "  {} ts={} run={} — {}\n",
                run.task_kind.as_str(),
                run.ts_unix,
                pass_label(&run.identity),
                run.note,
            ));
        }
    }
    out
}

fn render_run(out: &mut String, run: &UpdaterRunStatus) {
    out.push_str(&format!(
        "\n[{}] state={} ts={} run={} lane={} epoch={} policy_sha256={}\n",
        run.task_kind.as_str(),
        run.phase.as_str(),
        run.ts_unix,
        pass_label(&run.identity),
        lane_label(&run.identity),
        epoch_label(&run.identity),
        policy_label(&run.identity),
    ));
    if let Some(receipt) = &run.fired_receipt_sha256 {
        out.push_str(&format!("  fired_receipt_sha256: {receipt}\n"));
    }
    if !run.note.is_empty() {
        out.push_str(&format!("  note: {}\n", run.note));
    }
    let Some(result) = &run.result else {
        return;
    };
    out.push_str(&format!("  duration={}ms\n", result.duration_ms));
    if result.is_uneventful() {
        out.push_str(&format!(
            "  all {} components up to date\n",
            result.up_to_date_count()
        ));
        return;
    }
    for component in &result.components {
        let symbol = match component.status {
            ComponentStatus::UpToDate => "·",
            ComponentStatus::Upgraded => "↑",
            ComponentStatus::UpdateAvailable => "!",
            ComponentStatus::Staged => "↓",
            ComponentStatus::Failed => "✗",
            ComponentStatus::SkippedByGate => "⊘",
        };
        match &component.new_version {
            Some(new) => out.push_str(&format!(
                "  {symbol} {} {} → {new} [{}]\n",
                component.name,
                component.prior_version,
                component.status.as_str(),
            )),
            None => out.push_str(&format!(
                "  {symbol} {} {} [{}]\n",
                component.name,
                component.prior_version,
                component.status.as_str(),
            )),
        }
        if !component.note.is_empty() {
            out.push_str(&format!("      note: {}\n", component.note));
        }
    }
}

fn pass_label(identity: &UpdaterPassIdentity) -> &str {
    identity.correlatable_pass_id().unwrap_or("uncorrelatable")
}

fn lane_label(identity: &UpdaterPassIdentity) -> &str {
    identity.lane.map(|lane| lane.as_str()).unwrap_or("unknown")
}

fn epoch_label(identity: &UpdaterPassIdentity) -> String {
    identity
        .accepted_epoch
        .map(|epoch| epoch.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn policy_label(identity: &UpdaterPassIdentity) -> &str {
    identity
        .accepted_policy_sha256
        .as_deref()
        .unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::payloads_u04::{
        ComponentOutcome, UpdaterPassLane, UpdaterTaskFiredPayload, UpdaterTaskKind,
    };

    fn sample_result() -> UpdaterTaskResultPayload {
        UpdaterTaskResultPayload {
            identity: UpdaterPassIdentity::legacy(),
            task_kind: UpdaterTaskKind::CliVersions,
            ts_unix: 100,
            duration_ms: 500,
            terminal_outcome: None,
            fired_receipt_sha256: None,
            components: vec![
                ComponentOutcome::up_to_date("claude-cli", "1.2.3"),
                ComponentOutcome::upgraded("codex", "0.4.0", "0.5.0"),
            ],
        }
    }

    fn fired(
        identity: &UpdaterPassIdentity,
        task_kind: UpdaterTaskKind,
        ts_unix: u64,
    ) -> UpdaterAuditEvent {
        UpdaterAuditEvent::Fired(UpdaterTaskFiredPayload {
            identity: identity.clone(),
            task_kind,
            ts_unix,
        })
    }

    fn result(
        identity: &UpdaterPassIdentity,
        task_kind: UpdaterTaskKind,
        ts_unix: u64,
        component: ComponentOutcome,
    ) -> UpdaterAuditEvent {
        let fired_payload = UpdaterTaskFiredPayload {
            identity: identity.clone(),
            task_kind,
            ts_unix: ts_unix.saturating_sub(1),
        };
        let fired_receipt_sha256 =
            updater_fired_receipt_sha256(&serde_json::to_vec(&fired_payload).unwrap());
        let terminal_outcome = match component.status {
            ComponentStatus::Failed => UpdaterTerminalOutcome::Failed,
            ComponentStatus::SkippedByGate => UpdaterTerminalOutcome::SkippedByGate,
            _ => UpdaterTerminalOutcome::Completed,
        };
        UpdaterAuditEvent::Result(UpdaterTaskResultPayload {
            identity: identity.clone(),
            task_kind,
            ts_unix,
            duration_ms: 10,
            terminal_outcome: Some(terminal_outcome),
            fired_receipt_sha256: Some(fired_receipt_sha256),
            components: vec![component],
        })
    }

    fn write_test_segment(
        home: &Path,
        sequence: u64,
        events: &[UpdaterAuditEvent],
        compressed: bool,
    ) {
        write_test_segment_in_namespace(home, None, sequence, events, compressed);
    }

    fn write_test_segment_in_namespace(
        home: &Path,
        namespace: Option<&str>,
        sequence: u64,
        events: &[UpdaterAuditEvent],
        compressed: bool,
    ) {
        use crate::wal::HeaderBuilder;
        use crate::wal::compress::compress_frames;
        use crate::wal::frame::encode_frame;
        use crate::wal::segment_header::{
            SEGMENT_FLAG_COMPRESSED, SEGMENT_FLAG_SEALED, SEGMENT_HEADER_V2_LEN, SegmentHeaderV2,
            parse_segment_header,
        };
        use sha2::{Digest as _, Sha256};

        const TEST_HMAC_KEY: [u8; 32] = [7; 32];
        let wal_dir = home.join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        std::fs::write(wal_dir.join("hmac.key"), TEST_HMAC_KEY).unwrap();
        let name = namespace.map_or_else(
            || format!("{sequence:06}.wal"),
            |namespace| format!("{namespace}-{sequence:06}.wal"),
        );
        let flags = if compressed {
            SEGMENT_FLAG_COMPRESSED | SEGMENT_FLAG_SEALED
        } else {
            0
        };
        let segment_header = SegmentHeaderV2::new(0, sequence, 0, sequence, [9; 16], flags);
        let segment_header_bytes = segment_header.to_le_bytes();
        let parsed_header = parse_segment_header(&segment_header_bytes).unwrap();
        let mut frames = Vec::new();

        if sequence > 1 {
            let predecessor_sequence = sequence - 1;
            let predecessor_name = namespace.map_or_else(
                || format!("{predecessor_sequence:06}.wal"),
                |namespace| format!("{namespace}-{predecessor_sequence:06}.wal"),
            );
            let predecessor_raw = std::fs::read(wal_dir.join(&predecessor_name)).unwrap();
            let predecessor_header = parse_segment_header(&predecessor_raw).unwrap();
            let (_, predecessor_logical) =
                crate::wal::compaction::logical_segment_bytes(&predecessor_raw).unwrap();
            let link_payload = serde_json::to_vec(&serde_json::json!({
                "link_domain": "neoth.wal.cross-segment.v1",
                "link_version": 1,
                "closed_segment_name": predecessor_name,
                "closed_generation": predecessor_header.generation(),
                "closed_seq": predecessor_header.segment_seq(),
                "closed_bytes": predecessor_logical.len(),
                "closed_start_ts_ns": predecessor_header.segment_start_ts_ns(),
                "closed_node_id": predecessor_header.node_id(),
                "closed_physical_bytes": predecessor_raw.len(),
                "closed_sha256_hex": hex::encode(Sha256::digest(&predecessor_raw)),
                "opened_segment_name": &name,
                "opened_generation": parsed_header.generation(),
                "opened_seq": parsed_header.segment_seq(),
                "opened_start_ts_ns": parsed_header.segment_start_ts_ns(),
                "opened_node_id": parsed_header.node_id(),
                "reason": "size",
                "ts_ns": sequence,
            }))
            .unwrap();
            let link_header = HeaderBuilder::new(
                crate::wal::events::EVENT_TYPE_SEGMENT_ROLLOVER,
                &link_payload,
            )
            .flags(crate::wal::EventFlags::SYNTHETIC)
            .build();
            let link_frame = encode_frame(&link_header, &link_payload);
            let mut link_compaction = crate::wal::compaction::CompactionState::new(
                &TEST_HMAC_KEY,
                SEGMENT_HEADER_V2_LEN as u64,
            );
            link_compaction.update(&link_frame);
            frames.extend_from_slice(&link_frame);
            let link_marker = link_compaction.finalise_marker(
                &TEST_HMAC_KEY,
                (SEGMENT_HEADER_V2_LEN + frames.len()) as u64,
            );
            let marker_payload = serde_json::to_vec(&link_marker).unwrap();
            let marker_header = HeaderBuilder::new(
                crate::wal::events::EVENT_TYPE_COMPACTION_MARKER,
                &marker_payload,
            )
            .flags(crate::wal::EventFlags::SYNTHETIC)
            .build();
            frames.extend_from_slice(&encode_frame(&marker_header, &marker_payload));
        }

        let mut compaction = crate::wal::compaction::CompactionState::new(
            &TEST_HMAC_KEY,
            (SEGMENT_HEADER_V2_LEN + frames.len()) as u64,
        );
        let mut fired_receipts = std::collections::HashMap::new();
        for event in events {
            let (event_type, body) = match event {
                UpdaterAuditEvent::Fired(payload) => {
                    let body = serde_json::to_vec(payload).unwrap();
                    if let Some(run_id) =
                        payload.identity.correlatable_pass_id_for(payload.task_kind)
                    {
                        fired_receipts
                            .insert(run_id.to_string(), updater_fired_receipt_sha256(&body));
                    }
                    (EVENT_TYPE_UPDATER_TASK_FIRED, body)
                }
                UpdaterAuditEvent::Result(payload) => {
                    let mut payload = payload.clone();
                    if let Some(run_id) =
                        payload.identity.correlatable_pass_id_for(payload.task_kind)
                    {
                        payload.fired_receipt_sha256 = Some(
                            fired_receipts
                                .get(run_id)
                                .unwrap_or_else(|| {
                                    panic!(
                                        "schema-v3 RESULT fixture {run_id} omitted its preceding FIRED"
                                    )
                                })
                                .clone(),
                        );
                    }
                    (
                        EVENT_TYPE_UPDATER_TASK_RESULT,
                        serde_json::to_vec(&payload).unwrap(),
                    )
                }
            };
            let header = HeaderBuilder::new(event_type, &body)
                .flags(crate::wal::EventFlags::SYNTHETIC)
                .build();
            let frame = encode_frame(&header, &body);
            compaction.update(&frame);
            frames.extend_from_slice(&frame);
        }
        if compaction.frames() > 0 {
            let marker = compaction.finalise_marker(
                &TEST_HMAC_KEY,
                (SEGMENT_HEADER_V2_LEN + frames.len()) as u64,
            );
            let marker_payload = serde_json::to_vec(&marker).unwrap();
            let marker_header = HeaderBuilder::new(
                crate::wal::events::EVENT_TYPE_COMPACTION_MARKER,
                &marker_payload,
            )
            .flags(crate::wal::EventFlags::SYNTHETIC)
            .build();
            frames.extend_from_slice(&encode_frame(&marker_header, &marker_payload));
        }
        let mut bytes = segment_header_bytes.to_vec();
        if compressed {
            bytes.extend_from_slice(&compress_frames(&frames).unwrap());
        } else {
            bytes.extend_from_slice(&frames);
        }
        std::fs::write(wal_dir.join(name), bytes).unwrap();
    }

    #[test]
    fn load_jsonl_missing_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("nope.jsonl");
        let r = load_results_from_jsonl(&bogus).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn load_jsonl_parses_well_formed_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("results.jsonl");
        let line = serde_json::to_string(&sample_result()).unwrap();
        std::fs::write(&path, format!("{line}\n{line}\n")).unwrap();
        let r = load_results_from_jsonl(&path).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].task_kind, UpdaterTaskKind::CliVersions);
    }

    #[test]
    fn load_jsonl_rejects_malformed_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mixed.jsonl");
        let line = serde_json::to_string(&sample_result()).unwrap();
        std::fs::write(&path, format!("{line}\nnot-json-at-all\n{line}\n")).unwrap();
        let error = load_results_from_jsonl(&path).unwrap_err();
        assert!(error.to_string().contains("line 2"), "{error:#}");
    }

    #[test]
    fn status_budget_accepts_exact_boundaries_and_rejects_one_over() {
        let identity = UpdaterPassIdentity::new(UpdaterPassLane::NeothSelfProbe, 1);
        let event = UpdaterTaskFiredPayload {
            identity,
            task_kind: UpdaterTaskKind::NeothSelf,
            ts_unix: 1,
        };
        let body = serde_json::to_vec(&event).unwrap();
        let limits = UpdaterStatusLimits {
            max_events: 1,
            max_total_payload_bytes: body.len(),
            max_single_payload_bytes: body.len(),
            max_components_per_result: 1,
            max_jsonl_bytes: body.len(),
        };
        let mut budget = UpdaterStatusBudget::new(limits);
        let mut events = Vec::new();
        decode_updater_event(
            EVENT_TYPE_UPDATER_TASK_FIRED,
            &body,
            &mut budget,
            &mut events,
        )
        .expect("the exact event and byte ceilings must be admitted");
        assert_eq!(events.len(), 1);

        let event_error = decode_updater_event(
            EVENT_TYPE_UPDATER_TASK_FIRED,
            &body,
            &mut budget,
            &mut events,
        )
        .unwrap_err();
        assert!(
            format!("{event_error:#}").contains("1-event memory limit"),
            "{event_error:#}"
        );

        let mut one_byte_short = UpdaterStatusBudget::new(UpdaterStatusLimits {
            max_single_payload_bytes: body.len() - 1,
            ..limits
        });
        let payload_error = decode_updater_event(
            EVENT_TYPE_UPDATER_TASK_FIRED,
            &body,
            &mut one_byte_short,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(
            format!("{payload_error:#}").contains("per-event memory limit"),
            "{payload_error:#}"
        );
    }

    #[test]
    fn status_budget_rejects_aggregate_payload_one_byte_over() {
        let identity = UpdaterPassIdentity::new(UpdaterPassLane::NeothSelfProbe, 2);
        let body = serde_json::to_vec(&UpdaterTaskFiredPayload {
            identity,
            task_kind: UpdaterTaskKind::NeothSelf,
            ts_unix: 2,
        })
        .unwrap();
        let limits = UpdaterStatusLimits {
            max_events: 2,
            max_total_payload_bytes: body.len() * 2 - 1,
            max_single_payload_bytes: body.len(),
            max_components_per_result: 1,
            max_jsonl_bytes: body.len() * 2,
        };
        let mut budget = UpdaterStatusBudget::new(limits);
        let mut events = Vec::new();
        decode_updater_event(
            EVENT_TYPE_UPDATER_TASK_FIRED,
            &body,
            &mut budget,
            &mut events,
        )
        .unwrap();
        let error = decode_updater_event(
            EVENT_TYPE_UPDATER_TASK_FIRED,
            &body,
            &mut budget,
            &mut events,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("aggregate payload memory limit"),
            "{error:#}"
        );
    }

    #[test]
    fn status_budget_rejects_result_component_amplification() {
        let payload = sample_result();
        let body = serde_json::to_vec(&payload).unwrap();
        let limits = UpdaterStatusLimits {
            max_events: 1,
            max_total_payload_bytes: body.len(),
            max_single_payload_bytes: body.len(),
            max_components_per_result: payload.components.len() - 1,
            max_jsonl_bytes: body.len(),
        };
        let error = decode_updater_event(
            EVENT_TYPE_UPDATER_TASK_RESULT,
            &body,
            &mut UpdaterStatusBudget::new(limits),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("component memory limit"),
            "{error:#}"
        );
    }

    #[test]
    fn jsonl_input_accepts_exact_file_cap_and_rejects_one_byte_over() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bounded.jsonl");
        let line = serde_json::to_string(&sample_result()).unwrap();
        let body = format!("{line}\n");
        std::fs::write(&path, body.as_bytes()).unwrap();
        let limits = UpdaterStatusLimits {
            max_events: 1,
            max_total_payload_bytes: line.len(),
            max_single_payload_bytes: line.len(),
            max_components_per_result: 2,
            max_jsonl_bytes: body.len(),
        };
        assert_eq!(
            load_events_from_jsonl_with_limits(&path, limits)
                .unwrap()
                .len(),
            1
        );

        let error = load_events_from_jsonl_with_limits(
            &path,
            UpdaterStatusLimits {
                max_jsonl_bytes: body.len() - 1,
                ..limits
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("input limit"), "{error:#}");
    }

    #[test]
    fn status_rejects_config_that_single_segment_mode_would_ignore() {
        use clap::Parser as _;

        let error = crate::cli::Cli::try_parse_from([
            "neoth",
            "updater",
            "status",
            "--config",
            "instance/freedom.yaml",
            "--wal-segment",
            "diagnostic-000001.wal",
        ])
        .unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[tokio::test]
    async fn run_status_with_explicit_missing_wal_prints_bootstrap_hint() {
        // Point at a tempdir-segment that doesn't exist. The WAL
        // reader returns empty + render_updater_status prints the
        // "no record yet" friendly line. No error.
        let dir = tempfile::tempdir().unwrap();
        let args = UpdaterArgs {
            action: UpdaterAction::Status {
                config: None,
                wal_chain_base: None,
                wal_segment: Some(dir.path().join("nonexistent.wal")),
                from_jsonl: None,
            },
        };
        run_updater(args, OutputFormat::Table)
            .await
            .expect("status with missing wal");
    }

    #[test]
    fn default_status_treats_a_fresh_home_without_wal_storage_as_never_run() {
        let home = tempfile::tempdir().unwrap();
        let projection = project_updater_status_from_home(home.path()).unwrap();
        assert!(projection.latest.is_empty());
        assert!(projection.open_runs.is_empty());
    }

    #[tokio::test]
    async fn default_status_fails_closed_when_wal_exists_without_canonical_chain() {
        let home = tempfile::tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir(&wal).unwrap();
        std::fs::write(wal.join("bootstrap-snapshot.wal"), b"unrelated namespace").unwrap();

        let args = UpdaterArgs {
            action: UpdaterAction::Status {
                config: Some(home.path().join("freedom.yaml")),
                wal_chain_base: None,
                wal_segment: None,
                from_jsonl: None,
            },
        };
        let error = run_updater(args, OutputFormat::Table).await.unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("UPDATER_AUDIT_UNAVAILABLE"), "{rendered}");
        assert!(
            rendered.contains("selected WAL chain has no canonical base segment"),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn run_status_with_jsonl_renders_results() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("results.jsonl");
        let line = serde_json::to_string(&sample_result()).unwrap();
        std::fs::write(&path, format!("{line}\n")).unwrap();
        let args = UpdaterArgs {
            action: UpdaterAction::Status {
                config: None,
                wal_chain_base: None,
                wal_segment: None,
                from_jsonl: Some(path),
            },
        };
        run_updater(args, OutputFormat::Table)
            .await
            .expect("status with jsonl");
    }

    #[test]
    fn load_from_wal_missing_segment_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let r = load_results_from_wal(&dir.path().join("absent.wal")).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn load_from_wal_too_short_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("short.wal");
        std::fs::write(&path, [0u8; 5]).unwrap();
        let error = load_results_from_wal(&path).unwrap_err();
        assert!(error.to_string().contains("headerless"), "{error:#}");
    }

    #[test]
    fn updater_check_delegates_to_read_only_canonical_mode() {
        let args = canonical_check_args(OutputFormat::Json);
        assert!(args.check);
        assert!(!args.apply);
        assert!(!args.list);
        assert!(!args.self_check);
        assert!(args.self_repo.is_none());
        assert!(!args.allow_unsigned);
        assert!(matches!(args.output, OutputFormat::Json));
    }

    #[tokio::test]
    async fn load_from_wal_returns_emitted_results_only() {
        // Spawn a WAL writer, emit one 0x45 UPDATER_TASK_RESULT
        // frame + one 0x10 BOOT frame, scan back. Only the 0x45
        // payload should round-trip.
        use crate::wal::events::EVENT_TYPE_BOOT;
        use crate::wal::{EventFlags, HeaderBuilder};

        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("u04-000001.wal");
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        // Emit one unrelated BOOT frame first.
        let boot_payload = b"boot";
        let boot_header = HeaderBuilder::new(EVENT_TYPE_BOOT, boot_payload).build();
        writer
            .append(boot_header, boot_payload.to_vec())
            .await
            .unwrap();

        // Emit the UPDATER_TASK_RESULT.
        let payload = sample_result();
        let body = serde_json::to_vec(&payload).unwrap();
        let header = HeaderBuilder::new(EVENT_TYPE_UPDATER_TASK_RESULT, &body)
            .flags(EventFlags::SYNTHETIC)
            .build();
        writer.append(header, body).await.unwrap();

        drop(writer);
        join.await.unwrap();

        let results = load_results_from_wal(&seg).unwrap();
        assert_eq!(results.len(), 1, "only the 0x45 frame should match");
        assert_eq!(results[0].task_kind, payload.task_kind);
        assert_eq!(results[0].ts_unix, payload.ts_unix);
    }

    #[test]
    fn load_results_from_a_v2_compressed_wal_segment() {
        // GOLD-ARCH-03 regression: UPDATER_TASK_RESULT frames inside a v2
        // (zstd-compressed) segment must be read by load_results_from_wal,
        // not silently skipped as they were before the for_each_frame
        // migration.
        use crate::wal::HeaderBuilder;
        use crate::wal::compress::compress_frames;
        use crate::wal::frame::encode_frame;
        use crate::wal::segment_header::{SEGMENT_FLAG_COMPRESSED, SegmentHeaderV2};

        let dir = tempfile::tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let sample = sample_result();
        let body = serde_json::to_vec(&sample).unwrap();
        let h = HeaderBuilder::new(EVENT_TYPE_UPDATER_TASK_RESULT, &body).build();
        let frame = encode_frame(&h, &body);

        // Finalize as a v2 compressed segment: 61-byte header + zstd(frame).
        let blob = compress_frames(&frame).unwrap();
        let hdr = SegmentHeaderV2::new(0, 1, 0, 0, [0u8; 16], SEGMENT_FLAG_COMPRESSED);
        let mut seg_bytes = hdr.to_le_bytes().to_vec();
        seg_bytes.extend_from_slice(&blob);
        std::fs::write(&seg, &seg_bytes).unwrap();

        let results = load_results_from_wal(&seg).unwrap();
        assert_eq!(results.len(), 1, "result inside the zstd blob must be read");
        assert_eq!(results[0].task_kind, sample.task_kind);
        assert_eq!(results[0].components.len(), 2);
    }

    #[test]
    fn complete_home_chain_projects_latest_run_across_compressed_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let first_identity = UpdaterPassIdentity::new(UpdaterPassLane::NeothSelfProbe, 11);
        let second_identity = UpdaterPassIdentity::new(UpdaterPassLane::NeothSelfProbe, 12);
        write_test_segment(
            dir.path(),
            1,
            &[
                fired(&first_identity, UpdaterTaskKind::NeothSelf, 100),
                result(
                    &first_identity,
                    UpdaterTaskKind::NeothSelf,
                    101,
                    ComponentOutcome::up_to_date("neoth", "1.0.0"),
                ),
            ],
            true,
        );
        write_test_segment(
            dir.path(),
            2,
            &[
                fired(&second_identity, UpdaterTaskKind::NeothSelf, 200),
                result(
                    &second_identity,
                    UpdaterTaskKind::NeothSelf,
                    201,
                    ComponentOutcome::staged("neoth", "1.0.0", "1.0.1"),
                ),
            ],
            false,
        );

        let projection = project_updater_status_from_home(dir.path()).unwrap();
        assert_eq!(projection.latest.len(), 1);
        let latest = &projection.latest[0];
        assert_eq!(latest.phase, UpdaterRunPhase::Completed);
        assert_eq!(latest.identity, second_identity);
        assert_eq!(latest.ts_unix, 201);
        assert!(projection.open_runs.is_empty());
    }

    #[test]
    fn custom_home_namespace_projects_the_complete_rotating_chain() {
        let home = tempfile::tempdir().unwrap();
        let first_identity = UpdaterPassIdentity::new(UpdaterPassLane::NeothSelfProbe, 21);
        let second_identity = UpdaterPassIdentity::new(UpdaterPassLane::SelfStage, 22);
        write_test_segment_in_namespace(
            home.path(),
            Some("custom-daemon"),
            1,
            &[
                fired(&first_identity, UpdaterTaskKind::NeothSelf, 100),
                result(
                    &first_identity,
                    UpdaterTaskKind::NeothSelf,
                    101,
                    ComponentOutcome::up_to_date("neoth", "1.0.0"),
                ),
            ],
            true,
        );
        write_test_segment_in_namespace(
            home.path(),
            Some("custom-daemon"),
            2,
            &[
                fired(&second_identity, UpdaterTaskKind::NeothSelf, 200),
                result(
                    &second_identity,
                    UpdaterTaskKind::NeothSelf,
                    201,
                    ComponentOutcome::staged("neoth", "1.0.0", "1.0.1"),
                ),
            ],
            false,
        );

        let base = home.path().join("wal/custom-daemon-000001.wal");
        let projection = project_updater_status_from_home_chain(home.path(), &base).unwrap();
        assert_eq!(projection.latest.len(), 2, "one latest state per lane");
        assert!(
            projection
                .latest
                .iter()
                .any(|run| run.identity == first_identity && run.ts_unix == 101)
        );
        assert!(
            projection
                .latest
                .iter()
                .any(|run| run.identity == second_identity && run.ts_unix == 201)
        );
        assert!(projection.open_runs.is_empty());
    }

    #[test]
    fn later_boot_boundary_marks_crash_stranded_fired_as_interrupted() {
        use std::io::Write;

        let home = tempfile::tempdir().unwrap();
        let identity = UpdaterPassIdentity::new(UpdaterPassLane::NeothSelfProbe, 31);
        write_test_segment(
            home.path(),
            1,
            &[fired(&identity, UpdaterTaskKind::NeothSelf, 100)],
            false,
        );
        let boot_payload = br#"{"schema_version":1,"test":"restart"}"#;
        let boot_header = crate::wal::HeaderBuilder::new(EVENT_TYPE_BOOT, boot_payload).build();
        let boot_frame = crate::wal::frame::encode_frame(&boot_header, boot_payload);
        let path = home.path().join("wal/000001.wal");
        let mut segment = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        segment.write_all(&boot_frame).unwrap();
        segment.sync_all().unwrap();
        drop(segment);

        let projection = project_updater_status_from_home(home.path()).unwrap();
        assert!(projection.open_runs.is_empty());
        assert_eq!(projection.interrupted_run_count, 1);
        assert_eq!(projection.interrupted_runs.len(), 1);
        assert_eq!(projection.interrupted_runs[0].identity, identity);
        assert!(projection.interrupted_runs[0].note.contains("BOOT"));
        assert_eq!(projection.latest.len(), 1);
        assert_eq!(projection.latest[0].phase, UpdaterRunPhase::Interrupted);
    }

    #[test]
    fn projection_keeps_latest_terminal_and_marks_superseded_open_run_interrupted() {
        let abandoned = UpdaterPassIdentity::new(UpdaterPassLane::CliVersionProbe, 20);
        let completed = UpdaterPassIdentity::new(UpdaterPassLane::CliVersionProbe, 21);
        let projection = project_updater_status(vec![
            fired(&abandoned, UpdaterTaskKind::CliVersions, 100),
            fired(&completed, UpdaterTaskKind::CliVersions, 90),
            result(
                &completed,
                UpdaterTaskKind::CliVersions,
                91,
                ComponentOutcome::up_to_date("codex", "1.0"),
            ),
        ])
        .unwrap();

        assert_eq!(projection.latest.len(), 1);
        assert_eq!(
            projection.latest[0].identity, completed,
            "physical WAL order, not a regressed wall clock, selects latest"
        );
        assert_eq!(projection.latest[0].phase, UpdaterRunPhase::Completed);
        assert!(projection.open_runs.is_empty());
        assert_eq!(projection.interrupted_runs.len(), 1);
        assert_eq!(projection.interrupted_runs[0].identity, abandoned);
    }

    #[test]
    fn malformed_later_record_cannot_falsely_interrupt_a_valid_open_fired() {
        let open = UpdaterPassIdentity::new(UpdaterPassLane::CliVersionProbe, 22);
        let projection = project_updater_status(vec![
            fired(&open, UpdaterTaskKind::CliVersions, 100),
            UpdaterAuditEvent::Result(sample_result()),
        ])
        .unwrap();

        assert_eq!(projection.open_runs.len(), 1);
        assert_eq!(projection.open_runs[0].identity, open);
        assert_eq!(projection.open_runs[0].phase, UpdaterRunPhase::Fired);
        assert_eq!(projection.interrupted_run_count, 0);
        assert_eq!(projection.indeterminate_run_count, 1);
    }

    #[test]
    fn streaming_projection_keeps_old_open_fired_after_forty_thousand_completed_passes() {
        let limits = StreamingProjectionLimits {
            max_open_passes: 8,
            recent_identity_window: 64,
            retained_anomalies: 10,
        };
        let mut streaming = StreamingUpdaterProjection::new(limits);
        let old_open = UpdaterPassIdentity::new(UpdaterPassLane::SkillPluginProbe, 1);
        streaming
            .observe(fired(&old_open, UpdaterTaskKind::SkillPlugin, 1))
            .unwrap();

        for index in 0..40_000u64 {
            let identity = UpdaterPassIdentity::new(UpdaterPassLane::CliVersionProbe, index + 2);
            streaming
                .observe(fired(
                    &identity,
                    UpdaterTaskKind::CliVersions,
                    index * 2 + 2,
                ))
                .unwrap();
            streaming
                .observe(result(
                    &identity,
                    UpdaterTaskKind::CliVersions,
                    index * 2 + 3,
                    ComponentOutcome::up_to_date("codex", "1.0.0"),
                ))
                .unwrap();
        }

        assert_eq!(streaming.active.len(), 1, "only the old FIRED stays live");
        assert_eq!(
            streaming.recent.len(),
            limits.recent_identity_window,
            "completed pass identities must compact into the bounded recent window"
        );
        let projection = streaming.finish().unwrap();
        assert_eq!(projection.open_runs.len(), 1);
        assert_eq!(projection.open_runs[0].identity, old_open);
        assert_eq!(projection.open_runs[0].phase, UpdaterRunPhase::Fired);
        assert_eq!(projection.indeterminate_run_count, 0);
        assert_eq!(projection.interrupted_run_count, 0);
        assert!(
            projection.latest.iter().any(|run| {
                run.task_kind == UpdaterTaskKind::CliVersions
                    && run.phase == UpdaterRunPhase::Completed
            }),
            "the 40,000th completion must be the retained CLI lane state"
        );
    }

    #[test]
    fn streaming_projection_fails_closed_instead_of_evicting_an_open_fired() {
        let limits = StreamingProjectionLimits {
            max_open_passes: 1,
            recent_identity_window: 1,
            retained_anomalies: 1,
        };
        let mut streaming = StreamingUpdaterProjection::new(limits);
        let first = UpdaterPassIdentity::new(UpdaterPassLane::NeothSelfProbe, 1);
        let second = UpdaterPassIdentity::new(UpdaterPassLane::SkillPluginProbe, 1);
        streaming
            .observe(fired(&first, UpdaterTaskKind::NeothSelf, 1))
            .unwrap();
        let error = streaming
            .observe(fired(&second, UpdaterTaskKind::SkillPlugin, 2))
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("no FIRED record was evicted"),
            "{error:#}"
        );
        assert_eq!(streaming.active.len(), 1);
        assert!(
            streaming.active.contains_key(
                first
                    .correlatable_pass_id()
                    .expect("test identity is correlatable")
            )
        );
    }

    #[test]
    fn streaming_recent_window_poison_duplicate_terminal_identity() {
        let identity = UpdaterPassIdentity::new(UpdaterPassLane::NeothSelfProbe, 9);
        let terminal = result(
            &identity,
            UpdaterTaskKind::NeothSelf,
            2,
            ComponentOutcome::up_to_date("neoth", "1.0.0"),
        );
        let projection = project_updater_status(vec![
            fired(&identity, UpdaterTaskKind::NeothSelf, 1),
            terminal.clone(),
            terminal,
        ])
        .unwrap();

        assert_eq!(projection.indeterminate_run_count, 2);
        assert_eq!(projection.indeterminate_runs.len(), 2);
        assert_eq!(projection.latest.len(), 1);
        assert_eq!(projection.latest[0].phase, UpdaterRunPhase::Indeterminate);
        assert!(
            projection.latest[0].note.contains("poisoned correlation"),
            "{}",
            projection.latest[0].note
        );
    }

    #[test]
    fn latest_projection_keeps_distinct_lanes_that_share_a_task_kind() {
        let probe = UpdaterPassIdentity::new(UpdaterPassLane::NeothSelfProbe, 22);
        let stage = UpdaterPassIdentity::new(UpdaterPassLane::SelfStage, 22);
        let projection = project_updater_status(vec![
            fired(&probe, UpdaterTaskKind::NeothSelf, 100),
            result(
                &probe,
                UpdaterTaskKind::NeothSelf,
                101,
                ComponentOutcome::up_to_date("neoth", "1.0.0"),
            ),
            fired(&stage, UpdaterTaskKind::NeothSelf, 102),
            result(
                &stage,
                UpdaterTaskKind::NeothSelf,
                103,
                ComponentOutcome::staged("neoth", "1.0.0", "1.0.1"),
            ),
        ])
        .unwrap();

        assert_eq!(projection.latest.len(), 2);
        assert!(projection.latest.iter().any(|run| run.identity == probe));
        assert!(projection.latest.iter().any(|run| run.identity == stage));
    }

    #[test]
    fn projection_exposes_latest_open_correlated_run() {
        let identity = UpdaterPassIdentity::new(UpdaterPassLane::SkillPluginProbe, 30);
        let projection =
            project_updater_status(vec![fired(&identity, UpdaterTaskKind::SkillPlugin, 300)])
                .unwrap();

        assert_eq!(projection.latest[0].phase, UpdaterRunPhase::Fired);
        assert_eq!(projection.open_runs.len(), 1);
        assert_eq!(projection.open_runs[0].identity, identity);
        let rendered = render_updater_status(&projection);
        assert!(rendered.contains("state=fired"));
        assert!(rendered.contains("open runs: 1"));
    }

    #[test]
    fn correlated_failed_result_projects_failed_not_completed() {
        let identity = UpdaterPassIdentity::new(UpdaterPassLane::SelfStage, 31);
        let projection = project_updater_status(vec![
            fired(&identity, UpdaterTaskKind::NeothSelf, 310),
            result(
                &identity,
                UpdaterTaskKind::NeothSelf,
                311,
                ComponentOutcome::failed("self_stage", "1.0.0", "download failed"),
            ),
        ])
        .unwrap();

        assert_eq!(projection.latest[0].phase, UpdaterRunPhase::Failed);
        assert!(render_updater_status(&projection).contains("state=failed"));
    }

    #[test]
    fn mismatched_fired_receipt_poisoned_instead_of_pairing() {
        let identity = UpdaterPassIdentity::new(UpdaterPassLane::SelfStage, 31);
        let mut terminal = result(
            &identity,
            UpdaterTaskKind::NeothSelf,
            311,
            ComponentOutcome::up_to_date("self_stage", "1.0.0"),
        );
        let UpdaterAuditEvent::Result(payload) = &mut terminal else {
            unreachable!("result helper returns a RESULT");
        };
        payload.fired_receipt_sha256 = Some("f".repeat(64));
        let projection = project_updater_status(vec![
            fired(&identity, UpdaterTaskKind::NeothSelf, 310),
            terminal,
        ])
        .unwrap();

        assert_eq!(projection.latest[0].phase, UpdaterRunPhase::Indeterminate);
        assert_eq!(projection.indeterminate_run_count, 2);
        assert!(
            projection.latest[0]
                .note
                .contains("FIRED receipt conflicts")
        );
    }

    #[test]
    fn typed_cancelled_terminal_is_not_rendered_as_success() {
        let identity = UpdaterPassIdentity::new(UpdaterPassLane::SelfStage, 32);
        let mut terminal = result(
            &identity,
            UpdaterTaskKind::NeothSelf,
            321,
            ComponentOutcome::up_to_date("self_stage", "1.0.0"),
        );
        let UpdaterAuditEvent::Result(payload) = &mut terminal else {
            unreachable!("result helper returns a RESULT");
        };
        payload.terminal_outcome = Some(UpdaterTerminalOutcome::Cancelled);
        let projection = project_updater_status(vec![
            fired(&identity, UpdaterTaskKind::NeothSelf, 320),
            terminal,
        ])
        .unwrap();

        assert_eq!(projection.latest[0].phase, UpdaterRunPhase::Cancelled);
        assert!(render_updater_status(&projection).contains("state=cancelled"));
    }

    #[test]
    fn lane_task_mismatch_is_indeterminate_even_when_pair_fields_match() {
        let identity = UpdaterPassIdentity::new(UpdaterPassLane::SelfStage, 32);
        let projection = project_updater_status(vec![
            fired(&identity, UpdaterTaskKind::CliVersions, 320),
            result(
                &identity,
                UpdaterTaskKind::CliVersions,
                321,
                ComponentOutcome::up_to_date("codex", "1.0"),
            ),
        ])
        .unwrap();

        assert_eq!(projection.indeterminate_runs.len(), 2);
        assert_eq!(projection.latest[0].phase, UpdaterRunPhase::Indeterminate);
    }

    #[test]
    fn legacy_fired_and_result_remain_readable_but_uncorrelatable() {
        let legacy_fired: UpdaterTaskFiredPayload =
            serde_json::from_str(r#"{"task_kind":"neoth_self","ts_unix":1}"#).unwrap();
        let legacy_result: UpdaterTaskResultPayload = serde_json::from_str(
            r#"{"task_kind":"neoth_self","ts_unix":2,"duration_ms":1,"components":[]}"#,
        )
        .unwrap();
        assert_eq!(legacy_fired.identity, UpdaterPassIdentity::legacy());
        assert_eq!(legacy_result.identity, UpdaterPassIdentity::legacy());

        let projection = project_updater_status(vec![
            UpdaterAuditEvent::Fired(legacy_fired),
            UpdaterAuditEvent::Result(legacy_result),
        ])
        .unwrap();
        assert!(projection.open_runs.is_empty());
        assert_eq!(projection.indeterminate_runs.len(), 2);
        assert_eq!(projection.latest[0].phase, UpdaterRunPhase::Indeterminate);
        assert!(
            render_updater_status(&projection).contains("run=uncorrelatable"),
            "legacy frames must be explicit, never guessed into a healthy pair"
        );
    }

    #[test]
    fn corrupt_home_chain_fails_closed_instead_of_rendering_partial_status() {
        let dir = tempfile::tempdir().unwrap();
        let identity = UpdaterPassIdentity::new(UpdaterPassLane::NeothSelfProbe, 40);
        write_test_segment(
            dir.path(),
            1,
            &[
                fired(&identity, UpdaterTaskKind::NeothSelf, 1),
                result(
                    &identity,
                    UpdaterTaskKind::NeothSelf,
                    2,
                    ComponentOutcome::up_to_date("neoth", "1.0.0"),
                ),
            ],
            false,
        );
        let path = dir.path().join("wal").join("000001.wal");
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.last_mut().unwrap();
        *last ^= 0x5a;
        std::fs::write(&path, bytes).unwrap();

        let error = project_updater_status_from_home(dir.path()).unwrap_err();
        assert!(format!("{error:#}").contains("tamper-suspect"), "{error:#}");
    }
}
