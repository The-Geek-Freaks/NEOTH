//! GOLD-ADAPT-OH-10 — people scorer.
//!
//! A per-person relationship signal, mirroring [`super::channel_weights`] but
//! keyed by the operator's *correspondents* rather than `(channel, topic)`.
//! Every in-scope inbound message that produces a reply records one
//! interaction for that person; [`score_person`] then folds four signals into
//! a single clamped `[0, 1]` relationship score:
//!
//!   - **recency**    — how recently they last reached us (exponential decay).
//!   - **frequency**  — how many interactions we've had (saturating).
//!   - **reciprocity** — how often they engage *back* with our replies
//!     (`reply_to_bot / interactions`), i.e. is it a two-way relationship or a
//!     one-way broadcast.
//!   - **depth**      — average message richness (longer, substantive messages
//!     score higher than one-word pings).
//!
//! Adopted from openhuman `people/scorer.rs` (recency × frequency ×
//! reciprocity × depth, clamped). The ranking is surfaced today via
//! `neoth memory --people` and is the natural priority key a future proactive
//! surfacing pass reads to decide *whom* to nudge first.
//!
//! ## Privacy + anti-poison (mirrors KF-05 operator-scope)
//!
//! Recording uses the same [`super::channel_weights::learn_factor`] scope as
//! the channel-weight recorder. Operator/allowlisted senders contribute at
//! full weight; `all_tiny` strangers contribute at `0.1`, and `off`/
//! `allowlisted` skip out-of-scope senders. The weight scales every accumulator
//! and the score's confidence, so ten tiny samples equal one trusted sample
//! instead of one tiny sample receiving a full recency/depth boost.
//!
//! ## Why a JSON file, not the WAL/SQLite
//!
//! Like `channel_weights`, this is a small, lazily-decayed, best-effort
//! aggregate — an atomic temp+rename JSON file in `~/.neoth/` is the right
//! weight class. A write failure is non-fatal: the operator loses one
//! interaction's worth of signal, never a turn.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Serializes load→mutate→save of `people.json` so concurrent interaction
/// records can't lose updates (COR-30, same class as `channel_weights`'s
/// `CHANNEL_WEIGHTS_LOCK`). Pure readers ([`load_people`]/[`top_people`]) skip
/// it — the atomic temp+rename in [`save_people`] hands them a torn-free
/// snapshot. Poison-tolerant: a panic mid-update must not brick the store.
static PEOPLE_LOCK: Mutex<()> = Mutex::new(());

pub const PEOPLE_FILE: &str = "people.json";
pub const PEOPLE_SCHEMA_VERSION: u32 = 2;
const LEGACY_PEOPLE_SCHEMA_VERSION: u32 = 1;
/// Hard cardinality bound for untrusted/open-channel identities.
pub const MAX_PEOPLE_ROWS: usize = 4_096;
/// Reject a corrupt or attacker-grown snapshot before allocating it.
pub const MAX_PEOPLE_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_PERSON_KEY_BYTES: usize = 256;
pub const MAX_CHANNEL_BYTES: usize = 64;
pub const MAX_DISPLAY_CHARS: usize = 256;

/// Saturating cap on a person's cumulative interaction count. Past this the
/// frequency signal is already maxed, so a flood adds nothing — bounding it
/// keeps `frequency` honest and the JSON small.
pub const MAX_INTERACTION_COUNT: f32 = 100.0;
/// Hebbian decay multiplier applied to `interaction_count` per elapsed day —
/// a once-close contact who's gone quiet for weeks slowly loses frequency
/// weight. Matches `channel_weights`'s daily-decay shape.
pub const FREQUENCY_DAILY_DECAY: f32 = 0.97;
/// `recency` half-life: days after which the recency signal halves. ~10 days
/// means last-week contacts stay near the top, last-month ones fade.
pub const RECENCY_HALFLIFE_DAYS: f32 = 10.0;
/// Message length (chars) that saturates the `depth` signal — a single
/// substantive paragraph. Longer doesn't score higher (avoids rewarding
/// wall-of-text spam).
pub const DEPTH_SATURATION_CHARS: f32 = 400.0;

// Signal weights — sum to 1.0 so the composite stays in `[0, 1]`. Recency +
// frequency dominate ("who's active in my life right now"); reciprocity +
// depth refine ("…and is it a real two-way, substantive relationship").
pub const W_RECENCY: f32 = 0.35;
pub const W_FREQUENCY: f32 = 0.30;
pub const W_RECIPROCITY: f32 = 0.20;
pub const W_DEPTH: f32 = 0.15;

/// One correspondent's accumulated interaction signal.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PersonStat {
    /// Stable identity key: the resolved cross-channel `human_uuid` when
    /// present, else the channel-native `sender_id`. Opaque.
    pub person_key: String,
    /// Channel the person was last seen on (provenance; informational).
    pub channel: String,
    /// Human-readable name when the channel surfaced one.
    pub display: Option<String>,
    /// Number of recorded interactions (drives `frequency`; lazily decayed).
    pub interaction_count: f32,
    /// How many of those interactions were the person replying to / quoting
    /// the bot (drives `reciprocity`). Never decayed independently — it's a
    /// ratio numerator against `interaction_count`.
    pub reply_to_bot_count: f32,
    /// Sum of inbound message lengths (chars), for the average-depth signal.
    pub msg_len_total: f64,
    /// Unix seconds of the most recent interaction (drives `recency`).
    pub last_seen_unix: u64,
    /// Anchor for the per-day frequency decay (the last time we touched the
    /// row), so reads can lazily age `interaction_count`.
    pub decay_anchor_unix: u64,
}

/// The on-disk store: `~/.neoth/people.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct People {
    pub schema_version: u32,
    pub rows: Vec<PersonStat>,
}

impl Default for People {
    fn default() -> Self {
        Self {
            schema_version: PEOPLE_SCHEMA_VERSION,
            rows: Vec::new(),
        }
    }
}

fn people_path(home: &Path) -> PathBuf {
    home.join(PEOPLE_FILE)
}

fn people_lock_path(home: &Path) -> PathBuf {
    home.join(format!("{PEOPLE_FILE}.lock"))
}

fn validate_people(people: &People) -> Result<()> {
    anyhow::ensure!(
        people.schema_version == PEOPLE_SCHEMA_VERSION,
        "people.json schema mismatch: loaded {}, expected {}",
        people.schema_version,
        PEOPLE_SCHEMA_VERSION
    );
    anyhow::ensure!(
        people.rows.len() <= MAX_PEOPLE_ROWS,
        "people.json has {} rows, cap is {MAX_PEOPLE_ROWS}",
        people.rows.len()
    );
    let mut keys = HashSet::with_capacity(people.rows.len());
    for row in &people.rows {
        anyhow::ensure!(
            !row.person_key.trim().is_empty() && row.person_key.len() <= MAX_PERSON_KEY_BYTES,
            "people.json contains an invalid person key"
        );
        anyhow::ensure!(
            !row.channel.trim().is_empty() && row.channel.len() <= MAX_CHANNEL_BYTES,
            "people.json contains an invalid channel"
        );
        anyhow::ensure!(
            row.display
                .as_deref()
                .map(|display| display.chars().count() <= MAX_DISPLAY_CHARS)
                .unwrap_or(true),
            "people.json contains an oversized display name"
        );
        anyhow::ensure!(
            row.interaction_count.is_finite()
                && (0.0..=MAX_INTERACTION_COUNT).contains(&row.interaction_count)
                && row.reply_to_bot_count.is_finite()
                && row.reply_to_bot_count >= 0.0
                && row.reply_to_bot_count <= row.interaction_count + f32::EPSILON
                && row.msg_len_total.is_finite()
                && row.msg_len_total >= 0.0
                && row.msg_len_total
                    <= f64::from(row.interaction_count) * f64::from(DEPTH_SATURATION_CHARS)
                        + f64::EPSILON,
            "people.json contains invalid interaction accumulators"
        );
        anyhow::ensure!(
            keys.insert(row.person_key.as_str()),
            "people.json contains duplicate person keys"
        );
    }
    Ok(())
}

fn migrate_legacy_people(mut people: People) -> People {
    for row in &mut people.rows {
        if row.interaction_count.is_finite() && row.interaction_count > MAX_INTERACTION_COUNT {
            let factor = f64::from(MAX_INTERACTION_COUNT) / f64::from(row.interaction_count);
            row.interaction_count = MAX_INTERACTION_COUNT;
            row.reply_to_bot_count *= factor as f32;
            row.msg_len_total *= factor;
        }
        if row.interaction_count.is_finite() && row.interaction_count >= 0.0 {
            row.reply_to_bot_count = row.reply_to_bot_count.min(row.interaction_count).max(0.0);
            row.msg_len_total = row
                .msg_len_total
                .min(f64::from(row.interaction_count) * f64::from(DEPTH_SATURATION_CHARS))
                .max(0.0);
        }
    }
    if people.rows.len() > MAX_PEOPLE_ROWS {
        people.rows.sort_by(|a, b| {
            b.last_seen_unix
                .cmp(&a.last_seen_unix)
                .then_with(|| b.interaction_count.total_cmp(&a.interaction_count))
                .then_with(|| a.person_key.cmp(&b.person_key))
        });
        people.rows.truncate(MAX_PEOPLE_ROWS);
    }
    people.schema_version = PEOPLE_SCHEMA_VERSION;
    people
}

/// Strict loader for every read-modify-write path. Existing malformed bytes
/// are never converted into an empty store and overwritten.
fn load_people_strict(home: &Path) -> Result<People> {
    let path = people_path(home);
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(People::default());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("stat {}", path.display()));
        }
    };
    anyhow::ensure!(
        metadata.len() <= MAX_PEOPLE_FILE_BYTES,
        "{} exceeds the {}-byte safety cap",
        path.display(),
        MAX_PEOPLE_FILE_BYTES
    );
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_PEOPLE_FILE_BYTES,
        "{} grew beyond the safety cap while reading",
        path.display()
    );
    let mut people: People = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse {} without discarding it", path.display()))?;
    if people.schema_version == LEGACY_PEOPLE_SCHEMA_VERSION {
        tracing::info!(
            path = %path.display(),
            "people.json v1 loaded; bounded scorer migration will persist on the next mutation"
        );
        people = migrate_legacy_people(people);
    }
    validate_people(&people)?;
    Ok(people)
}

/// Best-effort read-only load. Mutating paths use [`load_people_strict`] so a
/// malformed snapshot can never be silently replaced with an empty one.
pub fn load_people(home: &Path) -> People {
    let path = people_path(home);
    match load_people_strict(home) {
        Ok(people) => people,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                error = %error,
                "people.json invalid — preserving bytes and returning an empty read-only view"
            );
            People::default()
        }
    }
}

fn save_people_unlocked(home: &Path, people: &People) -> Result<()> {
    validate_people(people)?;
    let path = people_path(home);
    let body = serde_json::to_vec_pretty(people).context("serialise people.json")?;
    anyhow::ensure!(
        body.len() as u64 <= MAX_PEOPLE_FILE_BYTES,
        "serialized people.json exceeds the safety cap"
    );
    crate::util::atomic_write::atomic_write_private(&path, &body)
        .with_context(|| format!("atomically write private {}", path.display()))
}

/// Validated, crash-safe private write serialized against daemon and CLI
/// writers in this process and in other processes.
pub fn save_people(home: &Path, people: &People) -> Result<()> {
    let _guard = PEOPLE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _os_guard =
        crate::util::locked_file::lock_file_blocking(&people_lock_path(home), "people scorer")?;
    save_people_unlocked(home, people)
}

/// Apply Hebbian frequency decay per elapsed day.
fn apply_frequency_decay(count: f32, anchor_unix: u64, now_unix: u64) -> f32 {
    let elapsed = now_unix.saturating_sub(anchor_unix);
    let days = (elapsed / 86_400) as i32;
    if days <= 0 {
        return count;
    }
    count * FREQUENCY_DAILY_DECAY.powi(days)
}

fn decay_row(row: &mut PersonStat, now_unix: u64) {
    let previous = row.interaction_count;
    let decayed = apply_frequency_decay(previous, row.decay_anchor_unix, now_unix);
    let factor = if previous > 0.0 {
        (decayed / previous).clamp(0.0, 1.0)
    } else {
        0.0
    };
    row.interaction_count = decayed;
    row.reply_to_bot_count *= factor;
    row.msg_len_total *= f64::from(factor);
}

fn clamp_accumulators(row: &mut PersonStat) {
    if row.interaction_count > MAX_INTERACTION_COUNT {
        // Derive the shared cap factor in f64: `msg_len_total` is f64 and
        // repeatedly applying a rounded f32 ratio otherwise drifts its average
        // away from the capped interaction denominator.
        let factor = f64::from(MAX_INTERACTION_COUNT) / f64::from(row.interaction_count);
        row.interaction_count = MAX_INTERACTION_COUNT;
        row.reply_to_bot_count *= factor as f32;
        row.msg_len_total *= factor;
    }
    row.reply_to_bot_count = row.reply_to_bot_count.min(row.interaction_count);
    row.msg_len_total = row
        .msg_len_total
        .min(f64::from(row.interaction_count) * f64::from(DEPTH_SATURATION_CHARS));
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn row_index(people: &People, person_key: &str) -> Option<usize> {
    people.rows.iter().position(|r| r.person_key == person_key)
}

/// One interaction's worth of signal, recorded by the pipeline on every
/// in-scope inbound that produced a reply.
#[derive(Clone, Debug, PartialEq)]
pub struct Interaction<'a> {
    /// Stable `human_uuid` when resolved, otherwise a channel-qualified native
    /// sender id. Required.
    pub person_key: &'a str,
    pub channel: &'a str,
    pub display: Option<&'a str>,
    /// True when the inbound was the person replying to / quoting the bot
    /// (mention_kind ReplyToBot | QuotedBot) — the reciprocity signal.
    pub is_reply_to_bot: bool,
    /// Length in chars of the inbound text (the depth signal).
    pub msg_len: u32,
    /// Operator-scope learning weight. `AllTiny` strangers use `0.1`; trusted
    /// correspondents use `1.0`. It scales every accumulator consistently.
    pub weight: f32,
}

/// Record one interaction: load, lazily decay frequency, increment counters,
/// stamp `last_seen`, save. Best-effort — the caller treats a write error as
/// non-fatal (one interaction's signal lost, never a turn).
pub fn record_interaction(home: &Path, ix: &Interaction<'_>, now_unix: u64) -> Result<()> {
    anyhow::ensure!(
        !ix.person_key.trim().is_empty() && ix.person_key.len() <= MAX_PERSON_KEY_BYTES,
        "person key is empty or exceeds {MAX_PERSON_KEY_BYTES} bytes"
    );
    anyhow::ensure!(
        !ix.channel.trim().is_empty() && ix.channel.len() <= MAX_CHANNEL_BYTES,
        "channel is empty or exceeds {MAX_CHANNEL_BYTES} bytes"
    );
    anyhow::ensure!(
        ix.weight.is_finite() && ix.weight > 0.0 && ix.weight <= 1.0,
        "people learning weight must be finite and in (0, 1]"
    );
    // COR-30: hold the lock across load→mutate→save so a concurrent record
    // can't read the same pre-state, mutate, and clobber our write.
    let _guard = PEOPLE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _os_guard =
        crate::util::locked_file::lock_file_blocking(&people_lock_path(home), "people scorer")?;
    let mut people = load_people_strict(home)?;
    match row_index(&people, ix.person_key) {
        Some(idx) => {
            let row = &mut people.rows[idx];
            let effective_now = now_unix.max(row.last_seen_unix).max(row.decay_anchor_unix);
            decay_row(row, effective_now);
            row.interaction_count += ix.weight;
            if ix.is_reply_to_bot {
                row.reply_to_bot_count += ix.weight;
            }
            row.msg_len_total +=
                f64::from(ix.msg_len).min(f64::from(DEPTH_SATURATION_CHARS)) * f64::from(ix.weight);
            clamp_accumulators(row);
            row.last_seen_unix = effective_now;
            row.decay_anchor_unix = effective_now;
            row.channel = ix.channel.to_string();
            // Refresh display when the channel surfaced a newer name.
            if let Some(d) = ix.display {
                row.display = Some(truncate_chars(d, MAX_DISPLAY_CHARS));
            }
        }
        None => {
            let candidate = PersonStat {
                person_key: ix.person_key.to_string(),
                channel: ix.channel.to_string(),
                display: ix
                    .display
                    .map(|display| truncate_chars(display, MAX_DISPLAY_CHARS)),
                interaction_count: ix.weight,
                reply_to_bot_count: if ix.is_reply_to_bot { ix.weight } else { 0.0 },
                msg_len_total: f64::from(ix.msg_len).min(f64::from(DEPTH_SATURATION_CHARS))
                    * f64::from(ix.weight),
                last_seen_unix: now_unix,
                decay_anchor_unix: now_unix,
            };
            if people.rows.len() < MAX_PEOPLE_ROWS {
                people.rows.push(candidate);
            } else if let Some((lowest_idx, lowest)) =
                people.rows.iter().enumerate().min_by(|(_, a), (_, b)| {
                    score_person(a, now_unix)
                        .total_cmp(&score_person(b, now_unix))
                        .then_with(|| a.last_seen_unix.cmp(&b.last_seen_unix))
                        .then_with(|| b.person_key.cmp(&a.person_key))
                })
            {
                let candidate_order = score_person(&candidate, now_unix)
                    .total_cmp(&score_person(lowest, now_unix))
                    .then_with(|| candidate.last_seen_unix.cmp(&lowest.last_seen_unix))
                    .then_with(|| lowest.person_key.cmp(&candidate.person_key));
                if candidate_order.is_gt() {
                    people.rows[lowest_idx] = candidate;
                } else {
                    tracing::debug!(
                        person_hash = xxhash_rust::xxh3::xxh3_64(ix.person_key.as_bytes()),
                        "people scorer at capacity; lower-priority new identity not persisted"
                    );
                    return Ok(());
                }
            }
        }
    }
    save_people_unlocked(home, &people)
}

/// Count every [`PersonStat`] whose `display` name contains `topic`
/// (case-insensitive), using the same strict loader and locking discipline as
/// [`forget_people_by_display`]. This is the read-only half of the CLI forget
/// preview: malformed state fails loudly instead of understating the erasure
/// scope.
pub fn count_people_by_display(home: &Path, topic: &str) -> Result<i64> {
    let needle = topic.trim().to_lowercase();
    if needle.is_empty() {
        return Ok(0);
    }
    let _guard = PEOPLE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _os_guard =
        crate::util::locked_file::lock_file_blocking(&people_lock_path(home), "people scorer")?;
    let people = load_people_strict(home)?;
    Ok(people
        .rows
        .iter()
        .filter(|row| {
            row.display
                .as_deref()
                .is_some_and(|display| display.to_lowercase().contains(&needle))
        })
        .count() as i64)
}

/// GDPR (D4) — remove every [`PersonStat`] whose `display` name contains
/// `topic` (case-insensitive). Held under [`PEOPLE_LOCK`] across
/// load→filter→save for atomicity. Returns the number of rows removed. A
/// missing file returns 0. Malformed/unreadable state fails loudly and is
/// preserved. Rows with no display name are kept: with no
/// human-readable name they can't match the topic, and `person_key` is an
/// opaque id, not a re-identifier.
pub fn forget_people_by_display(home: &Path, topic: &str) -> Result<i64> {
    let needle = topic.trim().to_lowercase();
    if needle.is_empty() {
        return Ok(0);
    }
    let _guard = PEOPLE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _os_guard =
        crate::util::locked_file::lock_file_blocking(&people_lock_path(home), "people scorer")?;
    let mut people = load_people_strict(home)?;
    let before = people.rows.len();
    people.rows.retain(|row| {
        row.display
            .as_deref()
            .map(|d| !d.to_lowercase().contains(&needle))
            .unwrap_or(true)
    });
    let removed = (before - people.rows.len()) as i64;
    if removed > 0 {
        save_people_unlocked(home, &people)?;
    }
    Ok(removed)
}

/// Exponential recency factor in `[0, 1]`: `1.0` at `last_seen == now`,
/// halving every [`RECENCY_HALFLIFE_DAYS`].
fn recency_factor(last_seen_unix: u64, now_unix: u64) -> f32 {
    let elapsed_days = now_unix.saturating_sub(last_seen_unix) as f32 / 86_400.0;
    0.5_f32.powf(elapsed_days / RECENCY_HALFLIFE_DAYS)
}

/// Compute the clamped `[0, 1]` relationship score for a row at `now_unix`.
/// Pure — the four-signal fold is unit-tested directly.
pub fn score_person(row: &PersonStat, now_unix: u64) -> f32 {
    let recency = recency_factor(row.last_seen_unix, now_unix);

    let decayed_freq =
        apply_frequency_decay(row.interaction_count, row.decay_anchor_unix, now_unix);
    let frequency = (decayed_freq / MAX_INTERACTION_COUNT).clamp(0.0, 1.0);

    let reciprocity = if row.interaction_count > 0.0 {
        (row.reply_to_bot_count / row.interaction_count).clamp(0.0, 1.0)
    } else {
        0.0
    };

    let depth = if row.interaction_count > 0.0 {
        let avg_len = (row.msg_len_total / row.interaction_count as f64) as f32;
        (avg_len / DEPTH_SATURATION_CHARS).clamp(0.0, 1.0)
    } else {
        0.0
    };

    // Fractional AllTiny samples must not receive the full recency/depth score
    // of one trusted interaction. Ten 0.1 samples build the same confidence as
    // one full-weight sample; ratios remain unchanged.
    let confidence = decayed_freq.clamp(0.0, 1.0);
    (confidence
        * (W_RECENCY * recency
            + W_FREQUENCY * frequency
            + W_RECIPROCITY * reciprocity
            + W_DEPTH * depth))
        .clamp(0.0, 1.0)
}

/// A scored row for inspection / ranking surfaces.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ScoredPerson {
    pub person_key: String,
    pub channel: String,
    pub display: Option<String>,
    pub score: f32,
    pub interaction_count: f32,
    pub last_seen_unix: u64,
}

/// Top-`n` correspondents by score, highest first. The priority key a
/// proactive surfacing pass reads to decide whom to reach out to, and what
/// `neoth memory --people` renders. `n == 0` returns the full ranking.
pub fn top_people(home: &Path, n: usize, now_unix: u64) -> Vec<ScoredPerson> {
    let people = load_people(home);
    let mut scored: Vec<ScoredPerson> = people
        .rows
        .iter()
        .map(|r| ScoredPerson {
            person_key: r.person_key.clone(),
            channel: r.channel.clone(),
            display: r.display.clone(),
            score: score_person(r, now_unix),
            interaction_count: r.interaction_count,
            last_seen_unix: r.last_seen_unix,
        })
        .collect();
    // Highest score first; final opaque-key tie-break makes the ordering stable
    // across filesystems/processes too (no NaN — validated finite inputs).
    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.last_seen_unix.cmp(&a.last_seen_unix))
            .then_with(|| a.person_key.cmp(&b.person_key))
    });
    if n > 0 {
        scored.truncate(n);
    }
    scored
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;

    fn ix<'a>(key: &'a str, reply: bool, len: u32) -> Interaction<'a> {
        Interaction {
            person_key: key,
            channel: "telegram",
            display: Some("Alice"),
            is_reply_to_bot: reply,
            msg_len: len,
            weight: 1.0,
        }
    }

    #[test]
    fn first_interaction_creates_row_at_count_one() {
        let dir = tempfile::tempdir().unwrap();
        record_interaction(dir.path(), &ix("alice", true, 100), 1000).unwrap();
        let p = load_people(dir.path());
        assert_eq!(p.rows.len(), 1);
        let row = &p.rows[0];
        assert_eq!(row.person_key, "alice");
        assert_eq!(row.interaction_count, 1.0);
        assert_eq!(row.reply_to_bot_count, 1.0);
        assert_eq!(row.msg_len_total, 100.0);
        assert_eq!(row.last_seen_unix, 1000);
    }

    #[test]
    fn repeated_interactions_accumulate() {
        let dir = tempfile::tempdir().unwrap();
        for _ in 0..5 {
            record_interaction(dir.path(), &ix("alice", false, 50), 1000).unwrap();
        }
        let p = load_people(dir.path());
        assert_eq!(p.rows.len(), 1, "same person must not duplicate rows");
        let row = &p.rows[0];
        assert_eq!(row.interaction_count, 5.0);
        assert_eq!(row.reply_to_bot_count, 0.0);
        assert_eq!(row.msg_len_total, 250.0);
    }

    #[test]
    fn interaction_count_saturates_at_cap() {
        let dir = tempfile::tempdir().unwrap();
        for _ in 0..200 {
            record_interaction(dir.path(), &ix("alice", false, 10), 1000).unwrap();
        }
        let p = load_people(dir.path());
        let row = &p.rows[0];
        assert!((row.interaction_count - MAX_INTERACTION_COUNT).abs() < 1e-3);
        assert!(
            (row.msg_len_total / f64::from(row.interaction_count) - 10.0).abs() < 1e-6,
            "capping must scale the denominator and depth numerator together"
        );
    }

    #[test]
    fn all_tiny_weight_scales_every_accumulator_and_score_confidence() {
        let dir = tempfile::tempdir().unwrap();
        let mut tiny = ix("stranger", true, 400);
        tiny.weight = 0.1;
        record_interaction(dir.path(), &tiny, 1000).unwrap();
        let row = load_people(dir.path()).rows.remove(0);
        assert!((row.interaction_count - 0.1).abs() < 1e-6);
        assert!((row.reply_to_bot_count - 0.1).abs() < 1e-6);
        assert!((row.msg_len_total - 40.0).abs() < 1e-5);

        let mut trusted = row.clone();
        trusted.interaction_count = 1.0;
        trusted.reply_to_bot_count = 1.0;
        trusted.msg_len_total = 400.0;
        assert!(
            score_person(&row, 1000) < score_person(&trusted, 1000) * 0.11,
            "one tiny sample must not receive a full trusted-contact score"
        );
    }

    #[test]
    fn decay_scales_ratio_numerators_with_the_denominator() {
        let dir = tempfile::tempdir().unwrap();
        record_interaction(dir.path(), &ix("alice", true, 200), 1000).unwrap();
        record_interaction(dir.path(), &ix("alice", false, 100), 1000 + DAY).unwrap();
        let row = load_people(dir.path()).rows.remove(0);
        let expected_old = FREQUENCY_DAILY_DECAY;
        assert!((row.interaction_count - (expected_old + 1.0)).abs() < 1e-5);
        assert!((row.reply_to_bot_count - expected_old).abs() < 1e-5);
        assert!((row.msg_len_total - (200.0 * f64::from(expected_old) + 100.0)).abs() < 1e-4);
    }

    #[test]
    fn backwards_clock_does_not_move_a_person_back_in_time() {
        let dir = tempfile::tempdir().unwrap();
        record_interaction(dir.path(), &ix("alice", false, 10), 2000).unwrap();
        record_interaction(dir.path(), &ix("alice", false, 10), 1000).unwrap();
        let row = load_people(dir.path()).rows.remove(0);
        assert_eq!(row.last_seen_unix, 2000);
        assert_eq!(row.decay_anchor_unix, 2000);
        assert_eq!(row.interaction_count, 2.0);
    }

    #[test]
    fn recency_factor_halves_at_halflife() {
        let fresh = recency_factor(1000, 1000);
        assert!((fresh - 1.0).abs() < 1e-6);
        let half = recency_factor(1000, 1000 + (RECENCY_HALFLIFE_DAYS as u64) * DAY);
        assert!(
            (half - 0.5).abs() < 0.02,
            "expected ~0.5 at half-life, got {half}"
        );
    }

    #[test]
    fn recency_dominates_for_recent_active_contact() {
        // A contact seen just now with several interactions scores well above
        // a long-silent one.
        let recent = PersonStat {
            person_key: "r".into(),
            channel: "telegram".into(),
            display: None,
            interaction_count: 10.0,
            reply_to_bot_count: 8.0,
            msg_len_total: 2000.0,
            last_seen_unix: 1_700_000_000,
            decay_anchor_unix: 1_700_000_000,
        };
        let stale = PersonStat {
            last_seen_unix: 1_700_000_000 - 120 * DAY,
            decay_anchor_unix: 1_700_000_000 - 120 * DAY,
            ..recent.clone()
        };
        let now = 1_700_000_000;
        assert!(
            score_person(&recent, now) > score_person(&stale, now),
            "recent contact must outscore a 120-day-silent one"
        );
    }

    #[test]
    fn reciprocity_rewards_two_way_engagement() {
        // Two contacts, identical except one always replies to the bot.
        let now = 1000;
        let one_way = PersonStat {
            person_key: "broadcast".into(),
            channel: "telegram".into(),
            display: None,
            interaction_count: 10.0,
            reply_to_bot_count: 0.0,
            msg_len_total: 1000.0,
            last_seen_unix: now,
            decay_anchor_unix: now,
        };
        let two_way = PersonStat {
            reply_to_bot_count: 10.0,
            ..one_way.clone()
        };
        assert!(
            score_person(&two_way, now) > score_person(&one_way, now),
            "a reciprocal contact must outscore a one-way broadcaster"
        );
    }

    #[test]
    fn depth_rewards_substantive_messages() {
        let now = 1000;
        let shallow = PersonStat {
            person_key: "pinger".into(),
            channel: "telegram".into(),
            display: None,
            interaction_count: 10.0,
            reply_to_bot_count: 5.0,
            msg_len_total: 100.0, // avg 10 chars — one-word pings
            last_seen_unix: now,
            decay_anchor_unix: now,
        };
        let deep = PersonStat {
            msg_len_total: 4000.0, // avg 400 chars — saturates depth
            ..shallow.clone()
        };
        assert!(
            score_person(&deep, now) > score_person(&shallow, now),
            "substantive messages must outscore one-word pings"
        );
    }

    #[test]
    fn score_always_in_unit_interval() {
        let now = 1000;
        // Maxed-out everything still clamps to <= 1.0.
        let maxed = PersonStat {
            person_key: "x".into(),
            channel: "telegram".into(),
            display: None,
            interaction_count: MAX_INTERACTION_COUNT,
            reply_to_bot_count: MAX_INTERACTION_COUNT,
            msg_len_total: (DEPTH_SATURATION_CHARS as f64) * MAX_INTERACTION_COUNT as f64 * 2.0,
            last_seen_unix: now,
            decay_anchor_unix: now,
        };
        let s = score_person(&maxed, now);
        assert!((0.0..=1.0).contains(&s), "score {s} out of [0,1]");
        // Empty/cold row floors at >= 0.
        let cold = PersonStat {
            interaction_count: 0.0,
            reply_to_bot_count: 0.0,
            msg_len_total: 0.0,
            last_seen_unix: 0,
            decay_anchor_unix: 0,
            ..maxed.clone()
        };
        assert!(score_person(&cold, now) >= 0.0);
    }

    #[test]
    fn frequency_decays_for_gone_quiet_contact() {
        // Same row scored fresh vs after a long silence — the lazily-decayed
        // frequency drags the later score down even though stored counts match.
        let row = PersonStat {
            person_key: "x".into(),
            channel: "telegram".into(),
            display: None,
            interaction_count: 50.0,
            reply_to_bot_count: 25.0,
            msg_len_total: 5000.0,
            last_seen_unix: 1000,
            decay_anchor_unix: 1000,
        };
        let fresh = score_person(&row, 1000);
        let aged = score_person(&row, 1000 + 90 * DAY);
        assert!(
            aged < fresh,
            "90-day-stale score {aged} must be < fresh {fresh}"
        );
    }

    #[test]
    fn top_people_orders_by_score_desc() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_000_000;
        // Bob: many reciprocal, substantive, recent → high.
        for _ in 0..20 {
            record_interaction(
                dir.path(),
                &Interaction {
                    person_key: "bob",
                    channel: "slack",
                    display: Some("Bob"),
                    is_reply_to_bot: true,
                    msg_len: 400,
                    weight: 1.0,
                },
                now,
            )
            .unwrap();
        }
        // Carol: one shallow one-way ping → low.
        record_interaction(
            dir.path(),
            &Interaction {
                person_key: "carol",
                channel: "slack",
                display: Some("Carol"),
                is_reply_to_bot: false,
                msg_len: 5,
                weight: 1.0,
            },
            now,
        )
        .unwrap();
        let top = top_people(dir.path(), 0, now);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].person_key, "bob", "highest score first");
        assert_eq!(top[1].person_key, "carol");
        assert!(top[0].score > top[1].score);
    }

    #[test]
    fn top_people_truncates_to_n() {
        let dir = tempfile::tempdir().unwrap();
        for k in ["a", "b", "c"] {
            record_interaction(dir.path(), &ix(k, true, 100), 1000).unwrap();
        }
        assert_eq!(top_people(dir.path(), 2, 1000).len(), 2);
        assert_eq!(top_people(dir.path(), 0, 1000).len(), 3, "n=0 returns all");
    }

    #[test]
    fn display_refreshes_on_newer_name() {
        let dir = tempfile::tempdir().unwrap();
        record_interaction(
            dir.path(),
            &Interaction {
                person_key: "u",
                channel: "telegram",
                display: Some("Old"),
                is_reply_to_bot: false,
                msg_len: 10,
                weight: 1.0,
            },
            1000,
        )
        .unwrap();
        record_interaction(
            dir.path(),
            &Interaction {
                person_key: "u",
                channel: "telegram",
                display: Some("New"),
                is_reply_to_bot: false,
                msg_len: 10,
                weight: 1.0,
            },
            1000,
        )
        .unwrap();
        assert_eq!(
            load_people(dir.path()).rows[0].display.as_deref(),
            Some("New")
        );
    }

    #[test]
    fn malformed_json_loads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let malformed = b"{ not json";
        std::fs::write(people_path(dir.path()), malformed).unwrap();
        assert!(load_people(dir.path()).rows.is_empty());
        assert!(
            record_interaction(dir.path(), &ix("alice", true, 100), 1000).is_err(),
            "a mutating path must fail closed on malformed state"
        );
        assert_eq!(
            std::fs::read(people_path(dir.path())).unwrap(),
            malformed,
            "malformed recovery bytes must be preserved"
        );
    }

    #[test]
    fn wrong_schema_loads_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            people_path(dir.path()),
            br#"{"schema_version":999,"rows":[]}"#,
        )
        .unwrap();
        assert!(load_people(dir.path()).rows.is_empty());
    }

    #[test]
    fn v1_snapshot_migrates_overgrown_accumulators_without_erasing_identity() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            people_path(dir.path()),
            br#"{
                "schema_version": 1,
                "rows": [{
                    "person_key": "legacy",
                    "channel": "telegram",
                    "display": "Alice",
                    "interaction_count": 100.0,
                    "reply_to_bot_count": 250.0,
                    "msg_len_total": 1000000.0,
                    "last_seen_unix": 5,
                    "decay_anchor_unix": 5
                }]
            }"#,
        )
        .unwrap();

        let migrated = load_people(dir.path());
        assert_eq!(migrated.schema_version, PEOPLE_SCHEMA_VERSION);
        assert_eq!(migrated.rows[0].person_key, "legacy");
        assert_eq!(migrated.rows[0].reply_to_bot_count, 100.0);
        assert_eq!(
            migrated.rows[0].msg_len_total,
            f64::from(MAX_INTERACTION_COUNT) * f64::from(DEPTH_SATURATION_CHARS)
        );

        record_interaction(dir.path(), &ix("legacy", false, 10), 5).unwrap();
        let persisted: People =
            serde_json::from_slice(&std::fs::read(people_path(dir.path())).unwrap()).unwrap();
        assert_eq!(persisted.schema_version, PEOPLE_SCHEMA_VERSION);
    }

    #[test]
    fn round_trip_disk() {
        let dir = tempfile::tempdir().unwrap();
        let p = People {
            schema_version: PEOPLE_SCHEMA_VERSION,
            rows: vec![PersonStat {
                person_key: "k".into(),
                channel: "telegram".into(),
                display: Some("Name".into()),
                interaction_count: 3.0,
                reply_to_bot_count: 2.0,
                msg_len_total: 300.0,
                last_seen_unix: 5,
                decay_anchor_unix: 5,
            }],
        };
        save_people(dir.path(), &p).unwrap();
        assert_eq!(load_people(dir.path()), p);
    }

    #[test]
    fn save_leaves_no_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        save_people(dir.path(), &People::default()).unwrap();
        let leftovers = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0);
        assert!(people_lock_path(dir.path()).exists());
    }

    #[test]
    fn validation_rejects_oversized_or_duplicate_identity_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut invalid = People {
            schema_version: PEOPLE_SCHEMA_VERSION,
            rows: vec![PersonStat {
                person_key: "x".repeat(MAX_PERSON_KEY_BYTES + 1),
                channel: "telegram".into(),
                display: None,
                interaction_count: 1.0,
                reply_to_bot_count: 0.0,
                msg_len_total: 1.0,
                last_seen_unix: 1,
                decay_anchor_unix: 1,
            }],
        };
        assert!(save_people(dir.path(), &invalid).is_err());

        invalid.rows[0].person_key = "same".into();
        invalid.rows.push(invalid.rows[0].clone());
        assert!(save_people(dir.path(), &invalid).is_err());
    }

    #[test]
    fn deterministic_final_tie_break_uses_person_key() {
        let dir = tempfile::tempdir().unwrap();
        for key in ["z", "a"] {
            record_interaction(dir.path(), &ix(key, true, 100), 1000).unwrap();
        }
        let ranked = top_people(dir.path(), 0, 1000);
        assert_eq!(ranked[0].person_key, "a");
        assert_eq!(ranked[1].person_key, "z");
    }

    #[test]
    fn forget_people_by_display_removes_matching_names_only() {
        // D4 (GDPR): wipe rows whose display name contains the topic
        // (case-insensitive); leave the rest; never wipe everything on empty.
        let dir = tempfile::tempdir().unwrap();
        let people = People {
            schema_version: PEOPLE_SCHEMA_VERSION,
            rows: vec![
                PersonStat {
                    person_key: "1".into(),
                    channel: "telegram".into(),
                    display: Some("Alice AcmeCorp".into()),
                    interaction_count: 1.0,
                    reply_to_bot_count: 0.0,
                    msg_len_total: 10.0,
                    last_seen_unix: 1,
                    decay_anchor_unix: 1,
                },
                PersonStat {
                    person_key: "2".into(),
                    channel: "telegram".into(),
                    display: Some("Bob".into()),
                    interaction_count: 1.0,
                    reply_to_bot_count: 0.0,
                    msg_len_total: 10.0,
                    last_seen_unix: 1,
                    decay_anchor_unix: 1,
                },
            ],
        };
        save_people(dir.path(), &people).unwrap();
        assert_eq!(forget_people_by_display(dir.path(), "acmecorp").unwrap(), 1);
        let after = load_people(dir.path());
        assert_eq!(after.rows.len(), 1);
        assert_eq!(after.rows[0].display.as_deref(), Some("Bob"));
        assert_eq!(forget_people_by_display(dir.path(), "nobody").unwrap(), 0);
        // empty/blank topic must never wipe the store
        assert_eq!(forget_people_by_display(dir.path(), "   ").unwrap(), 0);
        assert_eq!(load_people(dir.path()).rows.len(), 1);
    }

    #[test]
    fn concurrent_records_are_not_lost() {
        // COR-30: N threads record for the SAME person at once. Under the
        // load→mutate→save lock every increment must land + no duplicate rows.
        use std::sync::Arc;
        let dir = Arc::new(tempfile::tempdir().unwrap());
        let n = 20u32;
        let mut handles = Vec::new();
        for _ in 0..n {
            let dir = Arc::clone(&dir);
            handles.push(std::thread::spawn(move || {
                record_interaction(dir.path(), &ix("alice", true, 100), 1000).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let p = load_people(dir.path());
        assert_eq!(p.rows.len(), 1, "racing records must not duplicate the row");
        assert!(
            (p.rows[0].interaction_count - n as f32).abs() < 1e-3,
            "expected {n} from serialized increments, got {} (lost update)",
            p.rows[0].interaction_count
        );
    }
}
