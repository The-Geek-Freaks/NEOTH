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
//! Recording is gated upstream to in-learn-scope senders only (the same
//! [`super::channel_weights::learn_factor`] gate the channel-weight recorder
//! uses), so a stranger flooding an open channel can't manufacture a
//! high-priority "relationship" or skew whom NEOTH chooses to reach out to.
//!
//! ## Why a JSON file, not the WAL/SQLite
//!
//! Like `channel_weights`, this is a small, lazily-decayed, best-effort
//! aggregate — an atomic temp+rename JSON file in `~/.neoth/` is the right
//! weight class. A write failure is non-fatal: the operator loses one
//! interaction's worth of signal, never a turn.

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
pub const PEOPLE_SCHEMA_VERSION: u32 = 1;

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

/// Load from disk. Missing / malformed / wrong-schema → empty (never panics),
/// matching the best-effort contract of `channel_weights`.
pub fn load_people(home: &Path) -> People {
    let path = people_path(home);
    match std::fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<People>(&bytes) {
            Ok(p) if p.schema_version == PEOPLE_SCHEMA_VERSION => p,
            Ok(p) => {
                tracing::warn!(
                    path = %path.display(),
                    loaded = p.schema_version,
                    expected = PEOPLE_SCHEMA_VERSION,
                    "people.json schema mismatch — starting empty"
                );
                People::default()
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "people.json malformed — starting empty");
                People::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => People::default(),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "people.json unreadable — starting empty");
            People::default()
        }
    }
}

/// Atomic temp+rename write; mode-0600 on Unix (the file names correspondents
/// → treat it like the other `~/.neoth` secrets).
pub fn save_people(home: &Path, people: &People) -> Result<()> {
    let path = people_path(home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let body = serde_json::to_vec_pretty(people).context("serialise people.json")?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &body).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms)?;
    }
    Ok(())
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

fn row_index(people: &People, person_key: &str) -> Option<usize> {
    people.rows.iter().position(|r| r.person_key == person_key)
}

/// One interaction's worth of signal, recorded by the pipeline on every
/// in-scope inbound that produced a reply.
#[derive(Clone, Debug, PartialEq)]
pub struct Interaction<'a> {
    /// `human_uuid` when resolved, else `sender_id`. Required.
    pub person_key: &'a str,
    pub channel: &'a str,
    pub display: Option<&'a str>,
    /// True when the inbound was the person replying to / quoting the bot
    /// (mention_kind ReplyToBot | QuotedBot) — the reciprocity signal.
    pub is_reply_to_bot: bool,
    /// Length in chars of the inbound text (the depth signal).
    pub msg_len: u32,
}

/// Record one interaction: load, lazily decay frequency, increment counters,
/// stamp `last_seen`, save. Best-effort — the caller treats a write error as
/// non-fatal (one interaction's signal lost, never a turn).
pub fn record_interaction(home: &Path, ix: &Interaction<'_>, now_unix: u64) -> Result<()> {
    // COR-30: hold the lock across load→mutate→save so a concurrent record
    // can't read the same pre-state, mutate, and clobber our write.
    let _guard = PEOPLE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut people = load_people(home);
    match row_index(&people, ix.person_key) {
        Some(idx) => {
            let row = &mut people.rows[idx];
            row.interaction_count =
                apply_frequency_decay(row.interaction_count, row.decay_anchor_unix, now_unix);
            row.interaction_count = (row.interaction_count + 1.0).min(MAX_INTERACTION_COUNT);
            if ix.is_reply_to_bot {
                row.reply_to_bot_count += 1.0;
            }
            row.msg_len_total += ix.msg_len as f64;
            row.last_seen_unix = now_unix;
            row.decay_anchor_unix = now_unix;
            row.channel = ix.channel.to_string();
            // Refresh display when the channel surfaced a newer name.
            if let Some(d) = ix.display {
                row.display = Some(d.to_string());
            }
        }
        None => people.rows.push(PersonStat {
            person_key: ix.person_key.to_string(),
            channel: ix.channel.to_string(),
            display: ix.display.map(str::to_string),
            interaction_count: 1.0,
            reply_to_bot_count: if ix.is_reply_to_bot { 1.0 } else { 0.0 },
            msg_len_total: ix.msg_len as f64,
            last_seen_unix: now_unix,
            decay_anchor_unix: now_unix,
        }),
    }
    save_people(home, &people)
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

    (W_RECENCY * recency + W_FREQUENCY * frequency + W_RECIPROCITY * reciprocity + W_DEPTH * depth)
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
    // Highest score first; ties broken by most-recent so the ordering is
    // deterministic (no NaN — score is always finite + clamped).
    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.last_seen_unix.cmp(&a.last_seen_unix))
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
        assert!((p.rows[0].interaction_count - MAX_INTERACTION_COUNT).abs() < 1e-3);
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
        std::fs::write(people_path(dir.path()), b"{ not json").unwrap();
        assert!(load_people(dir.path()).rows.is_empty());
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
        assert!(!people_path(dir.path()).with_extension("json.tmp").exists());
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
