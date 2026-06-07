//! KF-05 — cross-channel memory unification: a Hebbian per-channel acceptance
//! store, mirroring [`super::routing_weights`] but keyed by
//! `(channel, topic_hash)` instead of `(topic_hash, hemisphere_role)`.
//!
//! Every time a channel message (Telegram / Slack / WhatsApp / …) produces a
//! successful reply, [`record_channel_acceptance`] bumps that channel's weight
//! for the message's topic (lazy Hebbian decay on read). The accumulated
//! weight is a per-channel-per-topic FAMILIARITY signal an operator can inspect
//! (`neoth memory channel-weights`) and a future channel-aware recall-ranking
//! pass can read via [`load_channel_weight`].
//!
//! Like routing_weights, the per-acceptance delta is a `const` (not config) so
//! an adversarial flood of "thanks!" replies can't rapidly skew the weights.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Serializes the load→mutate→save of `channel_weights.json` so concurrent
/// acceptance records can't lose updates (a read-modify-write race — COR-30,
/// the same class as the cluster `REGISTRY_LOCK`). Only the read-modify-write
/// path ([`record_channel_acceptance_scoped`]) takes it; pure readers
/// ([`load_channel_weight`]) skip it because the atomic temp+rename in
/// [`save_channel_weights`] hands them a torn-free snapshot. Poison-tolerant:
/// a panic mid-update must not permanently brick this best-effort store.
static CHANNEL_WEIGHTS_LOCK: Mutex<()> = Mutex::new(());

pub const CHANNEL_WEIGHTS_FILE: &str = "channel_weights.json";
pub const CHANNEL_WEIGHTS_SCHEMA_VERSION: u32 = 1;
/// Per-acceptance bump — `const`, not config (anti-manipulation, mirrors
/// `routing_weights::MAX_WEIGHT_DELTA`).
pub const MAX_CHANNEL_WEIGHT_DELTA: f32 = 0.05;
/// Saturating cap on a row's cumulative success count.
pub const MAX_CHANNEL_SUCCESS_COUNT: f32 = 30.0;
/// Prior returned for a `(channel, topic)` with no history.
pub const NEUTRAL_CHANNEL_WEIGHT: f32 = 0.5;
/// Hebbian decay multiplier per elapsed day.
pub const HEBBIAN_CHANNEL_DAILY_DECAY: f32 = 0.93;

/// Provenance: which channel + sender + chat originated a request. The
/// `channel` is also the weight-table key domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelContext {
    pub channel: String,
    pub sender_id: Option<String>,
    pub chat_id: Option<String>,
}

impl ChannelContext {
    pub fn from_inbound(msg: &crate::channels::InboundMessage) -> Self {
        Self {
            channel: msg.channel.as_str().to_string(),
            sender_id: Some(msg.sender_id.clone()),
            chat_id: Some(msg.chat_id.clone()),
        }
    }
    pub fn channel_key(&self) -> &str {
        &self.channel
    }
}

/// One `(channel, topic_hash)` acceptance row.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChannelWeight {
    pub channel: String,
    pub topic_hash: u64,
    pub success_count: f32,
    pub decay_anchor_unix: u64,
}

/// The on-disk store: `~/.neoth/channel_weights.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelWeights {
    pub schema_version: u32,
    pub rows: Vec<ChannelWeight>,
}

impl Default for ChannelWeights {
    fn default() -> Self {
        Self {
            schema_version: CHANNEL_WEIGHTS_SCHEMA_VERSION,
            rows: Vec::new(),
        }
    }
}

fn weights_path(home: &Path) -> PathBuf {
    home.join(CHANNEL_WEIGHTS_FILE)
}

/// Load from disk. Missing / malformed / wrong-schema → empty (never panics).
pub fn load_channel_weights(home: &Path) -> ChannelWeights {
    let path = weights_path(home);
    match std::fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<ChannelWeights>(&bytes) {
            Ok(p) if p.schema_version == CHANNEL_WEIGHTS_SCHEMA_VERSION => p,
            Ok(p) => {
                tracing::warn!(
                    path = %path.display(),
                    loaded = p.schema_version,
                    expected = CHANNEL_WEIGHTS_SCHEMA_VERSION,
                    "channel_weights.json schema mismatch — starting empty"
                );
                ChannelWeights::default()
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "channel_weights.json malformed — starting empty");
                ChannelWeights::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ChannelWeights::default(),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "channel_weights.json unreadable — starting empty");
            ChannelWeights::default()
        }
    }
}

/// Atomic temp+rename write; mode-0600 on Unix.
pub fn save_channel_weights(home: &Path, weights: &ChannelWeights) -> Result<()> {
    let path = weights_path(home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    let body = serde_json::to_vec_pretty(weights).context("serialise channel_weights.json")?;
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

/// Apply Hebbian decay per elapsed day.
fn apply_channel_decay(success_count: f32, anchor_unix: u64, now_unix: u64) -> f32 {
    let elapsed = now_unix.saturating_sub(anchor_unix);
    let days = (elapsed / 86_400) as i32;
    if days <= 0 {
        return success_count;
    }
    success_count * HEBBIAN_CHANNEL_DAILY_DECAY.powi(days)
}

fn row_index(weights: &ChannelWeights, channel: &str, topic_hash: u64) -> Option<usize> {
    weights
        .rows
        .iter()
        .position(|r| r.channel == channel && r.topic_hash == topic_hash)
}

/// KF-05 operator-scope (P1): the fraction of the full Hebbian delta a
/// non-operator, non-allowlisted sender contributes under the `all_tiny` scope.
/// Small enough that a flood of foreign replies can't dominate the operator's
/// own signal, but non-zero so an open channel still adapts.
pub const NON_OPERATOR_TINY_FACTOR: f32 = 0.1;

/// KF-05 operator-scope decision (P1) — PURE. Returns the weight factor a
/// sender's accepted reply contributes (`1.0` = full), or `None` to NOT learn
/// from this sender at all. Bounds WHOSE replies move the recall ranking so a
/// non-operator on a shared/open channel can't poison it.
///
/// `sender_uuid` is the inbound's resolved cross-channel `human_uuid`;
/// `operator_uuid` is the operator's pinned uuid (`None` = unconfigured → every
/// sender is treated as the operator; see [`crate::config::ChannelWeightsConfig`]).
pub fn learn_factor(
    scope: crate::config::ChannelLearnScope,
    sender_uuid: Option<&str>,
    operator_uuid: Option<&str>,
    allowlisted: &[String],
) -> Option<f32> {
    use crate::config::ChannelLearnScope as S;
    let is_operator = match (sender_uuid, operator_uuid) {
        (Some(s), Some(o)) => s == o,
        // Operator uuid not pinned → can't distinguish; a solo install has only
        // the operator, so treat as operator (keeps KF-05 alive until pinned).
        (_, None) => true,
        // Operator IS pinned but this sender carries no uuid → not the operator.
        (None, Some(_)) => false,
    };
    let is_allowlisted = sender_uuid.is_some_and(|s| allowlisted.iter().any(|a| a == s));
    match scope {
        S::OperatorOnly => is_operator.then_some(1.0),
        S::Allowlisted => (is_operator || is_allowlisted).then_some(1.0),
        S::AllTiny => Some(if is_operator || is_allowlisted {
            1.0
        } else {
            NON_OPERATOR_TINY_FACTOR
        }),
    }
}

/// Record one acceptance for `(channel, topic_hash)` at full strength. Thin
/// wrapper over [`record_channel_acceptance_scoped`] (factor `1.0`) — kept for
/// callers that don't gate on sender scope.
pub fn record_channel_acceptance(
    home: &Path,
    channel: &str,
    topic_hash: u64,
    now_unix: u64,
) -> Result<()> {
    record_channel_acceptance_scoped(home, channel, topic_hash, now_unix, 1.0)
}

/// Record one acceptance for `(channel, topic_hash)`, scaling the Hebbian delta
/// by `factor` (KF-05 operator-scope: `1.0` for the operator/allowlisted, a
/// tiny fraction for a non-operator under `all_tiny`). Load, lazily decay,
/// saturating-increment (capped at [`MAX_CHANNEL_SUCCESS_COUNT`]), save.
/// Best-effort: the caller treats a write error as non-fatal.
pub fn record_channel_acceptance_scoped(
    home: &Path,
    channel: &str,
    topic_hash: u64,
    now_unix: u64,
    factor: f32,
) -> Result<()> {
    let delta = MAX_CHANNEL_WEIGHT_DELTA * factor.clamp(0.0, 1.0);
    // COR-30: hold the lock across the whole load→mutate→save so a concurrent
    // record can't read the same pre-state, mutate, and clobber our write
    // (lost update). Pure readers don't lock — the atomic rename in
    // save_channel_weights gives them a consistent snapshot.
    let _guard = CHANNEL_WEIGHTS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut weights = load_channel_weights(home);
    match row_index(&weights, channel, topic_hash) {
        Some(idx) => {
            let row = &mut weights.rows[idx];
            row.success_count = apply_channel_decay(row.success_count, row.decay_anchor_unix, now_unix);
            row.success_count = (row.success_count + delta).min(MAX_CHANNEL_SUCCESS_COUNT);
            row.decay_anchor_unix = now_unix;
        }
        None => weights.rows.push(ChannelWeight {
            channel: channel.to_string(),
            topic_hash,
            success_count: delta,
            decay_anchor_unix: now_unix,
        }),
    }
    save_channel_weights(home, &weights)
}

/// Read the lazily-decayed familiarity weight for `(channel, topic_hash)`,
/// mapped to `[NEUTRAL_CHANNEL_WEIGHT, 1.0]`. Returns the neutral prior when no
/// history exists.
pub fn load_channel_weight(home: &Path, channel: &str, topic_hash: u64, now_unix: u64) -> f32 {
    let weights = load_channel_weights(home);
    channel_weight_of(&weights, channel, topic_hash, now_unix)
}

/// Pure: the decayed, normalised weight for a row within an in-memory store.
pub fn channel_weight_of(
    weights: &ChannelWeights,
    channel: &str,
    topic_hash: u64,
    now_unix: u64,
) -> f32 {
    let Some(idx) = row_index(weights, channel, topic_hash) else {
        return NEUTRAL_CHANNEL_WEIGHT;
    };
    let row = &weights.rows[idx];
    let decayed = apply_channel_decay(row.success_count, row.decay_anchor_unix, now_unix);
    let normalised = (decayed / MAX_CHANNEL_SUCCESS_COUNT).clamp(0.0, 1.0);
    (NEUTRAL_CHANNEL_WEIGHT + (1.0 - NEUTRAL_CHANNEL_WEIGHT) * normalised).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ChannelLearnScope as S;

    const DAY: u64 = 86_400;

    // ── KF-05 operator-scope (P1) ───────────────────────────────────────────

    #[test]
    fn learn_factor_operator_only_filters_non_operator_when_pinned() {
        let allow: Vec<String> = vec![];
        // Operator pinned: their reply learns at full; a stranger's does not.
        assert_eq!(
            learn_factor(S::OperatorOnly, Some("op"), Some("op"), &allow),
            Some(1.0)
        );
        assert_eq!(
            learn_factor(S::OperatorOnly, Some("stranger"), Some("op"), &allow),
            None,
            "a non-operator must NOT move the ranking under operator_only"
        );
        // No uuid on the inbound + operator pinned → not the operator → skip.
        assert_eq!(learn_factor(S::OperatorOnly, None, Some("op"), &allow), None);
    }

    #[test]
    fn learn_factor_unpinned_operator_treats_everyone_as_operator() {
        // Default fresh install (operator_uuid None) keeps KF-05 alive.
        let allow: Vec<String> = vec![];
        assert_eq!(
            learn_factor(S::OperatorOnly, Some("whoever"), None, &allow),
            Some(1.0)
        );
        assert_eq!(learn_factor(S::OperatorOnly, None, None, &allow), Some(1.0));
    }

    #[test]
    fn learn_factor_allowlisted_admits_listed_uuids() {
        let allow = vec!["friend".to_string()];
        assert_eq!(
            learn_factor(S::Allowlisted, Some("friend"), Some("op"), &allow),
            Some(1.0)
        );
        assert_eq!(
            learn_factor(S::Allowlisted, Some("stranger"), Some("op"), &allow),
            None
        );
    }

    #[test]
    fn learn_factor_all_tiny_gives_strangers_a_tiny_weight() {
        let allow: Vec<String> = vec![];
        assert_eq!(
            learn_factor(S::AllTiny, Some("op"), Some("op"), &allow),
            Some(1.0)
        );
        assert_eq!(
            learn_factor(S::AllTiny, Some("stranger"), Some("op"), &allow),
            Some(NON_OPERATOR_TINY_FACTOR),
            "a stranger still adapts, but only at the tiny factor"
        );
    }

    #[test]
    fn scoped_record_applies_the_factor() {
        let dir = tempfile::tempdir().unwrap();
        // Full vs tiny on two distinct topics → the tiny one accrues less.
        record_channel_acceptance_scoped(dir.path(), "telegram", 1, 1000, 1.0).unwrap();
        record_channel_acceptance_scoped(dir.path(), "telegram", 2, 1000, NON_OPERATOR_TINY_FACTOR)
            .unwrap();
        let w = load_channel_weights(dir.path());
        let full = w.rows.iter().find(|r| r.topic_hash == 1).unwrap().success_count;
        let tiny = w.rows.iter().find(|r| r.topic_hash == 2).unwrap().success_count;
        assert!(full > tiny, "full-factor delta must exceed the tiny-factor delta");
        assert!((tiny - MAX_CHANNEL_WEIGHT_DELTA * NON_OPERATOR_TINY_FACTOR).abs() < 1e-6);
    }

    #[test]
    fn new_row_starts_at_neutral() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            load_channel_weight(dir.path(), "telegram", 7, 1000),
            NEUTRAL_CHANNEL_WEIGHT
        );
    }

    #[test]
    fn record_increments_above_neutral() {
        let dir = tempfile::tempdir().unwrap();
        record_channel_acceptance(dir.path(), "telegram", 7, 1000).unwrap();
        assert!(load_channel_weight(dir.path(), "telegram", 7, 1000) > NEUTRAL_CHANNEL_WEIGHT);
    }

    #[test]
    fn cap_prevents_runaway() {
        let dir = tempfile::tempdir().unwrap();
        for _ in 0..1000 {
            record_channel_acceptance(dir.path(), "slack", 1, 1000).unwrap();
        }
        let w = load_channel_weights(dir.path());
        let row = w.rows.iter().find(|r| r.channel == "slack").unwrap();
        assert!((row.success_count - MAX_CHANNEL_SUCCESS_COUNT).abs() < 1e-3);
    }

    #[test]
    fn decay_reduces_stale_weight() {
        let dir = tempfile::tempdir().unwrap();
        for _ in 0..20 {
            record_channel_acceptance(dir.path(), "telegram", 7, 1000).unwrap();
        }
        let fresh = load_channel_weight(dir.path(), "telegram", 7, 1000);
        let stale = load_channel_weight(dir.path(), "telegram", 7, 1000 + 60 * DAY);
        assert!(stale < fresh, "60-day-stale weight {stale} must be < fresh {fresh}");
    }

    #[test]
    fn neutral_prior_for_other_channel() {
        let dir = tempfile::tempdir().unwrap();
        record_channel_acceptance(dir.path(), "telegram", 7, 1000).unwrap();
        // A different channel with no history reads neutral.
        assert_eq!(
            load_channel_weight(dir.path(), "slack", 7, 1000),
            NEUTRAL_CHANNEL_WEIGHT
        );
    }

    #[test]
    fn per_channel_per_topic_isolation() {
        let dir = tempfile::tempdir().unwrap();
        record_channel_acceptance(dir.path(), "telegram", 7, 1000).unwrap();
        // Same channel, different topic → neutral.
        assert_eq!(
            load_channel_weight(dir.path(), "telegram", 8, 1000),
            NEUTRAL_CHANNEL_WEIGHT
        );
    }

    #[test]
    fn round_trip_disk() {
        let dir = tempfile::tempdir().unwrap();
        let w = ChannelWeights {
            schema_version: CHANNEL_WEIGHTS_SCHEMA_VERSION,
            rows: vec![ChannelWeight {
                channel: "x".into(),
                topic_hash: 1,
                success_count: 0.3,
                decay_anchor_unix: 5,
            }],
        };
        save_channel_weights(dir.path(), &w).unwrap();
        assert_eq!(load_channel_weights(dir.path()), w);
    }

    #[test]
    fn malformed_json_loads_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(weights_path(dir.path()), b"{ not json").unwrap();
        assert!(load_channel_weights(dir.path()).rows.is_empty());
    }

    #[test]
    fn wrong_schema_loads_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(weights_path(dir.path()), br#"{"schema_version":999,"rows":[]}"#).unwrap();
        assert!(load_channel_weights(dir.path()).rows.is_empty());
    }

    #[test]
    fn save_leaves_no_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        save_channel_weights(dir.path(), &ChannelWeights::default()).unwrap();
        assert!(!weights_path(dir.path()).with_extension("json.tmp").exists());
    }

    #[test]
    fn save_overwrites_atomically() {
        let dir = tempfile::tempdir().unwrap();
        record_channel_acceptance(dir.path(), "a", 1, 1000).unwrap();
        record_channel_acceptance(dir.path(), "b", 2, 1000).unwrap();
        let w = load_channel_weights(dir.path());
        assert_eq!(w.rows.len(), 2);
    }

    #[test]
    fn channel_context_from_inbound() {
        use crate::channels::{ChannelKind, InboundMessage};
        let msg = InboundMessage {
            channel: ChannelKind::Telegram,
            chat_id: "chat1".into(),
            thread_id: None,
            sender_id: "user1".into(),
            sender_display: None,
            text: Some("hi".into()),
            media: None,
            reply_to: None,
            message_id: None,
            edit_unix: None,
            mention_kind: None,
            channel_ts_unix: 0,
            raw_ts_ms: None,
            human_uuid: None,
        };
        let ctx = ChannelContext::from_inbound(&msg);
        assert_eq!(ctx.channel, "telegram");
        assert_eq!(ctx.sender_id.as_deref(), Some("user1"));
        assert_eq!(ctx.chat_id.as_deref(), Some("chat1"));
        assert_eq!(ctx.channel_key(), "telegram");
    }

    #[test]
    fn concurrent_acceptance_increments_are_not_lost() {
        // COR-30: N threads record an acceptance for the SAME (channel, topic)
        // at once. Under the load→mutate→save lock every increment must land —
        // the pre-lock code lost updates (two threads read the same pre-state,
        // both wrote, one increment vanished) and could create duplicate rows.
        use std::sync::Arc;
        let dir = Arc::new(tempfile::tempdir().unwrap());
        let n = 20u32;
        let mut handles = Vec::new();
        for _ in 0..n {
            let dir = Arc::clone(&dir);
            handles.push(std::thread::spawn(move || {
                record_channel_acceptance(dir.path(), "telegram", 7, 1000).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let w = load_channel_weights(dir.path());
        // Exactly one (channel, topic) row — no duplicate inserts from racing.
        assert_eq!(w.rows.len(), 1, "racing inserts must not duplicate the row");
        let row = w
            .rows
            .iter()
            .find(|r| r.channel == "telegram" && r.topic_hash == 7)
            .unwrap();
        // All N deltas accrued (same now_unix → no decay between them).
        let expected = MAX_CHANNEL_WEIGHT_DELTA * n as f32;
        assert!(
            (row.success_count - expected).abs() < 1e-4,
            "expected {expected} from {n} serialized increments, got {} (lost update)",
            row.success_count
        );
    }
}
