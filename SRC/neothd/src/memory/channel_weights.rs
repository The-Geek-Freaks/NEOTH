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

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

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

/// Record one acceptance for `(channel, topic_hash)` — load, lazily decay,
/// saturating-increment (capped at [`MAX_CHANNEL_SUCCESS_COUNT`]), save.
/// Best-effort: the caller treats a write error as non-fatal.
pub fn record_channel_acceptance(
    home: &Path,
    channel: &str,
    topic_hash: u64,
    now_unix: u64,
) -> Result<()> {
    let mut weights = load_channel_weights(home);
    match row_index(&weights, channel, topic_hash) {
        Some(idx) => {
            let row = &mut weights.rows[idx];
            row.success_count = apply_channel_decay(row.success_count, row.decay_anchor_unix, now_unix);
            row.success_count = (row.success_count + MAX_CHANNEL_WEIGHT_DELTA).min(MAX_CHANNEL_SUCCESS_COUNT);
            row.decay_anchor_unix = now_unix;
        }
        None => weights.rows.push(ChannelWeight {
            channel: channel.to_string(),
            topic_hash,
            success_count: MAX_CHANNEL_WEIGHT_DELTA,
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

    const DAY: u64 = 86_400;

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
}
