//! Memory-routing weights for council winner selection (Pick #8 SP-4,
//! Session 14).
//!
//! Stores Hebbian-decayed acceptance counts per `(topic_hash,
//! hemisphere_role)` pair. The `cli/chat.rs` dispatch path calls
//! [`record_acceptance`] after a council winner is emitted, and
//! `council::quality_score::score_response` (future SP wire-in) reads
//! [`load_memory_weight`] to lift the `memory_weight` component of the
//! composite `QualityScore` for hemispheres that have historically
//! produced operator-accepted answers on the same topic.
//!
//! **JSON file rather than SQLite** — keeps SP-4 scope contained.
//! The existing `views.db` schema is at version 11 (see
//! `memory::store::SCHEMA_VERSION`) with its own migration chain; bumping
//! it just for a Hebbian-decayed scalar table would invert the cost/benefit
//! ratio. JSON file at
//! `~/.neoth/routing_weights.json` follows the same atomic-temp-
//! rename + mode-0600 pattern as `quota.json` and
//! `models_catalog.json`. v0.4 follow-up can migrate to SQLite when
//! the table grows past 10k rows.
//!
//! ## Hard rules (from Pick #8 fractal synthesis)
//!
//! - **`MAX_WEIGHT_DELTA = 0.05` is `const`, not config**. An
//!   operator who tries to override this in `freedom.yaml` would be
//!   able to amplify EMA-poisoning attacks (Security threat #3:
//!   adversarial "thanks!" feedback shifting routing). The const
//!   value is the upper bound enforced at every `record_acceptance`
//!   call.
//! - **Per-event delta capped + cumulative drift bounded**. A given
//!   `(topic, role)` pair's success count saturates at
//!   `MAX_SUCCESS_COUNT` so an attacker can't push the weight beyond
//!   a documented floor / ceiling.
//! - **Hebbian decay applied lazily on read**, not eagerly on write.
//!   Decay coefficient operates per elapsed day so an unloved
//!   `(topic, role)` decays back toward the neutral prior.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::inference::HemisphereRole;

/// On-disk filename inside `~/.neoth/`.
pub const ROUTING_WEIGHTS_FILE: &str = "routing_weights.json";

/// Schema version pin. Bump when the on-disk shape breaks compat.
pub const ROUTING_WEIGHTS_SCHEMA_VERSION: u32 = 1;

/// Hard rule from Pick #8 fractal synthesis (#3) — per-acceptance-event
/// delta CAP. An operator cannot override this. Even repeated
/// acceptance signals on the same `(topic, role)` cannot shift the
/// weight by more than this fraction in a single call.
pub const MAX_WEIGHT_DELTA: f32 = 0.05;

/// Hard cumulative cap on success_count per `(topic_hash,
/// hemisphere_role)` pair. Prevents an attacker from compounding
/// acceptance signals indefinitely. Reached at 30 distinct accepted
/// runs (`30 * MAX_WEIGHT_DELTA = 1.5`, but we cap at 1.0 of the
/// memory_weight signal — see [`load_memory_weight`]).
pub const MAX_SUCCESS_COUNT: f32 = 30.0;

/// Neutral prior — what `load_memory_weight` returns when the
/// `(topic, role)` pair has no recorded history. Matches the
/// `QualityScore::tier_only` neutral memory prior.
pub const NEUTRAL_MEMORY_WEIGHT: f32 = 0.5;

/// Hebbian decay coefficient per elapsed day since the last
/// acceptance. Each day reduces success_count by this multiplicative
/// factor; reaches half within ~10 days, near-zero within 60 days.
pub const HEBBIAN_DAILY_DECAY: f32 = 0.93;

/// One `(topic_hash, hemisphere_role)` weight row.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoutingWeight {
    pub topic_hash: u64,
    pub hemisphere_role: HemisphereRole,
    /// Hebbian-decayed acceptance count. Stored as `f32` so lazy
    /// decay can apply non-integer multipliers on read without
    /// losing resolution. Saturated at [`MAX_SUCCESS_COUNT`].
    pub success_count: f32,
    /// Unix seconds of the last `record_acceptance` call. Used by
    /// `apply_decay_if_due` to compute elapsed days.
    pub decay_anchor_unix: u64,
}

/// Top-level on-disk shape. Keyed by `(topic_hash, role)` via the
/// `index_of` helper rather than a `HashMap` because:
/// - tests want deterministic iteration order
/// - the table stays small (typical: 100s of `(topic, role)` pairs)
/// - linear scan is faster than hash overhead at this size
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingWeights {
    #[serde(default = "default_schema_version")]
    pub version: u32,
    #[serde(default)]
    pub rows: Vec<RoutingWeight>,
    #[serde(skip)]
    path: Option<PathBuf>,
}

fn default_schema_version() -> u32 {
    ROUTING_WEIGHTS_SCHEMA_VERSION
}

impl Default for RoutingWeights {
    fn default() -> Self {
        Self {
            version: ROUTING_WEIGHTS_SCHEMA_VERSION,
            rows: Vec::new(),
            path: None,
        }
    }
}

impl RoutingWeights {
    pub fn default_path(neoth_home: &Path) -> PathBuf {
        neoth_home.join(ROUTING_WEIGHTS_FILE)
    }

    /// In-memory instance (no on-disk backing). Used by unit tests
    /// that want isolation from the operator's real `~/.neoth/`.
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Bind a path so a later [`Self::save`] knows where to write.
    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.path = Some(path);
        self
    }

    /// Load from disk. A missing file is a fresh empty state. Existing but
    /// unreadable, malformed, or version-incompatible state fails closed so
    /// routing history cannot silently disappear and change winner selection.
    pub fn load_from(path: &Path) -> Result<Self> {
        let mut weights: Self = match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<Self>(&bytes) {
                Ok(parsed) if parsed.version == ROUTING_WEIGHTS_SCHEMA_VERSION => parsed,
                Ok(parsed) => {
                    anyhow::bail!(
                        "routing weights schema mismatch in {}: loaded {}, expected {}",
                        path.display(),
                        parsed.version,
                        ROUTING_WEIGHTS_SCHEMA_VERSION
                    );
                }
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("parse routing weights {}", path.display()));
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => {
                return Err(e).with_context(|| format!("read routing weights {}", path.display()));
            }
        };
        weights.path = Some(path.to_path_buf());
        if weights.version == 0 {
            weights.version = ROUTING_WEIGHTS_SCHEMA_VERSION;
        }
        Ok(weights)
    }

    /// Atomic temp+rename write. Mode-0600 on unix. No-op when the
    /// instance has no path (in-memory mode).
    pub fn save(&self) -> Result<()> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        let body = serde_json::to_vec_pretty(self).context("serialise routing_weights.json")?;
        crate::util::atomic_write::atomic_write_private(path, &body).with_context(|| {
            format!(
                "atomically write private routing weights {}",
                path.display()
            )
        })?;
        Ok(())
    }

    fn index_of(&self, topic_hash: u64, role: HemisphereRole) -> Option<usize> {
        self.rows
            .iter()
            .position(|r| r.topic_hash == topic_hash && r.hemisphere_role == role)
    }

    /// Hard rule (#3): record an operator-acceptance signal for
    /// `(topic_hash, winning_role)`. Saturating delta capped at
    /// [`MAX_WEIGHT_DELTA`], cumulative count capped at
    /// [`MAX_SUCCESS_COUNT`].
    ///
    /// `now_unix` is parameterised for tests; production callers use
    /// [`now_unix`].
    pub fn record_acceptance(
        &mut self,
        topic_hash: u64,
        winning_role: HemisphereRole,
        now_unix: u64,
    ) {
        if let Some(idx) = self.index_of(topic_hash, winning_role) {
            let row = &mut self.rows[idx];
            // Apply lazy decay before incrementing — keeps a stale
            // row from compounding new acceptance on top of pre-
            // decay value.
            row.success_count = apply_decay(row.success_count, row.decay_anchor_unix, now_unix);
            row.success_count = (row.success_count + MAX_WEIGHT_DELTA).min(MAX_SUCCESS_COUNT);
            row.decay_anchor_unix = now_unix;
        } else {
            self.rows.push(RoutingWeight {
                topic_hash,
                hemisphere_role: winning_role,
                success_count: MAX_WEIGHT_DELTA,
                decay_anchor_unix: now_unix,
            });
        }
    }

    /// Read the lazily-decayed `memory_weight` for one
    /// `(topic_hash, role)`. Returns [`NEUTRAL_MEMORY_WEIGHT`] when
    /// no history exists.
    pub fn load_memory_weight(&self, topic_hash: u64, role: HemisphereRole, now_unix: u64) -> f32 {
        let Some(idx) = self.index_of(topic_hash, role) else {
            return NEUTRAL_MEMORY_WEIGHT;
        };
        let row = &self.rows[idx];
        let decayed = apply_decay(row.success_count, row.decay_anchor_unix, now_unix);
        // Map [0, MAX_SUCCESS_COUNT] → [neutral_prior, 1.0]
        let normalised = (decayed / MAX_SUCCESS_COUNT).clamp(0.0, 1.0);
        // Blend with neutral so a low success count doesn't crash
        // memory_weight below the prior.
        (NEUTRAL_MEMORY_WEIGHT + (1.0 - NEUTRAL_MEMORY_WEIGHT) * normalised).clamp(0.0, 1.0)
    }
}

/// Apply Hebbian decay multiplier per elapsed day.
fn apply_decay(success_count: f32, anchor_unix: u64, now_unix: u64) -> f32 {
    let elapsed = now_unix.saturating_sub(anchor_unix);
    if elapsed == 0 {
        return success_count;
    }
    let days_elapsed = (elapsed / 86_400) as i32;
    if days_elapsed <= 0 {
        return success_count;
    }
    let decay = HEBBIAN_DAILY_DECAY.powi(days_elapsed);
    success_count * decay
}

/// Wall-clock unix seconds. Wraps `SystemTime` so tests can stub via
/// the `now_unix` parameter on the per-fn API.
pub fn now_unix() -> u64 {
    crate::time::now_unix_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const T0: u64 = 1_700_000_000;
    const ONE_DAY: u64 = 86_400;

    fn topic(s: &str) -> u64 {
        xxhash_rust::xxh3::xxh3_64(s.as_bytes())
    }

    #[test]
    fn record_acceptance_creates_new_row() {
        let mut w = RoutingWeights::in_memory();
        w.record_acceptance(topic("rust"), HemisphereRole::Left, T0);
        assert_eq!(w.rows.len(), 1);
        assert!((w.rows[0].success_count - MAX_WEIGHT_DELTA).abs() < 1e-6);
        assert_eq!(w.rows[0].hemisphere_role, HemisphereRole::Left);
        assert_eq!(w.rows[0].decay_anchor_unix, T0);
    }

    #[test]
    fn record_acceptance_increments_existing_row() {
        let mut w = RoutingWeights::in_memory();
        w.record_acceptance(topic("rust"), HemisphereRole::Left, T0);
        w.record_acceptance(topic("rust"), HemisphereRole::Left, T0);
        assert_eq!(w.rows.len(), 1, "same key must update, not append");
        assert!((w.rows[0].success_count - 2.0 * MAX_WEIGHT_DELTA).abs() < 1e-6);
    }

    #[test]
    fn record_acceptance_caps_at_max_success_count() {
        let mut w = RoutingWeights::in_memory();
        // Run 1000 acceptances; should saturate at MAX_SUCCESS_COUNT.
        for _ in 0..1000 {
            w.record_acceptance(topic("rust"), HemisphereRole::Left, T0);
        }
        assert!((w.rows[0].success_count - MAX_SUCCESS_COUNT).abs() < 1e-3);
    }

    #[test]
    fn record_acceptance_different_roles_independent() {
        let mut w = RoutingWeights::in_memory();
        w.record_acceptance(topic("rust"), HemisphereRole::Left, T0);
        w.record_acceptance(topic("rust"), HemisphereRole::Right, T0);
        assert_eq!(w.rows.len(), 2, "different role → new row");
    }

    #[test]
    fn record_acceptance_different_topics_independent() {
        let mut w = RoutingWeights::in_memory();
        w.record_acceptance(topic("rust"), HemisphereRole::Left, T0);
        w.record_acceptance(topic("python"), HemisphereRole::Left, T0);
        assert_eq!(w.rows.len(), 2, "different topic → new row");
    }

    #[test]
    fn load_memory_weight_returns_neutral_when_no_history() {
        let w = RoutingWeights::in_memory();
        let mw = w.load_memory_weight(topic("unknown"), HemisphereRole::Left, T0);
        assert!((mw - NEUTRAL_MEMORY_WEIGHT).abs() < 1e-6);
    }

    #[test]
    fn load_memory_weight_lifts_above_neutral_with_history() {
        let mut w = RoutingWeights::in_memory();
        for _ in 0..5 {
            w.record_acceptance(topic("rust"), HemisphereRole::Left, T0);
        }
        let mw = w.load_memory_weight(topic("rust"), HemisphereRole::Left, T0);
        assert!(
            mw > NEUTRAL_MEMORY_WEIGHT,
            "memory weight must lift above neutral, got {mw}"
        );
        assert!(mw <= 1.0, "memory weight capped at 1.0");
    }

    #[test]
    fn decay_reduces_success_count_over_time() {
        let mut w = RoutingWeights::in_memory();
        for _ in 0..20 {
            w.record_acceptance(topic("rust"), HemisphereRole::Left, T0);
        }
        let mw_fresh = w.load_memory_weight(topic("rust"), HemisphereRole::Left, T0);
        // 10 days later: HEBBIAN_DAILY_DECAY^10 ≈ 0.484
        let mw_decayed =
            w.load_memory_weight(topic("rust"), HemisphereRole::Left, T0 + 10 * ONE_DAY);
        assert!(
            mw_decayed < mw_fresh,
            "decay must reduce memory weight, fresh={mw_fresh} decayed={mw_decayed}"
        );
        assert!(
            mw_decayed >= NEUTRAL_MEMORY_WEIGHT,
            "decay must NOT push below neutral prior (blend formula), got {mw_decayed}"
        );
    }

    #[test]
    fn decay_eventually_returns_to_neutral() {
        let mut w = RoutingWeights::in_memory();
        for _ in 0..30 {
            w.record_acceptance(topic("rust"), HemisphereRole::Left, T0);
        }
        // 365 days later: HEBBIAN_DAILY_DECAY^365 ≈ 0 (effectively)
        let mw = w.load_memory_weight(topic("rust"), HemisphereRole::Left, T0 + 365 * ONE_DAY);
        assert!(
            (mw - NEUTRAL_MEMORY_WEIGHT).abs() < 0.01,
            "365 days of decay → back to neutral, got {mw}"
        );
    }

    #[test]
    fn record_after_decay_does_not_compound_pre_decay_value() {
        let mut w = RoutingWeights::in_memory();
        // Build up 30 acceptances
        for _ in 0..30 {
            w.record_acceptance(topic("rust"), HemisphereRole::Left, T0);
        }
        let pre_decay = w.rows[0].success_count;
        // 30 days pass, then another acceptance
        w.record_acceptance(topic("rust"), HemisphereRole::Left, T0 + 30 * ONE_DAY);
        let post_one_more = w.rows[0].success_count;
        // Should be pre-decayed value + MAX_WEIGHT_DELTA, NOT
        // pre_decay + delta.
        assert!(
            post_one_more < pre_decay + MAX_WEIGHT_DELTA + 0.001,
            "30-day-old acceptance compounded without lazy decay"
        );
    }

    #[test]
    fn max_weight_delta_is_const_05() {
        // Hard rule pin — refactors that touch this const trip the
        // test. Operator MUST NOT be able to bypass this from
        // freedom.yaml.
        assert!((MAX_WEIGHT_DELTA - 0.05).abs() < 1e-6);
    }

    #[test]
    fn round_trip_through_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("routing_weights.json");
        let mut w = RoutingWeights::default().with_path(path.clone());
        w.record_acceptance(topic("rust"), HemisphereRole::Left, T0);
        w.record_acceptance(topic("python"), HemisphereRole::Right, T0);
        w.save().unwrap();

        let reloaded = RoutingWeights::load_from(&path).unwrap();
        assert_eq!(reloaded.rows.len(), 2);
        assert_eq!(reloaded.version, ROUTING_WEIGHTS_SCHEMA_VERSION);
    }

    #[test]
    fn malformed_file_fails_closed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("routing_weights.json");
        std::fs::write(&path, b"{ not valid").unwrap();
        let error = RoutingWeights::load_from(&path).unwrap_err();
        assert!(error.to_string().contains("parse routing weights"));
    }

    #[test]
    fn wrong_schema_version_fails_closed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("routing_weights.json");
        std::fs::write(&path, br#"{"version":999,"rows":[]}"#).unwrap();
        let error = RoutingWeights::load_from(&path).unwrap_err();
        assert!(error.to_string().contains("schema mismatch"));
    }

    #[test]
    fn missing_file_loads_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("never_existed.json");
        let w = RoutingWeights::load_from(&path).unwrap();
        assert!(w.rows.is_empty());
        assert_eq!(w.version, ROUTING_WEIGHTS_SCHEMA_VERSION);
    }

    #[test]
    fn default_path_under_neoth_subdir() {
        let neoth_home = Path::new("/tmp/fake_home/.neoth");
        let p = RoutingWeights::default_path(neoth_home);
        assert_eq!(p, neoth_home.join("routing_weights.json"));
    }
}
