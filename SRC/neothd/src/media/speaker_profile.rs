//! GOLD-ADAPT-SPEAKR-02 — Speaker voice-profile re-identification.
//!
//! Re-identifies a speaker from a voice embedding by cosine-matching it against
//! known [`SpeakerProfile`] entries, updating the winning centroid with a 70/30
//! EMA, and applying an ambiguity guard that rejects the match when the two
//! best candidates are too close together.
//!
//! ## Design (re-derived from speakr AGPL concepts; NO code pasted)
//!
//! * **Cosine similarity** — normalised dot product; range \[-1, 1\]. Computed
//!   with a small epsilon guard so a zero-norm embedding never divides by zero.
//! * **Match threshold** — only profiles whose centroid cosine-sim exceeds
//!   `MATCH_THRESHOLD` (0.75) are considered candidates.
//! * **Ambiguity guard** — when the top-2 candidates are within
//!   `AMBIGUITY_MARGIN` (0.05) of each other, confidence is too low to commit
//!   to either name; [`SpeakerMatcher::match_and_label`] returns `None`.
//! * **EMA update** — `centroid = 0.7 * old_centroid + 0.3 * new_embedding`;
//!   re-normalised to unit length so future cosine comparisons stay correct.
//! * **Confidence** — `min(count / 10, 1.0)` capped at 1.0; a single-sample
//!   profile is low-confidence (≤ 0.1), a ten-sample one is fully trusted.
//! * **Auto-label** — when no profile matches, a new `SPEAKER_NN` entry is
//!   created (NN = number of existing profiles + 1).
//!
//! ## Embedding-dimension migration
//!
//! The persisted store records the embedding dimension in
//! [`ProfileStore::embedding_dim`]. On load, if the stored dim does not match
//! the incoming embeddings, the store is discarded and a fresh one is started.
//! This prevents silent cosine-0.0 re-labelling of every known speaker when
//! the operator switches from the 80-dim log-mel encoder to the 512-dim
//! x-vector encoder (or back). The warning is logged at `WARN` level.
//!
//! ## Wiring note
//!
//! The wiring point (`media.auto_speaker_labels: true` + post-transcription
//! embedding path via `stt_dispatch`) is hot-lane adjacent — ship the module
//! + tests standalone first; call `SpeakerMatcher::match_and_label` from the
//! STT post-processing step once embeddings are available. That wire is tracked
//! as a follow-up.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

/// EMA weight on the existing centroid (old).
const EMA_ALPHA: f32 = 0.7;
/// EMA weight on the new embedding (new).
const EMA_BETA: f32 = 0.3;

/// Minimum cosine similarity for a candidate match to be considered.
const MATCH_THRESHOLD: f32 = 0.75;

/// Maximum similarity gap between rank-1 and rank-2 before the result is
/// considered ambiguous and `None` is returned.
const AMBIGUITY_MARGIN: f32 = 0.05;

/// Guard against divide-by-zero in cosine when embeddings are pathologically
/// zero-norm.
const NORM_EPSILON: f32 = 1e-8;

/// Fixed embedding dimensionality emitted by [`crate::media::speaker_encoder`]
/// (mean + std over 40 mel bands). All persisted centroids assume this width:
/// `cosine_similarity` returns 0.0 on a length mismatch, so **changing this
/// silently re-labels every learned speaker as a new `SPEAKER_NN`** — bump it
/// only alongside wiping `speaker_profiles.json`.
pub const SPEAKER_EMBEDDING_DIM: usize = 80;

/// A speaker's learned centroid + metadata.
///
/// The `avg_embedding` is always unit-norm (enforced by [`ema_update`]).
/// `count` tracks how many observations have been folded in so confidence
/// can be calibrated.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SpeakerProfile {
    /// Stable identifier ("Alex", "SPEAKER_01", …).
    pub name: String,
    /// Running centroid — unit-normalised after every EMA step.
    pub avg_embedding: Vec<f32>,
    /// Number of observations folded into the centroid so far.
    pub count: u32,
    /// Confidence score in \[0, 1\]; derived from `count` but stored so
    /// callers don't need to recompute it.
    pub confidence: f32,
}

impl SpeakerProfile {
    /// Create a new profile seeded by a single observation.
    ///
    /// The embedding is unit-normalised; confidence starts low (0.1 for the
    /// first sample — `min(1 / 10, 1.0)`).
    pub fn new(name: impl Into<String>, embedding: Vec<f32>) -> Self {
        let normed = unit_normalise(&embedding);
        let count = 1u32;
        Self {
            name: name.into(),
            avg_embedding: normed,
            count,
            confidence: compute_confidence(count),
        }
    }

    /// Fold a new observation in via the 70/30 EMA and re-normalise.
    pub fn update(&mut self, new_embedding: &[f32]) {
        self.avg_embedding = ema_update(&self.avg_embedding, new_embedding);
        self.count = self.count.saturating_add(1);
        self.confidence = compute_confidence(self.count);
    }
}

// ── math helpers ────────────────────────────────────────────────────────────

/// L2-normalise a vector to unit length.
///
/// If the vector has near-zero norm (pathological input) it is returned as-is
/// to avoid NaN propagation; the caller should treat that embedding as
/// unreliable.
pub fn unit_normalise(v: &[f32]) -> Vec<f32> {
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm < NORM_EPSILON {
        return v.to_vec();
    }
    v.iter().map(|x| x / norm).collect()
}

/// Cosine similarity of two vectors.
///
/// Returns a value in \[-1, 1\].  Zero-norm inputs safely return 0.0 (no
/// match) rather than NaN.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        // Dimension mismatch — graceful degradation: return 0.0 (no match).
        // In production this is a bug; the caller's embedding pipeline should
        // emit uniform-dimension vectors.
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    let denom = na * nb;
    if denom < NORM_EPSILON {
        return 0.0;
    }
    (dot / denom).clamp(-1.0, 1.0)
}

/// 70 / 30 exponential moving average then re-normalise.
fn ema_update(old_centroid: &[f32], new_embedding: &[f32]) -> Vec<f32> {
    let blended: Vec<f32> = old_centroid
        .iter()
        .zip(new_embedding.iter())
        .map(|(o, n)| EMA_ALPHA * o + EMA_BETA * n)
        .collect();
    unit_normalise(&blended)
}

/// Map observation count to a confidence score in \[0, 1\].
///
/// 10 or more observations → fully confident (1.0).
fn compute_confidence(count: u32) -> f32 {
    (count as f32 / 10.0).min(1.0)
}

// ── matcher ─────────────────────────────────────────────────────────────────

/// Match result returned by [`SpeakerMatcher::match_and_label`].
#[derive(Debug, Clone, PartialEq)]
pub struct MatchResult {
    /// The matched (or newly assigned) speaker name.
    pub name: String,
    /// Cosine similarity of the winning match (or 0.0 for a new speaker).
    pub similarity: f32,
    /// Confidence derived from the profile's observation count.
    pub confidence: f32,
    /// Whether this was a new profile created for an unlabelled speaker.
    pub is_new: bool,
}

/// Stateful matcher over a collection of speaker profiles.
///
/// Holds the profiles in memory; serialise to/from the `speaker_profiles`
/// SQLite table at the call site (not here — pure data logic).
#[derive(Debug, Default)]
pub struct SpeakerMatcher {
    profiles: Vec<SpeakerProfile>,
}

impl SpeakerMatcher {
    /// Create a matcher from pre-loaded profiles (e.g. from the store).
    pub fn from_profiles(profiles: Vec<SpeakerProfile>) -> Self {
        Self { profiles }
    }

    /// Borrow the current profile list (for persistence).
    pub fn profiles(&self) -> &[SpeakerProfile] {
        &self.profiles
    }

    /// Match `embedding` against known profiles.
    ///
    /// Returns:
    /// * `Some(MatchResult { is_new: false, … })` — clear winner above
    ///   threshold with no ambiguity.
    /// * `None` — top-2 candidates are within `AMBIGUITY_MARGIN` of each
    ///   other; the caller should not commit to either label.
    /// * `Some(MatchResult { is_new: true, … })` — no candidate exceeds the
    ///   threshold; a new `SPEAKER_NN` profile is created and returned.
    ///
    /// **Side effect**: the winning profile's centroid is updated in-place via
    /// the 70/30 EMA (even on a new profile — its first observation IS its
    /// centroid, so `new()` already handles that path).
    pub fn match_and_label(&mut self, embedding: &[f32]) -> Option<MatchResult> {
        // Score all existing profiles.
        let mut scored: Vec<(usize, f32)> = self
            .profiles
            .iter()
            .enumerate()
            .map(|(i, p)| (i, cosine_similarity(&p.avg_embedding, embedding)))
            .filter(|(_, sim)| *sim >= MATCH_THRESHOLD)
            .collect();

        // Sort descending by similarity.
        scored.sort_unstable_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        match scored.as_slice() {
            // ── ambiguity guard ───────────────────────────────────────────
            [(_, sim1), (_, sim2), ..] if sim1 - sim2 <= AMBIGUITY_MARGIN => {
                // Top-2 too close — refuse to label.
                None
            }

            // ── clear winner ──────────────────────────────────────────────
            [(winner_idx, sim), ..] => {
                let idx = *winner_idx;
                let similarity = *sim;
                self.profiles[idx].update(embedding);
                Some(MatchResult {
                    name: self.profiles[idx].name.clone(),
                    similarity,
                    confidence: self.profiles[idx].confidence,
                    is_new: false,
                })
            }

            // ── no match — new speaker ────────────────────────────────────
            [] => {
                let new_name = format!("SPEAKER_{:02}", self.profiles.len() + 1);
                let profile = SpeakerProfile::new(&new_name, embedding.to_vec());
                let confidence = profile.confidence;
                self.profiles.push(profile);
                Some(MatchResult {
                    name: new_name,
                    similarity: 0.0,
                    confidence,
                    is_new: true,
                })
            }
        }
    }
}

// ── SPEAKR-02b / SPEAKR-02c: persistent profile store + dim-migration ────────

/// On-disk JSON envelope for the speaker profile store.
///
/// Wraps the profile list with the embedding dimension so we can detect
/// dimension changes (e.g. switching from the 80-dim log-mel encoder to the
/// 512-dim x-vector encoder) and reset the store rather than silently
/// mismatching cosines.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ProfileStore {
    /// Embedding dimension all centroids were trained on.
    embedding_dim: usize,
    /// The stored profiles.
    profiles: Vec<SpeakerProfile>,
}

type ProfileTransactionLock = Mutex<()>;

/// Process-wide lock registry keyed by the canonical speaker-profile path.
///
/// Speaker labelling is a read-modify-write transaction: loading and matching
/// under separate locks would still allow two concurrent STT calls to assign
/// the same `SPEAKER_NN` or lose one centroid update. A distinct lock per home
/// preserves concurrency between isolated NEOTH homes while serialising the
/// full transaction within one home. Weak entries keep the registry bounded as
/// short-lived/test homes disappear.
static PROFILE_TRANSACTION_LOCKS: OnceLock<Mutex<HashMap<PathBuf, Weak<ProfileTransactionLock>>>> =
    OnceLock::new();

fn profile_lock_key(home: &Path) -> PathBuf {
    let absolute_home = if home.is_absolute() {
        home.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(home))
            .unwrap_or_else(|_| home.to_path_buf())
    };
    std::fs::canonicalize(&absolute_home)
        .unwrap_or(absolute_home)
        .join("speaker_profiles.json")
}

fn profile_transaction_lock(home: &Path) -> Arc<ProfileTransactionLock> {
    let key = profile_lock_key(home);
    let registry = PROFILE_TRANSACTION_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut locks = registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}

/// Default profile-store path: `<home>/speaker_profiles.json`.
pub fn profiles_path(home: &std::path::Path) -> std::path::PathBuf {
    home.join("speaker_profiles.json")
}

/// Load the persisted speaker profiles.
///
/// `incoming_dim` is the dimensionality of the embeddings the caller is about
/// to produce. If the store exists but was written with a different dimension,
/// it is discarded (logged at `WARN`) and an empty list is returned — preventing
/// silent cosine-0.0 mismatches on every speaker.
///
/// Absent / unreadable / corrupt file → empty (fresh start, no warning).
pub fn load_profiles(path: &std::path::Path, incoming_dim: usize) -> Vec<SpeakerProfile> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Vec::new(), // file absent or unreadable → fresh start
    };

    // Try the new envelope format first.
    if let Ok(store) = serde_json::from_str::<ProfileStore>(&raw) {
        if store.embedding_dim != incoming_dim {
            tracing::warn!(
                stored_dim = store.embedding_dim,
                incoming_dim,
                "speaker_profile: embedding dimension changed — discarding {} profile(s) \
                 and starting fresh (re-learn will happen automatically)",
                store.profiles.len()
            );
            return Vec::new();
        }
        return store.profiles;
    }

    // Legacy format: bare Vec<SpeakerProfile> (written before dim-migration).
    // Accept only if the actual centroid lengths match incoming_dim.
    if let Ok(profiles) = serde_json::from_str::<Vec<SpeakerProfile>>(&raw) {
        let consistent = profiles.is_empty()
            || profiles
                .iter()
                .all(|p| p.avg_embedding.len() == incoming_dim);
        if consistent {
            return profiles;
        }
        tracing::warn!(
            incoming_dim,
            "speaker_profile: legacy store has mismatched embedding dim — discarding and starting fresh"
        );
    }

    Vec::new()
}

/// Persist the profiles (atomic private write). Best-effort: a write/serialise
/// error is logged, never propagated (speaker labelling must never fail a
/// transcription). On Unix the store is always narrowed to mode `0600` before
/// its biometric centroids are written.
///
/// Writes the new envelope format with `embedding_dim` recorded.
pub fn save_profiles(path: &std::path::Path, profiles: &[SpeakerProfile], embedding_dim: usize) {
    let embedding_dim = if profiles.is_empty() {
        // No profiles yet — record the dim so the next load can gate correctly.
        embedding_dim
    } else {
        // Sanity-check: all centroids should be the declared dim.
        let actual = profiles[0].avg_embedding.len();
        if actual != embedding_dim {
            tracing::warn!(
                declared = embedding_dim,
                actual,
                "speaker_profile: dim mismatch on save — using actual centroid length"
            );
            actual
        } else {
            embedding_dim
        }
    };

    let store = ProfileStore {
        embedding_dim,
        profiles: profiles.to_vec(),
    };
    match serde_json::to_vec_pretty(&store) {
        Ok(bytes) => {
            if let Err(e) = crate::util::atomic_write::atomic_write_private(path, &bytes) {
                tracing::warn!(error = %e, "speaker_profile: persist failed (non-fatal)");
            }
        }
        Err(e) => tracing::warn!(error = %e, "speaker_profile: serialise failed"),
    }
}

/// SPEAKR-02b — label a batch of per-utterance voice embeddings against the
/// persisted speaker-profile store, returning one label per embedding (`None`
/// when the matcher refuses to commit on an ambiguous top-2). Side effect: the
/// matched/new profiles' centroids are EMA-updated and the store is re-persisted,
/// so speaker identity LEARNS across calls. Empty input → empty output + NO file
/// I/O — the no-op path the STT dispatch hits until a voice-embedding source (a
/// speaker encoder over the raw PCM) is wired.
pub fn label_embeddings(home: &std::path::Path, embeddings: &[Vec<f32>]) -> Vec<Option<String>> {
    if embeddings.is_empty() {
        return Vec::new();
    }
    let transaction_lock = profile_transaction_lock(home);
    let _transaction_guard = transaction_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let incoming_dim = embeddings[0].len();
    let path = profiles_path(home);
    let mut matcher = SpeakerMatcher::from_profiles(load_profiles(&path, incoming_dim));
    let labels: Vec<Option<String>> = embeddings
        .iter()
        .map(|emb| matcher.match_and_label(emb).map(|m| m.name))
        .collect();
    save_profiles(&path, matcher.profiles(), incoming_dim);
    labels
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_embeddings_empty_is_noop_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(label_embeddings(tmp.path(), &[]).is_empty());
        assert!(
            !profiles_path(tmp.path()).exists(),
            "empty input must not write the store"
        );
    }

    #[test]
    fn label_embeddings_persists_and_reidentifies_speaker() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let a = vec![1.0f32, 0.0, 0.0];
        let b = vec![0.0f32, 1.0, 0.0];
        let first = label_embeddings(home, &[a.clone(), b.clone()]);
        assert_eq!(first.len(), 2);
        assert!(first[0].is_some() && first[1].is_some());
        assert_ne!(first[0], first[1], "distinct voices → distinct labels");
        assert!(profiles_path(home).exists(), "store persisted");
        // Re-present speaker A → SAME label from the persisted profile (learning).
        let again = label_embeddings(home, &[a]);
        assert_eq!(
            again[0], first[0],
            "persisted profile re-identifies speaker A"
        );
    }

    // ── transactional persistence ───────────────────────────────────────────────

    #[test]
    fn concurrent_updates_in_one_home_are_not_lost() {
        const THREADS: usize = 16;

        let tmp = tempfile::tempdir().unwrap();
        let home = Arc::new(tmp.path().to_path_buf());
        let barrier = Arc::new(std::sync::Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|index| {
                let home = Arc::clone(&home);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let mut embedding = vec![0.0f32; THREADS];
                    embedding[index] = 1.0;
                    barrier.wait();
                    let labels = label_embeddings(&home, &[embedding]);
                    assert_eq!(labels.len(), 1);
                    assert!(labels[0].is_some());
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let profiles = load_profiles(&profiles_path(&home), THREADS);
        assert_eq!(
            profiles.len(),
            THREADS,
            "every concurrent update must survive"
        );
        let unique_names: std::collections::HashSet<_> = profiles
            .iter()
            .map(|profile| profile.name.as_str())
            .collect();
        assert_eq!(
            unique_names.len(),
            THREADS,
            "speaker ids must remain unique"
        );
    }

    #[test]
    fn profile_transactions_are_scoped_per_home() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();

        let first_lock = profile_transaction_lock(first.path());
        let first_lock_again = profile_transaction_lock(first.path());
        let second_lock = profile_transaction_lock(second.path());
        assert!(Arc::ptr_eq(&first_lock, &first_lock_again));
        assert!(!Arc::ptr_eq(&first_lock, &second_lock));

        let embedding = vec![1.0f32, 0.0, 0.0];
        assert_eq!(
            label_embeddings(first.path(), std::slice::from_ref(&embedding))[0].as_deref(),
            Some("SPEAKER_01")
        );
        assert_eq!(
            label_embeddings(second.path(), std::slice::from_ref(&embedding))[0].as_deref(),
            Some("SPEAKER_01")
        );
        label_embeddings(first.path(), &[embedding]);

        let first_profiles = load_profiles(&profiles_path(first.path()), 3);
        let second_profiles = load_profiles(&profiles_path(second.path()), 3);
        assert_eq!(first_profiles[0].count, 2);
        assert_eq!(second_profiles[0].count, 1);
    }

    #[cfg(unix)]
    #[test]
    fn profile_store_is_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let path = profiles_path(tmp.path());
        std::fs::write(&path, b"legacy").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let profile = SpeakerProfile::new("Alice", vec![1.0f32, 0.0, 0.0]);
        save_profiles(&path, &[profile], 3);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "speaker centroids must never be world-readable"
        );
    }

    // ── dim-migration ─────────────────────────────────────────────────────────

    #[test]
    fn dim_change_discards_store_and_starts_fresh() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let path = profiles_path(home);

        // Write a store with dim=80 (log-mel encoder).
        let p80 = SpeakerProfile::new("Alice", vec![1.0f32; 80]);
        save_profiles(&path, &[p80], 80);
        assert!(path.exists(), "store should exist after save");

        // Load with dim=512 (x-vector encoder) → store must be discarded.
        let loaded = load_profiles(&path, 512);
        assert!(
            loaded.is_empty(),
            "expected fresh store on dim change 80→512, got {} profile(s)",
            loaded.len()
        );
    }

    #[test]
    fn same_dim_load_recovers_profiles() {
        let tmp = tempfile::tempdir().unwrap();
        let path = profiles_path(tmp.path());

        let p = SpeakerProfile::new("Bob", vec![1.0f32; 3]);
        save_profiles(&path, &[p], 3);
        let loaded = load_profiles(&path, 3);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "Bob");
    }

    #[test]
    fn legacy_format_accepted_when_dim_matches() {
        // Bare Vec<SpeakerProfile> JSON (old format before ProfileStore wrapper).
        let tmp = tempfile::tempdir().unwrap();
        let path = profiles_path(tmp.path());

        let profiles = vec![SpeakerProfile::new("Carol", vec![0.5f32; 4])];
        let json = serde_json::to_vec_pretty(&profiles).unwrap();
        std::fs::write(&path, &json).unwrap();

        let loaded = load_profiles(&path, 4);
        assert_eq!(
            loaded.len(),
            1,
            "legacy format with matching dim should load"
        );
        assert_eq!(loaded[0].name, "Carol");
    }

    #[test]
    fn legacy_format_discarded_on_dim_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let path = profiles_path(tmp.path());

        // Legacy format with dim=2 centroids.
        let profiles = vec![SpeakerProfile::new("Dave", vec![1.0f32, 0.0])];
        let json = serde_json::to_vec_pretty(&profiles).unwrap();
        std::fs::write(&path, &json).unwrap();

        // Load expecting dim=512.
        let loaded = load_profiles(&path, 512);
        assert!(
            loaded.is_empty(),
            "legacy store with wrong dim must be discarded, got {} profile(s)",
            loaded.len()
        );
    }

    // ── cosine_similarity ─────────────────────────────────────────────────────

    #[test]
    fn cosine_identical_unit_vectors_is_one() {
        let v = vec![1.0_f32, 0.0, 0.0];
        assert!((cosine_similarity(&v, &v) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_orthogonal_vectors_is_zero() {
        let a = vec![1.0_f32, 0.0, 0.0];
        let b = vec![0.0_f32, 1.0, 0.0];
        assert!(cosine_similarity(&a, &b).abs() < 1e-6);
    }

    #[test]
    fn cosine_opposite_vectors_is_neg_one() {
        let a = vec![1.0_f32, 0.0];
        let b = vec![-1.0_f32, 0.0];
        assert!((cosine_similarity(&a, &b) + 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_zero_norm_returns_zero_not_nan() {
        let z = vec![0.0_f32, 0.0, 0.0];
        let v = vec![1.0_f32, 0.0, 0.0];
        let result = cosine_similarity(&z, &v);
        assert_eq!(result, 0.0);
        assert!(!result.is_nan());
    }

    #[test]
    fn cosine_dimension_mismatch_returns_zero() {
        let a = vec![1.0_f32, 0.0];
        let b = vec![1.0_f32, 0.0, 0.0];
        assert_eq!(cosine_similarity(&a, &b), 0.0);
    }

    #[test]
    fn cosine_scaled_vectors_same_as_unit() {
        // [2,0,0] vs [3,0,0] → cosine should be 1.0 regardless of magnitude.
        let a = vec![2.0_f32, 0.0, 0.0];
        let b = vec![3.0_f32, 0.0, 0.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 1e-6);
    }

    // ── unit_normalise ────────────────────────────────────────────────────────

    #[test]
    fn unit_normalise_produces_unit_length() {
        let v = vec![3.0_f32, 4.0, 0.0]; // norm = 5
        let n = unit_normalise(&v);
        let norm: f32 = n.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-6);
    }

    #[test]
    fn unit_normalise_zero_vector_passthrough() {
        let v = vec![0.0_f32, 0.0];
        let n = unit_normalise(&v);
        // Should not panic and should not produce NaN.
        assert!(n.iter().all(|x| !x.is_nan()));
    }

    // ── SpeakerProfile ────────────────────────────────────────────────────────

    #[test]
    fn new_profile_has_unit_norm_centroid() {
        let p = SpeakerProfile::new("Alex", vec![3.0_f32, 4.0, 0.0]);
        let norm: f32 = p.avg_embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-6);
    }

    #[test]
    fn single_sample_confidence_is_low() {
        let p = SpeakerProfile::new("Alex", vec![1.0_f32, 0.0]);
        // 1 / 10 = 0.1
        assert!((p.confidence - 0.1).abs() < 1e-6);
    }

    #[test]
    fn ten_samples_confidence_is_full() {
        let mut p = SpeakerProfile::new("Alex", vec![1.0_f32, 0.0]);
        for _ in 0..9 {
            p.update(&[1.0_f32, 0.0]);
        }
        assert!((p.confidence - 1.0).abs() < 1e-6);
    }

    #[test]
    fn ema_update_moves_centroid_toward_new() {
        // old centroid = [1, 0], new = [0, 1]
        // blended = [0.7, 0.3], normalised ≈ [0.919, 0.394]
        let old = vec![1.0_f32, 0.0];
        let new_emb = vec![0.0_f32, 1.0];
        let mut p = SpeakerProfile::new("A", old);
        p.update(&new_emb);
        // centroid must still be unit norm
        let norm: f32 = p.avg_embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-6);
        // x-component should be > 0 (pulled from 1 toward 0.7) and y > 0
        assert!(p.avg_embedding[0] > 0.0);
        assert!(p.avg_embedding[1] > 0.0);
    }

    #[test]
    fn profile_count_increments_on_update() {
        let mut p = SpeakerProfile::new("A", vec![1.0_f32, 0.0]);
        assert_eq!(p.count, 1);
        p.update(&[1.0, 0.0]);
        assert_eq!(p.count, 2);
    }

    // ── SpeakerMatcher — clear match ─────────────────────────────────────────

    #[test]
    fn exact_match_returns_profile_name() {
        let mut m = SpeakerMatcher::default();
        let emb = vec![1.0_f32, 0.0, 0.0];
        // Seed with a profile.
        m.match_and_label(&emb); // creates SPEAKER_01
        // Present the same embedding again.
        let result = m.match_and_label(&emb).expect("should match SPEAKER_01");
        assert_eq!(result.name, "SPEAKER_01");
        assert!(!result.is_new);
        assert!((result.similarity - 1.0).abs() < 1e-4);
    }

    #[test]
    fn near_match_above_threshold_returns_name() {
        let mut m = SpeakerMatcher::default();
        // Seed profile at [1,0].
        m.profiles
            .push(SpeakerProfile::new("Bob", vec![1.0_f32, 0.0]));
        // Query very close to [1,0] — should match.
        let query = unit_normalise(&[0.99_f32, 0.01]);
        let result = m.match_and_label(&query).expect("should match Bob");
        assert_eq!(result.name, "Bob");
        assert!(!result.is_new);
    }

    // ── SpeakerMatcher — new speaker ─────────────────────────────────────────

    #[test]
    fn no_profiles_creates_speaker_01() {
        let mut m = SpeakerMatcher::default();
        let result = m.match_and_label(&[1.0_f32, 0.0]).expect("new speaker");
        assert_eq!(result.name, "SPEAKER_01");
        assert!(result.is_new);
        assert_eq!(result.similarity, 0.0);
        assert_eq!(m.profiles.len(), 1);
    }

    #[test]
    fn orthogonal_embedding_creates_second_profile() {
        let mut m = SpeakerMatcher::default();
        m.match_and_label(&[1.0_f32, 0.0]); // SPEAKER_01
        // Orthogonal embedding — cosine is 0 < MATCH_THRESHOLD.
        let result = m.match_and_label(&[0.0_f32, 1.0]).expect("new speaker");
        assert_eq!(result.name, "SPEAKER_02");
        assert!(result.is_new);
        assert_eq!(m.profiles.len(), 2);
    }

    // ── SpeakerMatcher — ambiguity guard ─────────────────────────────────────

    #[test]
    fn ambiguous_pair_returns_none() {
        let mut m = SpeakerMatcher::default();
        // Two profiles almost identical to each other.
        // cos([1,ε], [1,0]) ≈ 1.0 for both.
        let eps = 0.001_f32;
        m.profiles
            .push(SpeakerProfile::new("Alice", unit_normalise(&[1.0, eps])));
        m.profiles
            .push(SpeakerProfile::new("Bob", unit_normalise(&[1.0, -eps])));

        // Query right in the middle — both should score nearly identically.
        let query = unit_normalise(&[1.0_f32, 0.0]);
        let result = m.match_and_label(&query);
        assert!(
            result.is_none(),
            "expected None for ambiguous pair, got {result:?}"
        );
    }

    #[test]
    fn non_ambiguous_pair_resolves() {
        let mut m = SpeakerMatcher::default();
        // Profile A close to [1,0], B close to [0,1].
        m.profiles
            .push(SpeakerProfile::new("Alice", unit_normalise(&[1.0, 0.05])));
        m.profiles
            .push(SpeakerProfile::new("Bob", unit_normalise(&[0.05, 1.0])));

        // Query near [1,0] — Alice should win clearly.
        let query = unit_normalise(&[1.0_f32, 0.01]);
        let result = m.match_and_label(&query).expect("Alice should win");
        assert_eq!(result.name, "Alice");
    }

    // ── EMA centroid drift ────────────────────────────────────────────────────

    #[test]
    fn repeated_updates_keep_centroid_unit_norm() {
        let mut m = SpeakerMatcher::default();
        m.match_and_label(&[1.0_f32, 0.0]); // creates SPEAKER_01
        // Feed many slight variations.
        for i in 0..20 {
            let angle = (i as f32) * 0.01;
            let emb = unit_normalise(&[angle.cos(), angle.sin()]);
            // May return Some or None depending on drift; we only care that
            // the centroid stays normalised.
            m.match_and_label(&emb);
        }
        let norm: f32 = m.profiles[0]
            .avg_embedding
            .iter()
            .map(|x| x * x)
            .sum::<f32>()
            .sqrt();
        assert!((norm - 1.0).abs() < 1e-5);
    }

    #[test]
    fn ema_weight_70_30_is_applied() {
        // Start with centroid = [1, 0].  Feed [0, 1].
        // After one step: blended = [0.7, 0.3], normalised ≈ [0.919, 0.394].
        let old = unit_normalise(&[1.0_f32, 0.0]);
        let new_e = unit_normalise(&[0.0_f32, 1.0]);

        let mut p = SpeakerProfile {
            name: "T".into(),
            avg_embedding: old.clone(),
            count: 1,
            confidence: 0.1,
        };
        p.update(&new_e);

        let expected_x = 0.7_f32 / (0.7_f32 * 0.7 + 0.3_f32 * 0.3).sqrt();
        let expected_y = 0.3_f32 / (0.7_f32 * 0.7 + 0.3_f32 * 0.3).sqrt();
        assert!(
            (p.avg_embedding[0] - expected_x).abs() < 1e-5,
            "x: got {} expected {expected_x}",
            p.avg_embedding[0]
        );
        assert!(
            (p.avg_embedding[1] - expected_y).abs() < 1e-5,
            "y: got {} expected {expected_y}",
            p.avg_embedding[1]
        );
    }
}
