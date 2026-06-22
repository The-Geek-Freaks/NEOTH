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
//! ## Wiring note
//!
//! The wiring point (`media.auto_speaker_labels: true` + post-transcription
//! embedding path via `stt_dispatch`) is hot-lane adjacent — ship the module
//! + tests standalone first; call `SpeakerMatcher::match_and_label` from the
//! STT post-processing step once embeddings are available. That wire is tracked
//! as a follow-up.

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

// ── SPEAKR-02b: persistent profile store + STT-dispatch labelling entry ──────

/// Default profile-store path: `<home>/speaker_profiles.json`.
pub fn profiles_path(home: &std::path::Path) -> std::path::PathBuf {
    home.join("speaker_profiles.json")
}

/// Load the persisted speaker profiles. Absent/unreadable/corrupt file → empty
/// (a fresh operator simply starts with no known speakers).
pub fn load_profiles(path: &std::path::Path) -> Vec<SpeakerProfile> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Persist the profiles (atomic write). Best-effort: a write/serialise error is
/// logged, never propagated (speaker labelling must never fail a transcription).
pub fn save_profiles(path: &std::path::Path, profiles: &[SpeakerProfile]) {
    match serde_json::to_vec_pretty(profiles) {
        Ok(bytes) => {
            if let Err(e) = crate::util::atomic_write::atomic_write(path, &bytes) {
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
    let path = profiles_path(home);
    let mut matcher = SpeakerMatcher::from_profiles(load_profiles(&path));
    let labels: Vec<Option<String>> = embeddings
        .iter()
        .map(|emb| matcher.match_and_label(emb).map(|m| m.name))
        .collect();
    save_profiles(&path, matcher.profiles());
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
        assert_eq!(again[0], first[0], "persisted profile re-identifies speaker A");
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
        m.profiles.push(SpeakerProfile::new("Bob", vec![1.0_f32, 0.0]));
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
