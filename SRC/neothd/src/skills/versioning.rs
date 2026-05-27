//! Round-3 v0.4 ARCH-07 — LOWKEY skill versioning + prompt-bundle
//! hashing primitives.
//!
//! Two cryptographic identifiers ARCH-07 reserves for the replay-
//! determinism + audit-chain stack:
//!
//! 1. **content_hash** = `SHA-256(yaml || template)` computed at
//!    skill-load time. A reviewer reading WAL frames can verify
//!    "the skill that injected at turn T was definitely the file
//!    on disk at audit time" by recomputing the hash; a divergence
//!    means the skill was edited since.
//!
//! 2. **prompt_bundle_hash** = `SHA-256(Block A || Block B || …
//!    || Block E)` computed per PROVIDER_REQUEST. Lets a future
//!    council adversarial test (ARCH-02 `test_prompt_bundle_replay_
//!    determinism`) verify "given the same prompt_bundle_hash the
//!    same provider produces the same response bytes" without
//!    re-serialising the bundle to compare.
//!
//! Both helpers are pure-fn. Integration into the skill loader +
//! prompt assembler + provider request emission is the downstream
//! wiring slice that follows. The WAL event registry entry
//! (`EVENT_TYPE_SKILL_INJECT_SKIPPED = 0x29`) ships in this same
//! commit so the audit emit-site can land cleanly once the
//! integration arrives.
//!
//! ## Why SHA-256 (not BLAKE3 / SHA-3)
//!
//! Already in tree (`sha2 = "0.10"`) — no new dep. The hash is
//! used purely for collision-resistance in operator audit (not
//! adversarial pre-image resistance against a sophisticated
//! attacker); SHA-256 is more than enough + matches the
//! HMAC-SHA256 compaction marker family in `wal/compaction.rs`.

use sha2::{Digest, Sha256};

/// Block label tag used in `prompt_bundle_hash` canonical encoding.
/// Single-character ASCII A..E + the literal `"Conductor"` for the
/// orchestrator-metadata block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BundleBlock {
    A,
    B,
    C,
    D,
    E,
    Conductor,
}

impl BundleBlock {
    /// Canonical 1-or-9-char tag the hash encoder prepends before
    /// each block's content bytes. Pinned so the hash stays stable
    /// across binary versions.
    pub fn tag(self) -> &'static str {
        match self {
            BundleBlock::A => "A",
            BundleBlock::B => "B",
            BundleBlock::C => "C",
            BundleBlock::D => "D",
            BundleBlock::E => "E",
            BundleBlock::Conductor => "Conductor",
        }
    }

    /// Canonical sort order: A < B < C < D < E < Conductor. Used by
    /// [`compute_prompt_bundle_hash`] so callers can pass blocks in
    /// any order + still get the same hash for the same content set.
    pub fn sort_key(self) -> u8 {
        match self {
            BundleBlock::A => 0,
            BundleBlock::B => 1,
            BundleBlock::C => 2,
            BundleBlock::D => 3,
            BundleBlock::E => 4,
            BundleBlock::Conductor => 5,
        }
    }
}

/// One block-tag + content pair for [`compute_prompt_bundle_hash`].
/// Callers construct one per block they emit into the prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleBlockEntry<'a> {
    pub block: BundleBlock,
    pub content: &'a str,
}

/// SHA-256(yaml || template) — the per-skill content fingerprint.
/// Concatenation is byte-exact (no separator) so a future tweak to
/// the separator would force every existing skill's hash to drift;
/// keep `yaml || template` literal.
///
/// Returns the 32-byte raw digest. Use [`skill_content_hash_hex`]
/// when the operator-visible 64-char hex form is needed.
pub fn compute_skill_content_hash(yaml: &str, template: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(yaml.as_bytes());
    hasher.update(template.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Lower-case 64-char hex of [`compute_skill_content_hash`]. Used as
/// the operator-readable `content_hash` field in
/// `EVENT_TYPE_SKILL_INJECT_SKIPPED` + the skill-versioning audit
/// log.
pub fn skill_content_hash_hex(yaml: &str, template: &str) -> String {
    hex_encode_lower(&compute_skill_content_hash(yaml, template))
}

/// Compute the prompt-bundle hash over a canonical encoding of the
/// supplied blocks. Encoding scheme:
///
/// ```text
/// for each block in canonical order (A, B, C, D, E, Conductor):
///   if present:
///     hasher.update(tag_bytes)
///     hasher.update(b"\x1f")            // ASCII unit-separator
///     hasher.update(content_bytes)
///     hasher.update(b"\x1e")            // ASCII record-separator
///   else:
///     skip (no zero-length placeholder; an absent block ≠ empty block)
/// ```
///
/// The ASCII unit/record separators (`\x1f` / `\x1e`) are control
/// characters that almost never appear in real prompt text; using
/// them as block delimiters means a contributor can't accidentally
/// craft a content string that re-derives a different bundle's
/// hash by spoofing the delimiter sequence.
///
/// Sort-on-encode means callers can pass blocks in any order +
/// still get the same hash for the same content set. Duplicate
/// blocks (e.g. two `Block::D` entries) get encoded in input order
/// after the canonical block-tag sort — preserving any operator-
/// chosen item-within-block ordering for D's recall list.
pub fn compute_prompt_bundle_hash(blocks: &[BundleBlockEntry<'_>]) -> [u8; 32] {
    let mut sorted: Vec<&BundleBlockEntry<'_>> = blocks.iter().collect();
    sorted.sort_by_key(|e| e.block.sort_key());
    let mut hasher = Sha256::new();
    for entry in sorted {
        hasher.update(entry.block.tag().as_bytes());
        hasher.update(b"\x1f");
        hasher.update(entry.content.as_bytes());
        hasher.update(b"\x1e");
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Hex-encoded form of [`compute_prompt_bundle_hash`] for the
/// PROVIDER_REQUEST payload + operator-visible audit logs.
pub fn prompt_bundle_hash_hex(blocks: &[BundleBlockEntry<'_>]) -> String {
    hex_encode_lower(&compute_prompt_bundle_hash(blocks))
}

/// Reason why a skill injection was skipped. Carried in the
/// `EVENT_TYPE_SKILL_INJECT_SKIPPED` WAL payload + the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillSkipReason {
    /// `freedom.yaml::skills.disabled_for_eval_sessions = true` AND
    /// the current session is flagged as an eval run. Skills are
    /// suppressed to avoid biasing the eval baseline.
    EvalSession,
    /// Operator explicitly disabled the skill via
    /// `neoth skills disable <id>`.
    OperatorDisabled,
    /// The on-disk content_hash doesn't match the pinned baseline
    /// hash in the skill's freedom.yaml entry — operator-installed
    /// integrity guard.
    HashMismatch,
    /// The Skills feature is gated off at compile time
    /// (`--no-default-features`).
    FeatureOff,
}

impl SkillSkipReason {
    /// Canonical snake_case string for the WAL payload.
    pub fn as_str(self) -> &'static str {
        match self {
            SkillSkipReason::EvalSession => "eval_session",
            SkillSkipReason::OperatorDisabled => "operator_disabled",
            SkillSkipReason::HashMismatch => "hash_mismatch",
            SkillSkipReason::FeatureOff => "feature_off",
        }
    }
}

fn hex_encode_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(hex_nibble(b >> 4));
        s.push(hex_nibble(b & 0x0F));
    }
    s
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => unreachable!("u4"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(block: BundleBlock, content: &str) -> BundleBlockEntry<'_> {
        BundleBlockEntry { block, content }
    }

    // ── compute_skill_content_hash ────────────────────────────────

    #[test]
    fn skill_content_hash_known_answer_test() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let got = skill_content_hash_hex("", "");
        assert_eq!(
            got, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA-256(empty) KAT"
        );
    }

    #[test]
    fn skill_content_hash_concatenation_order_matters() {
        let a = skill_content_hash_hex("foo", "bar");
        let b = skill_content_hash_hex("bar", "foo");
        assert_ne!(a, b, "yaml||template ≠ template||yaml");
    }

    #[test]
    fn skill_content_hash_deterministic() {
        let yaml = "name: lowkey\nversion: 1.0";
        let template = "respond in a direct + low-key tone";
        let a = skill_content_hash_hex(yaml, template);
        let b = skill_content_hash_hex(yaml, template);
        assert_eq!(a, b);
    }

    #[test]
    fn skill_content_hash_hex_is_64_lowercase() {
        let got = skill_content_hash_hex("x", "y");
        assert_eq!(got.len(), 64);
        assert!(got.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(got.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn skill_content_hash_template_change_changes_hash() {
        let a = skill_content_hash_hex("yaml", "template-v1");
        let b = skill_content_hash_hex("yaml", "template-v2");
        assert_ne!(a, b, "any template edit must change the hash");
    }

    // ── compute_prompt_bundle_hash ────────────────────────────────

    #[test]
    fn bundle_hash_order_independent_for_same_block_set() {
        let blocks_in_order = vec![
            entry(BundleBlock::A, "system"),
            entry(BundleBlock::B, "skill"),
            entry(BundleBlock::E, "user"),
        ];
        let blocks_shuffled = vec![
            entry(BundleBlock::E, "user"),
            entry(BundleBlock::A, "system"),
            entry(BundleBlock::B, "skill"),
        ];
        let h1 = prompt_bundle_hash_hex(&blocks_in_order);
        let h2 = prompt_bundle_hash_hex(&blocks_shuffled);
        assert_eq!(h1, h2, "encoder canonical-sorts blocks");
    }

    #[test]
    fn bundle_hash_distinct_for_distinct_content() {
        let a = vec![entry(BundleBlock::A, "alpha")];
        let b = vec![entry(BundleBlock::A, "beta")];
        assert_ne!(prompt_bundle_hash_hex(&a), prompt_bundle_hash_hex(&b));
    }

    #[test]
    fn bundle_hash_distinct_for_different_block_assignment() {
        // Same content but assigned to different blocks must produce
        // distinct hashes (the block-tag is part of the encoding).
        let a = vec![entry(BundleBlock::A, "text")];
        let b = vec![entry(BundleBlock::B, "text")];
        assert_ne!(prompt_bundle_hash_hex(&a), prompt_bundle_hash_hex(&b));
    }

    #[test]
    fn bundle_hash_absent_block_differs_from_empty_string() {
        // Block::A absent vs Block::A with empty content — DIFFERENT
        // hashes per the module-doc contract.
        let absent = vec![entry(BundleBlock::B, "x")];
        let empty_a = vec![entry(BundleBlock::A, ""), entry(BundleBlock::B, "x")];
        assert_ne!(
            prompt_bundle_hash_hex(&absent),
            prompt_bundle_hash_hex(&empty_a),
            "absent block ≠ empty block (per module-doc contract)"
        );
    }

    #[test]
    fn bundle_hash_empty_input_known_answer_test() {
        // Hashing nothing = SHA-256(empty) KAT.
        let got = prompt_bundle_hash_hex(&[]);
        assert_eq!(
            got,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }

    #[test]
    fn bundle_hash_duplicate_blocks_order_preserved_within_tag() {
        // Two D entries — relative order between them MUST stay the
        // input order after the canonical block-tag sort. We can't
        // assert exact bytes here (without computing the canonical
        // encoding) but we can assert that swapping the two D
        // entries produces a different hash → input order matters
        // within a block.
        let a = vec![
            entry(BundleBlock::D, "first"),
            entry(BundleBlock::D, "second"),
        ];
        let b = vec![
            entry(BundleBlock::D, "second"),
            entry(BundleBlock::D, "first"),
        ];
        assert_ne!(
            prompt_bundle_hash_hex(&a),
            prompt_bundle_hash_hex(&b),
            "within-block order matters (operator-chosen recall ordering)"
        );
    }

    #[test]
    fn bundle_hash_hex_is_64_lowercase() {
        let got = prompt_bundle_hash_hex(&[entry(BundleBlock::A, "x")]);
        assert_eq!(got.len(), 64);
        assert!(
            got.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    // ── BundleBlock ───────────────────────────────────────────────

    #[test]
    fn bundle_block_tag_canonical() {
        assert_eq!(BundleBlock::A.tag(), "A");
        assert_eq!(BundleBlock::B.tag(), "B");
        assert_eq!(BundleBlock::C.tag(), "C");
        assert_eq!(BundleBlock::D.tag(), "D");
        assert_eq!(BundleBlock::E.tag(), "E");
        assert_eq!(BundleBlock::Conductor.tag(), "Conductor");
    }

    #[test]
    fn bundle_block_sort_key_monotonic() {
        assert!(BundleBlock::A.sort_key() < BundleBlock::B.sort_key());
        assert!(BundleBlock::B.sort_key() < BundleBlock::C.sort_key());
        assert!(BundleBlock::C.sort_key() < BundleBlock::D.sort_key());
        assert!(BundleBlock::D.sort_key() < BundleBlock::E.sort_key());
        assert!(BundleBlock::E.sort_key() < BundleBlock::Conductor.sort_key());
    }

    // ── SkillSkipReason ───────────────────────────────────────────

    #[test]
    fn skill_skip_reason_as_str_snake_case() {
        assert_eq!(SkillSkipReason::EvalSession.as_str(), "eval_session");
        assert_eq!(
            SkillSkipReason::OperatorDisabled.as_str(),
            "operator_disabled"
        );
        assert_eq!(SkillSkipReason::HashMismatch.as_str(), "hash_mismatch");
        assert_eq!(SkillSkipReason::FeatureOff.as_str(), "feature_off");
    }
}
