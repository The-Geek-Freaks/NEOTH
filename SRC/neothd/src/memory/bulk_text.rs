//! Bulk-text → atomic-claims extractor — Phase 28c R-24 GT-6.
//!
//! Operator pastes a markdown blob or points at a file; this module pulls
//! out one factual claim per line. Two implementations:
//!
//!   1. **Heuristic-only** ([`extract_claims_heuristic`]) — layered split:
//!      paragraph (`\n\n`) → list-item regex → sentence boundary
//!      (`unicode-segmentation`) → 800-char hard cap. Drops chunks shorter
//!      than 20 chars and noise prefixes (`Note:`, `TODO`, `TBD`,
//!      `See also`). Used as the cold-start path before any provider is
//!      configured.
//!
//!   2. **LLM-assisted** ([`build_llm_prompt`] + [`parse_llm_output`]) —
//!      the wizard sends each ~800-char chunk to the configured provider
//!      with the system prompt from `memory/neoth_gt_onboarding_pins.md`
//!      ("output each discrete factual claim on its own line"). The
//!      provider call itself lives in the caller (CLI / wizard) so this
//!      module stays sync + dependency-free of the provider stack.
//!
//! Dedup uses the canonical normalised statement as the equality proof. An
//! `xxh3_64` fingerprint is retained only as a lookup accelerator: a hash
//! collision can never make two different normalised claims equal. The
//! current pass uses an in-memory `HashSet<String>`; completed import attempts
//! are recorded transactionally in `ground_truth_fingerprints`, so a restart
//! or a later import cannot re-assert the same claim as fresh corroboration.
//!
//! Output is always `Vec<Claim>` so the caller can hand them to
//! `groundtruth::insert(Source::BulkText, ...)`.

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashSet;

use unicode_segmentation::UnicodeSegmentation;

/// One atomic claim ready for `idx_groundtruth` insert.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub statement: String,
    /// 64-bit lookup accelerator over the normalised form. Equality is always
    /// checked against the full normalised statement as well.
    pub fingerprint: u64,
}

/// Durable outcome of importing one claim.
///
/// Re-pasting an active claim is a no-op: it does not increment
/// `source_weight`, confidence, or `confirmed_count`. A revoked row (or a hard
/// deleted row whose fingerprint ledger remains) is an operator tombstone and
/// is likewise not resurrected by a bulk import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistClaimOutcome {
    Inserted { id: i64 },
    SkippedActive { id: i64 },
    SkippedTombstone { id: Option<i64> },
}

/// Hard cap per claim. Anything longer is truncated at the next word
/// boundary. Memo: `memory/neoth_gt_onboarding_pins.md`.
pub const MAX_CLAIM_CHARS: usize = 800;
/// Drop chunks shorter than this — they're almost always noise after the
/// split passes (single-word list bullets, "?", etc).
pub const MIN_CLAIM_CHARS: usize = 20;

/// Prefixes that mark a line as TODO/scaffold rather than a fact. Drops
/// the entire chunk when matched (case-sensitive — TODO and Todo are
/// both flagged elsewhere; this set is the exact spec).
const NOISE_PREFIXES: &[&str] = &["Note:", "TODO", "TBD", "See also"];

/// Heuristic-only extractor. Returns deduped claims in document order.
pub fn extract_claims_heuristic(text: &str) -> Vec<Claim> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for paragraph in text.split("\n\n") {
        for chunk in split_paragraph(paragraph) {
            let trimmed = chunk.trim();
            if !is_acceptable(trimmed) {
                continue;
            }
            if let Some(claim) = claim_from_statement(trimmed, &mut seen) {
                out.push(claim);
            }
        }
    }
    out
}

/// Parse operator-curated, one-claim-per-line input. This path deliberately
/// keeps the raw line semantics (no sentence splitting or noise-prefix
/// filtering), but shares the exact same cap, normaliser, collision guard, and
/// in-pass dedup implementation as heuristic and LLM extraction.
pub fn extract_claims_raw(text: &str) -> Vec<Claim> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.chars().count() < MIN_CLAIM_CHARS {
            continue;
        }
        if let Some(claim) = claim_from_statement(trimmed, &mut seen) {
            out.push(claim);
        }
    }
    out
}

/// Build the LLM extraction prompt + the user-message body. Returns
/// `(system, user)`. The caller invokes `provider.complete()` with these.
pub fn build_llm_prompt(chunk: &str) -> (String, String) {
    let system = "You are a fact extractor. Given a text, output each discrete, \
                  self-contained factual claim on its own line. One claim per line. \
                  No bullet points. No preamble. No explanation. If a sentence \
                  contains multiple claims, split them."
        .to_string();
    (system, chunk.to_string())
}

/// Parse the LLM response. Each non-empty line becomes one claim,
/// after stripping bullet markers / leading whitespace. Empty input
/// returns an empty vec (caller decides whether that's an error).
pub fn parse_llm_output(response: &str) -> Vec<Claim> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for raw in response.lines() {
        let stripped = strip_bullet(raw).trim();
        if !is_acceptable(stripped) {
            continue;
        }
        if let Some(claim) = claim_from_statement(stripped, &mut seen) {
            out.push(claim);
        }
    }
    out
}

/// Persist one bulk claim and its canonical identity as one SQLite operation.
///
/// The ledger row is reserved before `idx_groundtruth` is touched. SQLite's
/// unique `(scope, normalised_statement)` key serialises racing importers; the
/// loser observes the committed row and skips instead of corroborating it. A
/// SAVEPOINT keeps this composable with caller-owned transactions and ensures
/// an insert failure cannot leave a fingerprint without its fact (or vice
/// versa).
pub fn persist_claim(
    conn: &Connection,
    claim: &Claim,
    scope: &str,
    now_ns: i64,
) -> Result<PersistClaimOutcome> {
    let scope = scope.trim();
    if scope.is_empty() {
        anyhow::bail!("bulk-text scope must be non-empty");
    }
    let statement = claim.statement.trim();
    if statement.is_empty() {
        anyhow::bail!("bulk-text claim must be non-empty");
    }
    let normalised = normalise_for_dedup(statement);
    if normalised.is_empty() {
        anyhow::bail!("bulk-text claim normalises to an empty statement");
    }
    let fingerprint = fingerprint_for_normalised(&normalised);
    persist_normalised(conn, statement, scope, &normalised, fingerprint, now_ns)
}

fn persist_normalised(
    conn: &Connection,
    statement: &str,
    scope: &str,
    normalised: &str,
    fingerprint: u64,
    now_ns: i64,
) -> Result<PersistClaimOutcome> {
    conn.execute_batch("SAVEPOINT bulk_text_persist")
        .context("begin bulk-text persistence savepoint")?;

    let result = (|| {
        let fingerprint_bytes = fingerprint.to_be_bytes();
        let reserved = conn
            .execute(
                "INSERT INTO ground_truth_fingerprints \
                     (scope, fingerprint, normalised_statement, groundtruth_id, first_seen_at) \
                 VALUES (?1, ?2, ?3, NULL, ?4) \
                 ON CONFLICT(scope, normalised_statement) DO NOTHING",
                params![scope, &fingerprint_bytes[..], normalised, now_ns],
            )
            .context("reserve persistent bulk-text fingerprint")?;

        if reserved == 0 {
            let existing: Option<(Option<i64>, Option<i64>, Option<i64>)> = conn
                .query_row(
                    "SELECT f.groundtruth_id, g.id, g.revoked_at \
                     FROM ground_truth_fingerprints f \
                     LEFT JOIN idx_groundtruth g ON g.id = f.groundtruth_id \
                     WHERE f.scope = ?1 AND f.normalised_statement = ?2",
                    params![scope, normalised],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .context("read persistent bulk-text fingerprint")?;
            let (ledger_id, joined_id, revoked_at) = existing.ok_or_else(|| {
                anyhow::anyhow!("bulk-text fingerprint conflict disappeared inside savepoint")
            })?;
            return Ok(match (ledger_id, joined_id, revoked_at) {
                (Some(id), Some(_), None) => PersistClaimOutcome::SkippedActive { id },
                (id, _, _) => PersistClaimOutcome::SkippedTombstone { id },
            });
        }

        let id = crate::memory::groundtruth::insert(
            conn,
            statement,
            &crate::memory::groundtruth::Source::BulkText,
            scope,
            now_ns,
        )?;
        let linked = conn
            .execute(
                "UPDATE ground_truth_fingerprints SET groundtruth_id = ?1 \
                 WHERE scope = ?2 AND normalised_statement = ?3 \
                   AND groundtruth_id IS NULL",
                params![id, scope, normalised],
            )
            .context("link bulk-text fingerprint to ground-truth row")?;
        if linked != 1 {
            anyhow::bail!("bulk-text fingerprint reservation lost before ground-truth link");
        }
        Ok(PersistClaimOutcome::Inserted { id })
    })();

    finish_savepoint(conn, result)
}

fn finish_savepoint(
    conn: &Connection,
    result: Result<PersistClaimOutcome>,
) -> Result<PersistClaimOutcome> {
    match result {
        Ok(outcome) => match conn.execute_batch("RELEASE SAVEPOINT bulk_text_persist") {
            Ok(()) => Ok(outcome),
            Err(release_error) => {
                let _ = conn.execute_batch(
                    "ROLLBACK TO SAVEPOINT bulk_text_persist; \
                     RELEASE SAVEPOINT bulk_text_persist",
                );
                Err(anyhow::Error::new(release_error)
                    .context("commit bulk-text persistence savepoint"))
            }
        },
        Err(error) => {
            let rollback = conn.execute_batch(
                "ROLLBACK TO SAVEPOINT bulk_text_persist; \
                 RELEASE SAVEPOINT bulk_text_persist",
            );
            if let Err(rollback_error) = rollback {
                return Err(error.context(format!(
                    "rollback bulk-text persistence savepoint failed: {rollback_error}"
                )));
            }
            Err(error)
        }
    }
}

// ── internals ───────────────────────────────────────────────────────────────

fn claim_from_statement(statement: &str, seen: &mut HashSet<String>) -> Option<Claim> {
    let capped = cap_at_word_boundary(statement, MAX_CLAIM_CHARS);
    let normalised = normalise_for_dedup(&capped);
    if normalised.is_empty() || !seen.insert(normalised.clone()) {
        return None;
    }
    Some(Claim {
        statement: capped,
        fingerprint: fingerprint_for_normalised(&normalised),
    })
}

fn is_acceptable(s: &str) -> bool {
    if s.chars().count() < MIN_CLAIM_CHARS {
        return false;
    }
    for prefix in NOISE_PREFIXES {
        if s.starts_with(prefix) {
            return false;
        }
    }
    true
}

fn strip_bullet(line: &str) -> &str {
    let trimmed = line.trim_start();
    for marker in ["- ", "* ", "• ", "+ "] {
        if let Some(rest) = trimmed.strip_prefix(marker) {
            return rest;
        }
    }
    // Numbered list: "1. ", "2. ", ...
    if let Some(idx) = trimmed.find(". ")
        && idx > 0
        && idx <= 3
        && trimmed[..idx].chars().all(|c| c.is_ascii_digit())
    {
        return &trimmed[idx + 2..];
    }
    trimmed
}

fn split_paragraph(paragraph: &str) -> Vec<String> {
    // Layered split: lines that look like list items (`- `, `* `, …) are
    // their own chunks; everything else feeds the sentence splitter.
    let mut chunks = Vec::new();
    let mut sentence_buffer = String::new();
    for line in paragraph.lines() {
        let trimmed = line.trim_start();
        let is_list_item = trimmed.starts_with("- ")
            || trimmed.starts_with("* ")
            || trimmed.starts_with("• ")
            || trimmed.starts_with("+ ")
            || trimmed
                .find(". ")
                .map(|i| i > 0 && i <= 3 && trimmed[..i].chars().all(|c| c.is_ascii_digit()))
                .unwrap_or(false);
        if is_list_item {
            // Flush any prose accumulated above.
            if !sentence_buffer.trim().is_empty() {
                chunks.extend(split_into_sentences(&sentence_buffer));
                sentence_buffer.clear();
            }
            chunks.push(strip_bullet(trimmed).to_string());
        } else {
            sentence_buffer.push_str(trimmed);
            sentence_buffer.push(' ');
        }
    }
    if !sentence_buffer.trim().is_empty() {
        chunks.extend(split_into_sentences(&sentence_buffer));
    }
    chunks
}

fn split_into_sentences(text: &str) -> Vec<String> {
    // `unicode-segmentation` gives us sentence boundaries that respect
    // multilingual punctuation and abbreviations better than naive `.`
    // splitting. Each sentence keeps its trailing punctuation.
    text.unicode_sentences()
        .map(|s| s.trim().to_string())
        .collect()
}

fn cap_at_word_boundary(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    // Find the last word boundary ≤ max chars. `char_indices()` walks
    // code points so multi-byte chars stay intact.
    let mut last_space = 0usize;
    for (idx, ch) in s.char_indices() {
        if idx > max {
            break;
        }
        if ch.is_whitespace() {
            last_space = idx;
        }
    }
    if last_space == 0 {
        // No whitespace inside the cap — hard truncate at the byte boundary
        // closest to `max` code points without splitting a code point.
        let mut end = 0usize;
        for (idx, _) in s.char_indices().take(max) {
            end = idx;
        }
        return s[..end].to_string();
    }
    s[..last_space].to_string()
}

pub(crate) fn normalise_for_dedup(s: &str) -> String {
    // Lower-case + collapse whitespace. Drop trailing punctuation so
    // "X is Y." and "X is Y" hash to the same fingerprint — repeated
    // pastes after a punctuation tweak shouldn't duplicate rows.
    let lower: String = s.to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut prev_was_space = false;
    for ch in lower.chars() {
        if ch.is_whitespace() {
            if !prev_was_space && !out.is_empty() {
                out.push(' ');
            }
            prev_was_space = true;
        } else {
            out.push(ch);
            prev_was_space = false;
        }
    }
    out.trim_end()
        .trim_end_matches([
            '.', '!', '?', ';', ':', ',', '。', '！', '？', '；', '：', '，',
        ])
        .trim_end()
        .to_string()
}

pub(crate) fn fingerprint_for_normalised(normalised: &str) -> u64 {
    xxhash_rust::xxh3::xxh3_64(normalised.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heuristic_splits_paragraphs_and_drops_short_chunks() {
        let text = "\
            NEOTH builds locally on Windows only.\n\
            Primary server is at 10.0.0.1 and must not be remote-rebooted.\n\
            \n\
            Telegram bot uses long-polling for v0.1.\n\
            ok\n";
        let claims = extract_claims_heuristic(text);
        assert!(claims.iter().any(|c| c.statement.contains("Windows")));
        assert!(claims.iter().any(|c| c.statement.contains("10.0.0.1")));
        assert!(claims.iter().any(|c| c.statement.contains("Telegram")));
        // "ok" is below MIN_CLAIM_CHARS → dropped.
        assert!(!claims.iter().any(|c| c.statement == "ok"));
    }

    #[test]
    fn heuristic_dedupes_repeated_claims() {
        let text = "\
            NEOTH never phones home.\n\
            \n\
            NEOTH never phones home.\n\
            \n\
            neoth NEVER phones home.\n";
        let claims = extract_claims_heuristic(text);
        // All three normalise to the same fingerprint.
        let phone_home: Vec<_> = claims
            .iter()
            .filter(|c| c.statement.to_lowercase().contains("phones home"))
            .collect();
        assert_eq!(phone_home.len(), 1, "got {claims:?}");
    }

    #[test]
    fn heuristic_dedup_ignores_trailing_punctuation() {
        let text = "The server is 10.0.0.1.\n\nThe server is 10.0.0.1";
        let claims = extract_claims_heuristic(text);
        assert_eq!(claims.len(), 1);
    }

    #[test]
    fn heuristic_skips_noise_prefixes() {
        let text = "\
            TODO: refactor the WAL writer next sprint\n\
            \n\
            Note: this is a placeholder until Phase 28c lands\n\
            \n\
            See also the spec at SPEC_wal.md for details\n\
            \n\
            NEOTH ships with a self-contained binary on every platform.\n";
        let claims = extract_claims_heuristic(text);
        assert_eq!(claims.len(), 1, "noise prefixes must drop");
        assert!(claims[0].statement.contains("self-contained"));
    }

    #[test]
    fn heuristic_splits_list_items() {
        let text = "Bullet list of facts:\n\
            - The primary server runs Unraid with three GPUs at 10.0.0.1\n\
            - The gateway VM is on 10.0.0.2 and serves as the proxy\n\
            * Star-bullet works too if the operator prefers it\n\
            1. Numbered list items also work after stripping the prefix\n";
        let claims = extract_claims_heuristic(text);
        assert!(claims.len() >= 3, "expected ≥3 claims, got {claims:?}");
        assert!(
            claims
                .iter()
                .any(|c| c.statement.starts_with("The primary server"))
        );
        assert!(claims.iter().any(|c| c.statement.starts_with("Numbered")));
    }

    #[test]
    fn cap_at_word_boundary_respects_max_and_unicode() {
        // Multi-byte chars: each greek letter is 2 bytes in UTF-8. Cap by
        // *characters*, never split a code point.
        let s = "α β γ δ ε ζ η θ ι κ λ μ ν ξ ο π ρ σ τ υ φ χ ψ ω";
        let capped = cap_at_word_boundary(s, 10);
        assert!(
            capped.chars().count() <= 10,
            "got {} chars",
            capped.chars().count()
        );
        // No panic, no broken UTF-8.
        assert!(capped.is_char_boundary(capped.len()));
    }

    #[test]
    fn cap_does_not_truncate_short_input() {
        let s = "short";
        assert_eq!(cap_at_word_boundary(s, 100), "short");
    }

    #[test]
    fn cap_truncates_at_word_boundary() {
        let s = "alpha beta gamma delta epsilon zeta eta";
        // Cap at 18 chars. Last whitespace ≤ 18 is at index 16 (after
        // "gamma"). Function returns `s[..16]` = "alpha beta gamma" — a
        // complete-word truncation that drops the trailing space.
        let capped = cap_at_word_boundary(s, 18);
        assert_eq!(capped, "alpha beta gamma");
        assert!(capped.chars().count() <= 18);
        // Never split a word — the next byte after the cap must be whitespace
        // or end-of-string.
        let next = s.as_bytes().get(capped.len()).copied();
        assert!(
            next == Some(b' ') || next.is_none(),
            "split a word: next byte = {next:?}"
        );
    }

    #[test]
    fn llm_prompt_carries_required_keywords() {
        let (system, user) = build_llm_prompt("the cat is gray");
        assert!(system.contains("fact extractor"));
        assert!(system.contains("One claim per line"));
        assert!(system.contains("No preamble"));
        assert_eq!(user, "the cat is gray");
    }

    #[test]
    fn llm_output_parses_lines_and_strips_bullets() {
        let raw = "- The operator prefers German for chat\n\
                   * Code stays in English\n\
                   1. NEOTH uses MSVC on Windows\n\
                   • Bullet-with-unicode also strips\n\
                   \n\
                   The daemon writes WAL frames before any provider call.\n";
        let claims = parse_llm_output(raw);
        // First claim ("The operator prefers German for chat") is 37 chars — passes MIN.
        assert!(
            claims
                .iter()
                .any(|c| c.statement.contains("operator prefers"))
        );
        assert!(
            claims
                .iter()
                .any(|c| c.statement.contains("NEOTH uses MSVC"))
        );
        assert!(
            claims
                .iter()
                .any(|c| c.statement.contains("writes WAL frames"))
        );
        // All bullets stripped:
        assert!(claims.iter().all(|c| !c.statement.starts_with('-')));
        assert!(claims.iter().all(|c| !c.statement.starts_with('*')));
    }

    #[test]
    fn llm_output_dedupes_across_lines() {
        let raw = "The operator builds NEOTH on Windows.\n\
                   the operator builds neoth on windows\n\
                   THE OPERATOR BUILDS NEOTH ON WINDOWS.\n";
        let claims = parse_llm_output(raw);
        assert_eq!(claims.len(), 1);
    }

    #[test]
    fn empty_input_returns_no_claims() {
        assert!(extract_claims_heuristic("").is_empty());
        assert!(extract_claims_heuristic("    \n\n   \n").is_empty());
        assert!(parse_llm_output("").is_empty());
    }

    #[test]
    fn raw_and_heuristic_share_the_canonical_normaliser() {
        let raw = extract_claims_raw("  THE   operator builds NEOTH on Windows!!!  ");
        let heuristic = extract_claims_heuristic("The operator builds neoth on windows.\n");
        assert_eq!(raw.len(), 1);
        assert_eq!(heuristic.len(), 1);
        assert_eq!(raw[0].fingerprint, heuristic[0].fingerprint);
        assert_eq!(
            normalise_for_dedup(&raw[0].statement),
            normalise_for_dedup(&heuristic[0].statement)
        );
    }

    #[test]
    fn persistent_dedup_survives_reopen_without_corroboration_bump() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("views.db");
        let first = extract_claims_raw("The operator builds NEOTH on Windows.")
            .pop()
            .unwrap();
        let conn = crate::memory::store::open(&path).unwrap();
        let inserted = persist_claim(&conn, &first, "global", 10).unwrap();
        let id = match inserted {
            PersistClaimOutcome::Inserted { id } => id,
            other => panic!("first import unexpectedly skipped: {other:?}"),
        };
        drop(conn);

        let second = extract_claims_raw("  THE   OPERATOR builds neoth on windows!!!  ")
            .pop()
            .unwrap();
        let conn = crate::memory::store::open(&path).unwrap();
        assert_eq!(
            persist_claim(&conn, &second, "global", 20).unwrap(),
            PersistClaimOutcome::SkippedActive { id }
        );
        let (rows, source_weight, confirmed_count, confidence): (i64, String, i64, f64) = conn
            .query_row(
                "SELECT COUNT(*), source_weight, confirmed_count, confidence \
                 FROM idx_groundtruth WHERE scope = 'global'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(rows, 1);
        assert_eq!(source_weight, r#"{"bulk-text":1}"#);
        assert_eq!(confirmed_count, 0, "re-paste is not corroboration");
        assert!((confidence - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn persistent_dedup_is_scope_qualified() {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        let claim = extract_claims_raw("The gateway listens on the private network.")
            .pop()
            .unwrap();
        assert!(matches!(
            persist_claim(&conn, &claim, "host:a", 1).unwrap(),
            PersistClaimOutcome::Inserted { .. }
        ));
        assert!(matches!(
            persist_claim(&conn, &claim, "host:b", 2).unwrap(),
            PersistClaimOutcome::Inserted { .. }
        ));
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_groundtruth", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 2);
    }

    #[test]
    fn fingerprint_collision_never_proves_claim_equality() {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        let forced_collision = 0xA11CE_u64;
        let first = "The alpha gateway listens on port one thousand.";
        let second = "The beta gateway listens on port two thousand.";
        assert!(matches!(
            persist_normalised(
                &conn,
                first,
                "global",
                &normalise_for_dedup(first),
                forced_collision,
                1,
            )
            .unwrap(),
            PersistClaimOutcome::Inserted { .. }
        ));
        assert!(matches!(
            persist_normalised(
                &conn,
                second,
                "global",
                &normalise_for_dedup(second),
                forced_collision,
                2,
            )
            .unwrap(),
            PersistClaimOutcome::Inserted { .. }
        ));
        let rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ground_truth_fingerprints \
                 WHERE fingerprint = ?1",
                params![&forced_collision.to_be_bytes()[..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 2, "full canonical text guards hash collisions");
    }

    #[test]
    fn revoked_and_deleted_rows_remain_import_tombstones() {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        let claim = extract_claims_raw("The retired gateway used the legacy address.")
            .pop()
            .unwrap();
        let id = match persist_claim(&conn, &claim, "global", 1).unwrap() {
            PersistClaimOutcome::Inserted { id } => id,
            other => panic!("first import unexpectedly skipped: {other:?}"),
        };
        crate::memory::groundtruth::revoke(&conn, id, 2).unwrap();
        assert_eq!(
            persist_claim(&conn, &claim, "global", 3).unwrap(),
            PersistClaimOutcome::SkippedTombstone { id: Some(id) }
        );

        conn.execute("DELETE FROM idx_groundtruth WHERE id = ?1", params![id])
            .unwrap();
        assert_eq!(
            persist_claim(&conn, &claim, "global", 4).unwrap(),
            PersistClaimOutcome::SkippedTombstone { id: None },
            "hard delete keeps the import ledger as a non-resurrection tombstone"
        );
    }

    #[test]
    fn failed_groundtruth_insert_rolls_back_fingerprint_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::memory::store::open(&dir.path().join("views.db")).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER reject_bulk_claim BEFORE INSERT ON idx_groundtruth \
             BEGIN SELECT RAISE(ABORT, 'forced groundtruth failure'); END;",
        )
        .unwrap();
        let claim = extract_claims_raw("The rollback test statement is long enough.")
            .pop()
            .unwrap();
        assert!(persist_claim(&conn, &claim, "global", 1).is_err());
        let fingerprints: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ground_truth_fingerprints",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let facts: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_groundtruth", [], |row| row.get(0))
            .unwrap();
        assert_eq!((fingerprints, facts), (0, 0));
    }
}
