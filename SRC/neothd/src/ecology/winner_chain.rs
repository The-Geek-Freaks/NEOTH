//! F4-01 — council winner-chain: a measured win-distribution over the
//! `0x63 COUNCIL_WINNER_SELECTED` WAL frames.
//!
//! The genealogy module ([`super::genealogy`]) deliberately refuses tool→win
//! edges: `0x63` carries no tool/skill id, so any tool→win linkage would be
//! invented. But the winner frame DOES carry `provider`, `role`, `score`, and
//! `mode` — so the chain of WHO WINS councils (which provider/hemisphere, at what
//! score, under which selection mode) is fully MEASURABLE today. This module
//! aggregates exactly those in-frame fields — nothing inferred, nothing joined
//! across a missing key — keeping the CH-13 pin "every signal is a pure function
//! over REAL WAL data".
//!
//! It complements [`super::correlation_detector`] (which flags consecutive-win
//! STREAKS, an adjacency signal) with the cumulative distribution: total wins
//! per provider+role, the average + most-recent selection score, the win share,
//! and the mode mix. Surfaced read-only via `neoth ecology winner-chain`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::correlation_detector::WinnerRecord;

/// Cumulative win stats for one `(provider, role)` voice across the scanned WAL.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WinnerStat {
    /// The winning provider id (e.g. `claude_cli`, `local_qwen`).
    pub provider: String,
    /// The winning hemisphere role (`left` / `right` / `cerebellum`).
    pub role: String,
    /// How many outer-council debates this `(provider, role)` won.
    pub wins: u32,
    /// `wins / total_debates` — this voice's share of all council wins.
    pub win_share: f64,
    /// Mean selection score across this voice's wins.
    pub avg_score: f64,
    /// The selection score of this voice's most-recent win (chronological last).
    pub last_score: f64,
}

/// The measured winner-chain: per-voice win stats + the selection-mode mix +
/// the total number of outer-council debates scanned.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WinnerChain {
    /// Per-`(provider, role)` win stats, most-wins first (ties by provider, role).
    pub stats: Vec<WinnerStat>,
    /// Win counts per selection mode (`consensus_or_best` / `best_always` /
    /// `legacy_majority` / `unknown`), most-wins first (ties by mode name).
    pub by_mode: Vec<(String, u32)>,
    /// Total outer-council debates aggregated (= sum of every voice's wins).
    pub total_debates: u32,
}

/// In-progress per-voice accumulator: `(wins, score_sum, last_score)`.
type VoiceAcc = (u32, f64, f64);

/// Build the winner-chain from outer-council winner records (chronological /
/// WAL order — `scan_winner_records` already guarantees this). PURE over its
/// input: no IO, no inference. An empty slice yields an empty chain.
pub fn build_winner_chain(records: &[WinnerRecord]) -> WinnerChain {
    let total = records.len() as u32;
    if total == 0 {
        return WinnerChain::default();
    }

    let mut voices: HashMap<(String, String), VoiceAcc> = HashMap::new();
    let mut modes: HashMap<String, u32> = HashMap::new();

    // Records are in chronological order, so the LAST write to `last_score` for
    // a voice is its most-recent win.
    for r in records {
        let slot = voices
            .entry((r.provider.clone(), r.role.clone()))
            .or_insert((0, 0.0, 0.0));
        slot.0 = slot.0.saturating_add(1);
        slot.1 += r.score;
        slot.2 = r.score;
        *modes.entry(r.mode.clone()).or_insert(0) += 1;
    }

    let total_f = total as f64;
    let mut stats: Vec<WinnerStat> = voices
        .into_iter()
        .map(
            |((provider, role), (wins, score_sum, last_score))| WinnerStat {
                provider,
                role,
                wins,
                win_share: wins as f64 / total_f,
                avg_score: if wins == 0 {
                    0.0
                } else {
                    score_sum / wins as f64
                },
                last_score,
            },
        )
        .collect();
    // Deterministic: most wins first, ties broken by provider then role.
    stats.sort_by(|a, b| {
        b.wins
            .cmp(&a.wins)
            .then_with(|| a.provider.cmp(&b.provider))
            .then_with(|| a.role.cmp(&b.role))
    });

    let mut by_mode: Vec<(String, u32)> = modes.into_iter().collect();
    by_mode.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    WinnerChain {
        stats,
        by_mode,
        total_debates: total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(provider: &str, role: &str, score: f64, mode: &str) -> WinnerRecord {
        WinnerRecord {
            provider: provider.into(),
            role: role.into(),
            score,
            mode: mode.into(),
        }
    }

    #[test]
    fn empty_records_yield_empty_chain() {
        let c = build_winner_chain(&[]);
        assert_eq!(c, WinnerChain::default());
        assert_eq!(c.total_debates, 0);
        assert!(c.stats.is_empty());
        assert!(c.by_mode.is_empty());
    }

    #[test]
    fn aggregates_wins_share_and_scores() {
        // claude_cli/left wins 3 (scores .8 .9 1.0), local_qwen/right wins 1 (.5).
        let recs = vec![
            rec("claude_cli", "left", 0.8, "consensus_or_best"),
            rec("claude_cli", "left", 0.9, "consensus_or_best"),
            rec("local_qwen", "right", 0.5, "best_always"),
            rec("claude_cli", "left", 1.0, "consensus_or_best"),
        ];
        let c = build_winner_chain(&recs);
        assert_eq!(c.total_debates, 4);
        assert_eq!(c.stats.len(), 2);

        let top = &c.stats[0];
        assert_eq!(top.provider, "claude_cli");
        assert_eq!(top.role, "left");
        assert_eq!(top.wins, 3);
        assert!((top.win_share - 0.75).abs() < 1e-9);
        assert!((top.avg_score - 0.9).abs() < 1e-9, "(.8+.9+1.0)/3 = .9");
        assert!(
            (top.last_score - 1.0).abs() < 1e-9,
            "last_score = chronologically-last win's score"
        );

        let second = &c.stats[1];
        assert_eq!(second.provider, "local_qwen");
        assert_eq!(second.wins, 1);
        assert!((second.win_share - 0.25).abs() < 1e-9);
    }

    #[test]
    fn same_provider_different_role_are_distinct_voices() {
        let recs = vec![
            rec("p", "left", 0.9, "best_always"),
            rec("p", "right", 0.9, "best_always"),
        ];
        let c = build_winner_chain(&recs);
        assert_eq!(
            c.stats.len(),
            2,
            "(p,left) and (p,right) are separate voices"
        );
    }

    #[test]
    fn mode_mix_counted_and_sorted_desc() {
        let recs = vec![
            rec("a", "left", 0.9, "consensus_or_best"),
            rec("a", "left", 0.9, "consensus_or_best"),
            rec("b", "left", 0.9, "best_always"),
        ];
        let c = build_winner_chain(&recs);
        assert_eq!(c.by_mode[0], ("consensus_or_best".to_string(), 2));
        assert_eq!(c.by_mode[1], ("best_always".to_string(), 1));
    }

    #[test]
    fn tie_break_is_deterministic() {
        // Two voices with equal wins → provider-asc, then role-asc.
        let recs = vec![rec("z", "left", 0.9, "m"), rec("a", "left", 0.9, "m")];
        let c = build_winner_chain(&recs);
        assert_eq!(c.stats[0].provider, "a", "equal wins → provider ascending");
        assert_eq!(c.stats[1].provider, "z");
    }
}
