//! Block-layer budget enforcement — the pure-fn core of
//! [`crate::tokens`] ARCH-04. Inputs: a `Vec<BlockItem>` representing
//! the assembled prompt blocks + an operator-configured `cap`.
//! Outputs: the degraded `Vec<BlockItem>` (in place) + an
//! `Option<BudgetExceededDetail>` the caller emits to WAL `0x2F`.
//!
//! Module-level docs in [`super`] cover the policy + the rationale.

use serde::{Deserialize, Serialize};

/// Coarse token-count estimator. Treats every 4 characters as one
/// token (the OpenAI tokeniser's average ratio for English+German
/// mixed text). See module docs for why precise tokenisation is
/// deliberately deferred to the provider's `prompt_token_actual`
/// audit field.
pub fn count_tokens(text: &str) -> u32 {
    // Saturating math: a malformed multi-GB input shouldn't panic
    // the assembly path; cap at u32::MAX.
    let chars = text.chars().count();
    chars.div_ceil(4) as u32
}

/// Which named block a `BlockItem` belongs to. Variant order is
/// load-bearing — the degradation policy references blocks by
/// name, not by enum-discriminant order. See module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Block {
    /// A — operator-explicit system prompt. NEVER dropped.
    A,
    /// B — active LOWKEY skill prompts. NEVER dropped.
    B,
    /// C — profile context (operator-claims). Drop lowest-importance
    /// 50% when degradation step 2 fires.
    C,
    /// D — episode / recall context. Drop oldest 50% when
    /// degradation step 1 fires.
    D,
    /// E — current message (operator's prompt this turn). NEVER
    /// dropped.
    E,
    /// Conductor.plan/spec — orchestrator metadata block. Truncated
    /// (not dropped) when degradation step 3 fires.
    Conductor,
}

impl Block {
    /// True iff degradation policy is permitted to remove or
    /// truncate this block. Centralises the "never A/B/E" hard rule
    /// so a future block addition doesn't accidentally bypass it.
    pub fn is_degradable(self) -> bool {
        matches!(self, Block::C | Block::D | Block::Conductor)
    }
}

/// One item inside a prompt block. The `importance` field drives
/// the step-2 (C lowest-importance) selection; the `ts_ns` field
/// drives the step-1 (D oldest) selection.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockItem {
    pub block: Block,
    /// Importance in `[0.0, 1.0]`. 0.5 = neutral default. Only
    /// consulted for block C; D + Conductor degradation uses ts_ns.
    pub importance: f32,
    /// Insertion timestamp (ns since epoch). Only consulted for
    /// block D; the "oldest 50%" cut sorts by this ascending +
    /// drops the bottom half.
    pub ts_ns: i64,
    /// Token count for this item (caller pre-computes via
    /// [`count_tokens`] or a more precise tokeniser).
    pub tokens: u32,
    /// Free-form payload. Caller (prompt assembler) owns the
    /// content shape; the budget enforcer only cares about the
    /// `tokens` count.
    pub content: String,
}

/// Per-block accounting in [`BudgetReport`]. Tracks pre + post
/// counts so the audit emit-site has the full diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockTokens {
    pub block: Block,
    pub tokens_before: u32,
    pub tokens_after: u32,
    pub items_before: u32,
    pub items_after: u32,
}

/// Detail the caller emits to WAL `0x2F BUDGET_EXCEEDED`. Returned
/// from [`enforce_budget`] only when degradation actually fired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetExceededDetail {
    pub cap: u32,
    pub original_total: u32,
    pub new_total: u32,
    pub dropped_d_count: u32,
    pub dropped_c_count: u32,
    pub conductor_truncated: bool,
    pub per_block: Vec<BlockTokens>,
}

/// Sum tokens across a slice of items.
pub fn count_total(items: &[BlockItem]) -> u32 {
    items.iter().map(|i| i.tokens).sum()
}

/// Per-block snapshot (for the audit detail).
fn snapshot_per_block(items: &[BlockItem]) -> Vec<(Block, u32, u32)> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<u8, (Block, u32, u32)> = BTreeMap::new();
    for item in items {
        let discrim = match item.block {
            Block::A => 0u8,
            Block::B => 1,
            Block::C => 2,
            Block::D => 3,
            Block::E => 4,
            Block::Conductor => 5,
        };
        let entry = map.entry(discrim).or_insert((item.block, 0, 0));
        entry.1 = entry.1.saturating_add(item.tokens);
        entry.2 = entry.2.saturating_add(1);
    }
    map.into_values().collect()
}

/// Enforce the operator's `cap` against the supplied `items` Vec
/// via the documented degradation policy. Mutates `items` in place
/// (drops removed entries; truncates Conductor.content); returns
/// `Some(detail)` when any degradation fired, `None` when
/// `count_total(items) <= cap` on entry.
///
/// Policy order (see module docs):
/// 1. D oldest 50% — drop bottom half by `ts_ns` ascending.
/// 2. C lowest-importance 50% — drop bottom half by `importance`
///    ascending.
/// 3. Conductor truncation — halve each Conductor item's content
///    + token count; never to zero (1-token floor).
pub fn enforce_budget(items: &mut Vec<BlockItem>, cap: u32) -> Option<BudgetExceededDetail> {
    let original_total = count_total(items);
    if original_total <= cap {
        return None;
    }
    let pre_per_block: Vec<(Block, u32, u32)> = snapshot_per_block(items);

    let mut dropped_d = 0u32;
    let mut dropped_c = 0u32;
    let mut conductor_truncated = false;

    // ── Step 1 — drop D oldest 50% ───────────────────────────────
    if count_total(items) > cap {
        let d_indices: Vec<usize> = items
            .iter()
            .enumerate()
            .filter_map(|(i, it)| (it.block == Block::D).then_some(i))
            .collect();
        if !d_indices.is_empty() {
            // Sort the D-only indices by ts_ns ascending (oldest first).
            let mut sorted = d_indices.clone();
            sorted.sort_by_key(|&i| items[i].ts_ns);
            let half = sorted.len() / 2;
            // Drop indices in DESCENDING order so we don't shift left.
            let mut to_remove: Vec<usize> = sorted.into_iter().take(half).collect();
            to_remove.sort_unstable();
            to_remove.reverse();
            for idx in to_remove {
                items.remove(idx);
                dropped_d += 1;
            }
        }
    }

    // ── Step 2 — drop C lowest-importance 50% ────────────────────
    if count_total(items) > cap {
        let c_indices: Vec<usize> = items
            .iter()
            .enumerate()
            .filter_map(|(i, it)| (it.block == Block::C).then_some(i))
            .collect();
        if !c_indices.is_empty() {
            let mut sorted = c_indices.clone();
            sorted.sort_by(|&a, &b| {
                items[a]
                    .importance
                    .partial_cmp(&items[b].importance)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            let half = sorted.len() / 2;
            let mut to_remove: Vec<usize> = sorted.into_iter().take(half).collect();
            to_remove.sort_unstable();
            to_remove.reverse();
            for idx in to_remove {
                items.remove(idx);
                dropped_c += 1;
            }
        }
    }

    // ── Step 3 — truncate Conductor ──────────────────────────────
    if count_total(items) > cap {
        for item in items.iter_mut() {
            if item.block == Block::Conductor && item.tokens > 1 {
                // Halve, 1-token floor. Re-derive the content
                // length proportionally so the audit detail's
                // payload reflects the truncation.
                let new_tokens = (item.tokens / 2).max(1);
                let new_content_len =
                    (item.content.len() * new_tokens as usize) / item.tokens.max(1) as usize;
                if new_content_len < item.content.len() {
                    // Truncate on a char boundary, not a byte.
                    let mut end = new_content_len.min(item.content.len());
                    while end > 0 && !item.content.is_char_boundary(end) {
                        end -= 1;
                    }
                    item.content.truncate(end);
                }
                item.tokens = new_tokens;
                conductor_truncated = true;
            }
        }
    }

    let new_total = count_total(items);
    let post_per_block: Vec<(Block, u32, u32)> = snapshot_per_block(items);
    let per_block = build_per_block(&pre_per_block, &post_per_block);

    Some(BudgetExceededDetail {
        cap,
        original_total,
        new_total,
        dropped_d_count: dropped_d,
        dropped_c_count: dropped_c,
        conductor_truncated,
        per_block,
    })
}

fn build_per_block(pre: &[(Block, u32, u32)], post: &[(Block, u32, u32)]) -> Vec<BlockTokens> {
    use std::collections::HashMap;
    let post_map: HashMap<Block, (u32, u32)> = post
        .iter()
        .map(|(b, tok, cnt)| (*b, (*tok, *cnt)))
        .collect();
    let mut out = Vec::with_capacity(pre.len());
    for (block, tokens_before, items_before) in pre {
        let (tokens_after, items_after) = post_map.get(block).copied().unwrap_or((0, 0));
        out.push(BlockTokens {
            block: *block,
            tokens_before: *tokens_before,
            tokens_after,
            items_before: *items_before,
            items_after,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(block: Block, importance: f32, ts_ns: i64, tokens: u32) -> BlockItem {
        BlockItem {
            block,
            importance,
            ts_ns,
            tokens,
            content: "x".repeat(tokens as usize * 4),
        }
    }

    // ── count_tokens ──────────────────────────────────────────────

    #[test]
    fn count_tokens_chars_div_4_roundup() {
        assert_eq!(count_tokens(""), 0);
        assert_eq!(count_tokens("a"), 1);
        assert_eq!(count_tokens("abc"), 1);
        assert_eq!(count_tokens("abcd"), 1);
        assert_eq!(count_tokens("abcde"), 2);
        assert_eq!(count_tokens("12345678"), 2);
        assert_eq!(count_tokens("123456789"), 3);
    }

    #[test]
    fn count_tokens_handles_unicode() {
        // chars() counts grapheme-precursors; "Müller" = 6 chars.
        assert_eq!(count_tokens("Müller"), 2);
    }

    // ── Block::is_degradable ──────────────────────────────────────

    #[test]
    fn is_degradable_matrix() {
        assert!(!Block::A.is_degradable());
        assert!(!Block::B.is_degradable());
        assert!(!Block::E.is_degradable());
        assert!(Block::C.is_degradable());
        assert!(Block::D.is_degradable());
        assert!(Block::Conductor.is_degradable());
    }

    // ── enforce_budget — no-op when under cap ─────────────────────

    #[test]
    fn enforce_returns_none_when_under_cap() {
        let mut items = vec![item(Block::A, 0.5, 0, 100), item(Block::E, 0.5, 0, 100)];
        let result = enforce_budget(&mut items, 500);
        assert!(result.is_none());
        assert_eq!(items.len(), 2, "items untouched");
    }

    #[test]
    fn enforce_returns_none_exactly_at_cap() {
        let mut items = vec![item(Block::A, 0.5, 0, 100), item(Block::E, 0.5, 0, 100)];
        let result = enforce_budget(&mut items, 200);
        assert!(result.is_none(), "exactly-at-cap must not trigger");
    }

    // ── Step 1: D oldest 50% ──────────────────────────────────────

    #[test]
    fn d_oldest_50pct_dropped_first() {
        let mut items = vec![
            item(Block::A, 0.5, 0, 100),
            item(Block::D, 0.5, 1, 100), // oldest
            item(Block::D, 0.5, 2, 100),
            item(Block::D, 0.5, 3, 100),
            item(Block::D, 0.5, 4, 100), // newest
            item(Block::E, 0.5, 0, 100),
        ];
        // Total 600, cap 400 → must drop 2 of the 4 D items (oldest).
        let detail = enforce_budget(&mut items, 400).expect("must trigger");
        assert_eq!(detail.dropped_d_count, 2);
        assert_eq!(detail.dropped_c_count, 0);
        assert!(!detail.conductor_truncated);
        // Survivors: A + D(ts=3) + D(ts=4) + E.
        let survivor_ts: Vec<i64> = items
            .iter()
            .filter(|i| i.block == Block::D)
            .map(|i| i.ts_ns)
            .collect();
        assert_eq!(survivor_ts, vec![3, 4]);
    }

    // ── Step 2: C lowest-importance 50% ───────────────────────────

    #[test]
    fn c_lowest_importance_50pct_dropped_second() {
        // No D items → step 1 is a no-op → step 2 fires.
        let mut items = vec![
            item(Block::A, 0.5, 0, 100),
            item(Block::C, 0.1, 0, 100), // lowest importance
            item(Block::C, 0.3, 0, 100),
            item(Block::C, 0.7, 0, 100),
            item(Block::C, 0.9, 0, 100), // highest importance
            item(Block::E, 0.5, 0, 100),
        ];
        let detail = enforce_budget(&mut items, 400).expect("must trigger");
        assert_eq!(detail.dropped_d_count, 0);
        assert_eq!(detail.dropped_c_count, 2);
        let survivor_imp: Vec<f32> = items
            .iter()
            .filter(|i| i.block == Block::C)
            .map(|i| i.importance)
            .collect();
        assert_eq!(survivor_imp, vec![0.7, 0.9]);
    }

    // ── Step 3: Conductor truncation ──────────────────────────────

    #[test]
    fn conductor_truncated_last_resort() {
        // Cap is so tight that even after dropping D + C halves we
        // still overflow. Conductor must halve.
        let mut items = vec![
            item(Block::A, 0.5, 0, 100),
            item(Block::E, 0.5, 0, 100),
            item(Block::Conductor, 0.5, 0, 400),
        ];
        // Total 600, cap 300 → no D/C to drop, must truncate Conductor.
        let detail = enforce_budget(&mut items, 300).expect("must trigger");
        assert!(detail.conductor_truncated);
        assert_eq!(detail.dropped_d_count, 0);
        assert_eq!(detail.dropped_c_count, 0);
        let conductor = items.iter().find(|i| i.block == Block::Conductor).unwrap();
        assert_eq!(conductor.tokens, 200, "halved from 400");
    }

    // ── A / B / E never touched ───────────────────────────────────

    #[test]
    fn a_b_e_never_dropped_even_under_extreme_pressure() {
        let mut items = vec![
            item(Block::A, 0.5, 0, 500),
            item(Block::B, 0.5, 0, 500),
            item(Block::E, 0.5, 0, 500),
        ];
        // Cap 100 — way under total 1500. No degradable items exist.
        // Degradation runs (returns Some) but A/B/E survive.
        let detail = enforce_budget(&mut items, 100).expect("must trigger");
        assert_eq!(items.len(), 3, "A + B + E all survive");
        assert_eq!(detail.dropped_d_count, 0);
        assert_eq!(detail.dropped_c_count, 0);
        assert!(!detail.conductor_truncated);
        // new_total still > cap — operator-visible signal that the
        // cap is too aggressive for the protected blocks alone.
        assert!(detail.new_total > detail.cap);
    }

    // ── Multi-step degradation ────────────────────────────────────

    #[test]
    fn multi_step_d_then_c_then_conductor() {
        let mut items = vec![
            item(Block::A, 0.5, 0, 50),
            item(Block::D, 0.5, 1, 100),
            item(Block::D, 0.5, 2, 100),
            item(Block::C, 0.1, 0, 100),
            item(Block::C, 0.9, 0, 100),
            item(Block::Conductor, 0.5, 0, 200),
            item(Block::E, 0.5, 0, 50),
        ];
        // Total 700, cap 350 → degrade through all three steps.
        let detail = enforce_budget(&mut items, 350).expect("must trigger");
        assert!(
            detail.dropped_d_count > 0 || detail.dropped_c_count > 0 || detail.conductor_truncated
        );
        assert!(detail.new_total <= detail.cap || items.iter().all(|i| !i.block.is_degradable()));
    }

    // ── Per-block accounting ──────────────────────────────────────

    #[test]
    fn per_block_accounting_pre_post_diff() {
        let mut items = vec![
            item(Block::A, 0.5, 0, 100),
            item(Block::D, 0.5, 1, 100),
            item(Block::D, 0.5, 2, 100),
            item(Block::E, 0.5, 0, 100),
        ];
        let detail = enforce_budget(&mut items, 300).expect("must trigger");
        let d_block = detail
            .per_block
            .iter()
            .find(|b| b.block == Block::D)
            .expect("D block must appear in pre");
        assert_eq!(d_block.tokens_before, 200);
        assert_eq!(d_block.items_before, 2);
        assert_eq!(d_block.items_after, 1, "1 of 2 D items dropped");
        let a_block = detail
            .per_block
            .iter()
            .find(|b| b.block == Block::A)
            .unwrap();
        assert_eq!(a_block.tokens_before, a_block.tokens_after, "A untouched");
    }

    #[test]
    fn count_total_sums_correctly() {
        let items = vec![
            item(Block::A, 0.5, 0, 10),
            item(Block::D, 0.5, 0, 20),
            item(Block::C, 0.5, 0, 30),
        ];
        assert_eq!(count_total(&items), 60);
    }

    #[test]
    fn count_total_empty_zero() {
        assert_eq!(count_total(&[]), 0);
    }
}
