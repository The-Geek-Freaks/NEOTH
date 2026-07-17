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
    u32::try_from(chars.div_ceil(4)).unwrap_or(u32::MAX)
}

/// Conservative tokenizer-independent upper bound for enforcement. A token
/// emitted from user-controlled UTF-8 text must consume at least one input
/// byte; provider/message control overhead is reserved separately at the final
/// leaf. This intentionally over-counts ordinary prose so `max_per_request`
/// remains a hard boundary even for CJK, emoji and adversarial byte sequences.
pub fn count_tokens_upper_bound(text: &str) -> u32 {
    u32::try_from(text.len()).unwrap_or(u32::MAX)
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
    /// Conservative token upper bound for this item (caller pre-computes via
    /// [`count_tokens_upper_bound`] or a reviewed provider tokenizer).
    pub tokens: u32,
    /// Free-form payload. Caller (prompt assembler) owns the
    /// content shape; the budget enforcer only cares about the
    /// `tokens` count.
    pub content: String,
}

impl BlockItem {
    /// Construct one typed block and bind its estimate to the exact content.
    /// Callers should use [`Self::replace_content`] for later prompt rewrites so
    /// the estimate cannot drift from the bytes that reach the provider.
    pub fn new(block: Block, content: impl Into<String>) -> Self {
        let content = content.into();
        Self {
            block,
            importance: 0.5,
            ts_ns: 0,
            tokens: count_tokens_upper_bound(&content),
            content,
        }
    }

    /// Replace content and recompute the coarse token estimate atomically.
    pub fn replace_content(&mut self, content: impl Into<String>) {
        self.content = content.into();
        self.tokens = count_tokens_upper_bound(&self.content);
    }
}

/// Render the provider-facing `(prompt, system)` pair from typed blocks.
/// Exactly one E block is required; accepting zero or multiple user-message
/// blocks would make the budgeted representation disagree with the request.
pub fn render_request(items: &[BlockItem]) -> Result<(String, Option<String>), &'static str> {
    let mut prompt = None;
    let mut system_parts = Vec::with_capacity(items.len().saturating_sub(1));
    for item in items {
        if item.block == Block::E {
            if prompt.replace(item.content.clone()).is_some() {
                return Err("token-budget bundle contains multiple Block E items");
            }
        } else {
            system_parts.push(item.content.as_str());
        }
    }
    let prompt = prompt.ok_or("token-budget bundle is missing Block E")?;
    let system = (!system_parts.is_empty()).then(|| system_parts.join("\n\n"));
    Ok((prompt, system))
}

/// Replace the sole E item after hooks/output presets mutate the user prompt.
/// Fails closed on a malformed typed bundle rather than creating an implicit
/// second request body outside the accounting surface.
pub fn replace_user_message(
    items: &mut [BlockItem],
    content: impl Into<String>,
) -> Result<(), &'static str> {
    let mut matches = items.iter_mut().filter(|item| item.block == Block::E);
    let item = matches
        .next()
        .ok_or("token-budget bundle is missing Block E")?;
    if matches.next().is_some() {
        return Err("token-budget bundle contains multiple Block E items");
    }
    item.replace_content(content);
    Ok(())
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
    items
        .iter()
        .fold(0u32, |total, item| total.saturating_add(item.tokens))
}

/// Hard cap applied after the 85 % scaling so a 1M-token model
/// does not set an 850k budget (no benefit; the real win is lifting
/// from 100k → 170k for Claude/GPT-4o).
pub const CAP_200K: u32 = 200_000;

/// Fraction of the discovered context window used as the effective cap.
const WINDOW_SCALE_FRAC: f64 = 0.85;

/// (model-name-stem, context-window-tokens) lookup table.
/// Stem matching is case-insensitive substring — longest-matching key wins.
/// Only cloud models with windows above the 100k static default are listed;
/// local models are covered by `coding::model_profile::KNOWN_PROFILES` and
/// operators set `tokens.max_per_request` in freedom.yaml to match.
static KNOWN_CONTEXT_WINDOWS: &[(&str, u32)] = &[
    ("claude-opus-4-7", 200_000),
    ("claude-sonnet-4-6", 200_000),
    ("claude-haiku-4-5", 200_000),
    ("claude-opus-4", 200_000), // alias family
    ("claude-sonnet-4", 200_000),
    ("gpt-4.1", 1_047_576),
    ("gpt-4o", 128_000),
    ("gemini-2.5-pro", 1_000_000),
    ("gemini-2.5-flash", 1_000_000),
    ("gemini-2.0", 1_000_000),
];

/// Resolve the effective token cap for a single provider request.
///
/// Logic (in priority order):
/// 1. Look `model_name` up in `KNOWN_CONTEXT_WINDOWS` (longest-matching
///    stem, case-insensitive). If found, scale by `WINDOW_SCALE_FRAC`
///    (0.85) and clamp to `CAP_200K` (200_000).
/// 2. Apply `min(scaled, operator_cap)` so the operator's explicit
///    ceiling is always respected.
/// 3. No match → return `operator_cap` unchanged (current behaviour).
///
/// `_provider_name` is reserved for future per-provider overrides
/// (e.g. Bedrock API vs. claude_cli may report different windows for
/// the same model string). Unused today; kept in signature to avoid a
/// later breaking change.
pub fn effective_cap(_provider_name: &str, model_name: &str, operator_cap: u32) -> u32 {
    let lower = model_name.to_ascii_lowercase();
    // Longest-key-wins: find the entry whose stem is the longest
    // substring of the lowercased model name.
    let best = KNOWN_CONTEXT_WINDOWS
        .iter()
        .filter(|(stem, _)| lower.contains(*stem))
        .max_by_key(|(stem, _)| stem.len());
    match best {
        None => operator_cap,
        Some((_, window)) => {
            let scaled = (*window as f64 * WINDOW_SCALE_FRAC) as u32;
            let capped = scaled.min(CAP_200K);
            capped.min(operator_cap)
        }
    }
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
            // `div_ceil` is load-bearing for the live assembler, where recall
            // is commonly one aggregated D item.  Floor division would drop
            // zero of one and make the documented first degradation step a
            // permanent no-op on the common path.
            let half = sorted.len().div_ceil(2);
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
            // A live profile/preset commonly arrives as one aggregated C
            // item. Floor division would drop zero of one and silently skip
            // the documented second degradation step.
            let half = sorted.len().div_ceil(2);
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
                // Halve by Unicode scalar count, then recompute the estimate
                // from the exact retained content.  Byte-proportional cuts can
                // leave a stale token count for multi-byte text.
                let keep_chars = item.content.chars().count().div_ceil(2).max(1);
                item.content = item.content.chars().take(keep_chars).collect();
                item.tokens = count_tokens_upper_bound(&item.content);
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

/// Reapply the ordered degradation pass until the content budget is met or no
/// degradable bytes remain. This is the provider-boundary variant: a large
/// aggregated C/D item or Conductor block must not cause a refusal merely
/// because one 50% pass still leaves safe-to-remove context above the cap.
pub fn enforce_budget_to_fit(items: &mut Vec<BlockItem>, cap: u32) -> Option<BudgetExceededDetail> {
    let original_total = count_total(items);
    if original_total <= cap {
        return None;
    }
    let pre_per_block = snapshot_per_block(items);
    let mut dropped_d_count = 0_u32;
    let mut dropped_c_count = 0_u32;
    let mut conductor_truncated = false;

    while count_total(items) > cap {
        let before = count_total(items);
        let detail = enforce_budget(items, cap).expect("over-cap pass returns detail");
        dropped_d_count = dropped_d_count.saturating_add(detail.dropped_d_count);
        dropped_c_count = dropped_c_count.saturating_add(detail.dropped_c_count);
        conductor_truncated |= detail.conductor_truncated;
        if count_total(items) >= before {
            break;
        }
    }

    let post_per_block = snapshot_per_block(items);
    Some(BudgetExceededDetail {
        cap,
        original_total,
        new_total: count_total(items),
        dropped_d_count,
        dropped_c_count,
        conductor_truncated,
        per_block: build_per_block(&pre_per_block, &post_per_block),
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
            content: "x".repeat(tokens as usize),
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

    #[test]
    fn one_d_item_is_dropped_via_div_ceil() {
        let mut items = vec![
            item(Block::A, 0.5, 0, 10),
            item(Block::D, 0.5, 1, 100),
            item(Block::E, 0.5, 0, 10),
        ];
        let detail = enforce_budget(&mut items, 20).expect("single D must degrade");
        assert_eq!(detail.dropped_d_count, 1);
        assert!(!items.iter().any(|item| item.block == Block::D));
        assert_eq!(detail.new_total, 20);
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

    #[test]
    fn one_c_item_is_dropped_via_div_ceil() {
        let mut items = vec![
            item(Block::A, 0.5, 0, 10),
            item(Block::C, 0.2, 0, 100),
            item(Block::E, 0.5, 0, 10),
        ];
        let detail = enforce_budget(&mut items, 20).expect("single C must degrade");
        assert_eq!(detail.dropped_c_count, 1);
        assert!(!items.iter().any(|item| item.block == Block::C));
        assert_eq!(detail.new_total, 20);
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
        // Total 700, cap 350 → exercise all three degradation steps.
        let detail = enforce_budget(&mut items, 350).expect("must trigger");
        // The point of this fixture is that every step fires in order
        // (D present, C present, Conductor present).
        assert!(
            detail.dropped_d_count > 0,
            "step 1 (drop oldest-50% D) must fire"
        );
        assert!(
            detail.dropped_c_count > 0,
            "step 2 (drop lowest-50% C) must fire"
        );
        assert!(
            detail.conductor_truncated,
            "step 3 (truncate Conductor) must fire"
        );
        // The policy is a SINGLE graceful pass (drop oldest-50% D, drop
        // lowest-50% C, halve Conductor once) — not loop-until-fit, as
        // `conductor_truncated_last_resort` pins (it leaves new_total >
        // cap with a still-degradable Conductor). So here `new_total`
        // can also still exceed the cap with degradable items left; the
        // BudgetExceededDetail reports that over-count to the operator.
        // We only require that degradation made real progress.
        assert!(
            detail.new_total < detail.original_total,
            "degradation must reduce the total ({} → {})",
            detail.original_total,
            detail.new_total
        );
    }

    #[test]
    fn provider_boundary_repeats_degradation_until_fit() {
        let mut items = vec![
            item(Block::A, 0.5, 0, 10),
            item(Block::D, 0.5, 1, 1_000),
            item(Block::C, 0.1, 0, 1_000),
            item(Block::Conductor, 0.5, 0, 1_000),
            item(Block::E, 0.5, 0, 10),
        ];
        let detail = enforce_budget_to_fit(&mut items, 100).expect("must degrade");
        assert!(detail.new_total <= 100, "{detail:?}");
        assert_eq!(detail.dropped_d_count, 1);
        assert_eq!(detail.dropped_c_count, 1);
        assert!(detail.conductor_truncated);
        assert!(
            items
                .iter()
                .all(|item| !matches!(item.block, Block::D | Block::C))
        );
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

    #[test]
    fn typed_render_and_user_replacement_keep_estimate_bound() {
        let mut items = vec![
            BlockItem::new(Block::A, "system"),
            BlockItem::new(Block::D, "recall"),
            BlockItem::new(Block::E, "hello"),
        ];
        let (prompt, system) = render_request(&items).expect("valid typed bundle");
        assert_eq!(prompt, "hello");
        assert_eq!(system.as_deref(), Some("system\n\nrecall"));

        replace_user_message(&mut items, "changed prompt").expect("one E item");
        let (prompt, _) = render_request(&items).expect("still valid");
        assert_eq!(prompt, "changed prompt");
        let user = items.iter().find(|item| item.block == Block::E).unwrap();
        assert_eq!(user.tokens, count_tokens_upper_bound("changed prompt"));
    }

    #[test]
    fn typed_render_rejects_missing_or_duplicate_user_blocks() {
        assert!(render_request(&[BlockItem::new(Block::A, "system")]).is_err());
        assert!(
            render_request(&[
                BlockItem::new(Block::E, "one"),
                BlockItem::new(Block::E, "two"),
            ])
            .is_err()
        );
    }

    #[test]
    fn unicode_conductor_truncation_recounts_retained_content() {
        let mut items = vec![
            BlockItem::new(Block::A, "a"),
            BlockItem::new(Block::Conductor, "🙂".repeat(40)),
            BlockItem::new(Block::E, "e"),
        ];
        let detail = enforce_budget(&mut items, 5).expect("conductor must truncate");
        assert!(detail.conductor_truncated);
        let conductor = items
            .iter()
            .find(|item| item.block == Block::Conductor)
            .unwrap();
        assert_eq!(
            conductor.tokens,
            count_tokens_upper_bound(&conductor.content)
        );
    }

    // ── effective_cap ─────────────────────────────────────────────

    #[test]
    fn effective_cap_scales_claude_opus_to_170k() {
        // 200_000 × 0.85 = 170_000; operator_cap > 170_000 so no clamp.
        let cap = effective_cap("claude_cli", "claude-opus-4-7", 200_000);
        assert_eq!(cap, 170_000);
    }

    #[test]
    fn effective_cap_clamps_to_operator_cap_when_lower() {
        // operator set a tight 50_000; effective_cap must not exceed it.
        let cap = effective_cap("anthropic_api", "claude-opus-4-7", 50_000);
        assert_eq!(cap, 50_000);
    }

    #[test]
    fn effective_cap_returns_operator_cap_for_unknown_model() {
        let cap = effective_cap("local_qwen", "qwen3-30b-a3b", 100_000);
        assert_eq!(cap, 100_000);
    }

    #[test]
    fn effective_cap_gpt4o_128k_scales_to_108800() {
        // 128_000 × 0.85 = 108_800; min(108_800, CAP_200K) = 108_800.
        let cap = effective_cap("openai_api", "gpt-4o", 200_000);
        assert_eq!(cap, 108_800);
    }

    #[test]
    fn effective_cap_gemini_pro_clamped_to_200k() {
        // 1_000_000 × 0.85 = 850_000 → clamped to CAP_200K (200_000).
        let cap = effective_cap("gemini_api", "gemini-2.5-pro", 200_000);
        assert_eq!(cap, 200_000);
    }

    #[test]
    fn dispatch_provider_cap_resolves_via_effective_cap() {
        // Simulate dispatch_provider: model="claude-opus-4-7", operator_cap=200_000.
        // The auto-scaler must yield 170_000 (85% of 200k window),
        // NOT the raw operator_cap of 200_000.
        let cap = effective_cap("claude_cli", "claude-opus-4-7", 200_000);
        assert_eq!(
            cap, 170_000,
            "dispatch_provider must use auto-scaled cap for claude-opus-4-7"
        );
        // Verify it still respects a tight operator ceiling (50k < 170k → clamp).
        let tight = effective_cap("claude_cli", "claude-opus-4-7", 50_000);
        assert_eq!(tight, 50_000);
        // operator_cap=100k is also below the 170k window-scale → clamp to 100k.
        let mid = effective_cap("claude_cli", "claude-opus-4-7", 100_000);
        assert_eq!(mid, 100_000);
    }
}
