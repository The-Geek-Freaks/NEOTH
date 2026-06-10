//! GOLD-ADOPT-24 — turn-end context-window usage bar.
//!
//! Ported from goose's `session/output.rs` context-bar renderer (the pct → bar
//! → threshold-color math), adapted to NEOTH's reality:
//!
//! - **Limit = `tokens.max_per_request`**, NOT a hardcoded per-model context
//!   window. NEOTH has a HARD RULE against hardcoding per-model data (it must
//!   never need hand-patching for new models — CLI providers pass through any
//!   model id). The operator already tunes `freedom.yaml::tokens.max_per_request`
//!   to their model's real window (the same value ADOPT-19 compaction uses), so
//!   the bar measures "this turn vs your configured cap" — portable + accurate.
//! - **No cost-estimate line.** goose renders `tokens × per-model-price → $`,
//!   which would require a hardcoded per-model price table (violates the
//!   model-version-agnostic rule) AND is misleading on NEOTH's default path
//!   (`claude_cli` is a flat subscription — zero per-token cost). Deliberately
//!   omitted; `neoth status` / the usage log carry real burn for operators who
//!   want it.

/// Render a fixed-width usage bar for `used` tokens against `limit`. Returns
/// `None` when `limit == 0` (no cap configured → nothing meaningful to show).
/// Plain text (no ANSI) so it is unit-testable; the print site may colorize.
pub fn render_context_bar(used: u32, limit: u32) -> Option<String> {
    if limit == 0 {
        return None;
    }
    let pct = ((used as f64 / limit as f64) * 100.0).round().min(100.0) as u32;
    const WIDTH: u32 = 20;
    let filled = ((pct as f64 / 100.0) * WIDTH as f64).round() as u32;
    let filled = filled.min(WIDTH);
    let bar: String = "━".repeat(filled as usize) + &"╌".repeat((WIDTH - filled) as usize);
    Some(format!(
        "  context {bar} {pct}% {}/{}",
        format_tokens(used),
        format_tokens(limit)
    ))
}

/// A heat label for the bar (lets the print site pick a color without the
/// renderer depending on a terminal-color crate). goose's thresholds: <50 cool,
/// <85 warm, else hot.
pub fn usage_heat(used: u32, limit: u32) -> &'static str {
    if limit == 0 {
        return "cool";
    }
    let pct = (used as f64 / limit as f64) * 100.0;
    if pct < 50.0 {
        "cool"
    } else if pct < 85.0 {
        "warm"
    } else {
        "hot"
    }
}

/// Compact token count: `42`, `1k`, `1.3M` (goose's `format_tokens`).
fn format_tokens(n: u32) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.0}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bar_none_when_no_limit() {
        assert_eq!(render_context_bar(500, 0), None);
    }

    #[test]
    fn bar_renders_pct_and_counts() {
        // 25k / 100k = 25%, 5/20 filled.
        let b = render_context_bar(25_000, 100_000).unwrap();
        assert!(b.contains("25%"), "{b}");
        assert!(b.contains("25k/100k"), "{b}");
        assert_eq!(b.matches('━').count(), 5, "5 filled at 25%: {b}");
        assert_eq!(b.matches('╌').count(), 15, "15 empty: {b}");
    }

    #[test]
    fn bar_caps_at_full_when_over_limit() {
        let b = render_context_bar(150_000, 100_000).unwrap();
        assert!(b.contains("100%"), "over-limit clamps to 100%: {b}");
        assert_eq!(b.matches('━').count(), 20);
        assert_eq!(b.matches('╌').count(), 0);
    }

    #[test]
    fn heat_thresholds_match_goose() {
        assert_eq!(usage_heat(10, 100), "cool"); // 10%
        assert_eq!(usage_heat(49, 100), "cool");
        assert_eq!(usage_heat(50, 100), "warm");
        assert_eq!(usage_heat(84, 100), "warm");
        assert_eq!(usage_heat(85, 100), "hot");
        assert_eq!(usage_heat(100, 100), "hot");
        assert_eq!(usage_heat(5, 0), "cool"); // no limit → cool
    }

    #[test]
    fn format_tokens_scales() {
        assert_eq!(format_tokens(42), "42");
        assert_eq!(format_tokens(1_500), "2k"); // rounds
        assert_eq!(format_tokens(1_300_000), "1.3M");
    }
}
