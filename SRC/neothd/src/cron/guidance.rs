//! N-05 (Session 24) — `cron-vs-n8n` decision rule lifted from
//! `docs/cron-vs-n8n.md` into runtime guidance.
//!
//! Operators adding a 3rd cron entry to `freedom.yaml` typically
//! cross the n8n threshold without realising it — at which point
//! the YAML becomes a debug-by-grep affair instead of the
//! browser-visible flow n8n offers. The doc spells out the rule
//! but it lives outside the runtime; this module ports the
//! heuristic into a typed classifier the CLI + future GUI can
//! call without operators re-reading the doc.
//!
//! ## Heuristic
//!
//! A job spec is classified into one of three buckets:
//!
//! - [`Recommendation::UseLocalCron`] — single CLI command, no
//!   shell branching, no chained processes, low frequency.
//!   "Operator-readable in 1 line" matches the doc's threshold.
//! - [`Recommendation::UseN8n`] — multi-step pipeline / branching /
//!   external trigger / fan-out / visual debugging required.
//! - [`Recommendation::CouldGoEither`] — the spec qualifies as
//!   "simple enough for local cron" BUT carries a hint that
//!   suggests the operator may want n8n's tweakability (e.g.
//!   schedule the operator might edit weekly).
//!
//! ## Why heuristic + not a strict parser
//!
//! The doc itself names the rule a "rule-of-thumb"; pretending we
//! have a strict classification would over-promise. The classifier
//! flags every reason it picked a bucket so operators see WHICH
//! signal moved the needle.

use serde::{Deserialize, Serialize};

/// Caller-supplied spec for one job. Mirrors the smallest subset
/// of [`crate::cron::schema::Job`] needed to classify — split out
/// so this module doesn't depend on the full job loader.
#[derive(Debug, Clone)]
pub struct JobSpec<'a> {
    /// The full command line the job will execute. Examples:
    ///   "neoth recall \"today's standup\""
    ///   "neoth memory gc --tier cold && neoth memory stats"
    pub command: &'a str,
    /// 5-field cron expression. Used to infer frequency.
    pub cron_expr: &'a str,
    /// Whether this job was triggered by an external event (webhook,
    /// git push, file watcher). Strong signal for n8n.
    pub has_external_trigger: bool,
    /// Optional operator hint: "this is something I'll tweak weekly"
    /// or "this is fire-and-forget". Tilts borderline cases.
    pub operator_will_tweak_often: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Recommendation {
    /// freedom.yaml::cron is the right home. `reasons` lists every
    /// signal that pointed there.
    UseLocalCron { reasons: Vec<String> },
    /// n8n workflow is the right home.
    UseN8n { reasons: Vec<String> },
    /// Both work; operator's call. `reasons` lists the trade-off.
    CouldGoEither { reasons: Vec<String> },
}

impl Recommendation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Recommendation::UseLocalCron { .. } => "use_local_cron",
            Recommendation::UseN8n { .. } => "use_n8n",
            Recommendation::CouldGoEither { .. } => "could_go_either",
        }
    }

    pub fn reasons(&self) -> &[String] {
        match self {
            Recommendation::UseLocalCron { reasons }
            | Recommendation::UseN8n { reasons }
            | Recommendation::CouldGoEither { reasons } => reasons,
        }
    }
}

/// Run the heuristic. Pure — no IO, no clock.
pub fn classify(spec: &JobSpec<'_>) -> Recommendation {
    let mut n8n_reasons = Vec::new();
    let mut local_reasons = Vec::new();

    // ── n8n signals ───────────────────────────────────────────────
    if spec.has_external_trigger {
        n8n_reasons.push(
            "external trigger (webhook / git push / file watcher) — local cron has no listener"
                .into(),
        );
    }
    if has_shell_branching(spec.command) {
        n8n_reasons.push(
            "command contains shell branching (`&&` / `||` / `if` / `case`) — n8n has explicit branch nodes"
                .into(),
        );
    }
    if has_shell_chaining(spec.command) {
        n8n_reasons.push(
            "command chains multiple processes (`;` / `|`) — n8n has per-step retry + debug view"
                .into(),
        );
    }
    if has_subshell(spec.command) {
        n8n_reasons.push(
            "command spawns subshells (`$( )` / backticks) — n8n's node model is clearer".into(),
        );
    }
    let est_fires = estimate_fires_per_day(spec.cron_expr);
    if est_fires > 24 {
        n8n_reasons.push(format!(
            "estimated {} fires/day (> 24) — n8n's visual debug helps at high frequency",
            est_fires,
        ));
    }

    // ── local-cron signals ────────────────────────────────────────
    if spec.command.trim_start().starts_with("neoth ") {
        local_reasons.push("single `neoth` CLI command — operator-readable in 1 line".into());
    }
    if est_fires <= 4 {
        local_reasons.push(format!(
            "estimated {} fires/day (≤ 4) — local cron keeps the schedule visible in freedom.yaml",
            est_fires,
        ));
    }

    // ── verdict ───────────────────────────────────────────────────
    if !n8n_reasons.is_empty() {
        return Recommendation::UseN8n {
            reasons: n8n_reasons,
        };
    }
    // Tiebreaker per doc: operator-tweakability tilts to n8n.
    if spec.operator_will_tweak_often {
        return Recommendation::CouldGoEither {
            reasons: vec![
                "single CLI command qualifies for local cron".into(),
                "operator hint: will tweak often — n8n's UI is friendlier for weekly edits".into(),
            ],
        };
    }
    if local_reasons.is_empty() {
        // No strong signal in either direction — could-go-either.
        return Recommendation::CouldGoEither {
            reasons: vec![
                "no strong signal — short command + plausible frequency in either home".into(),
            ],
        };
    }
    Recommendation::UseLocalCron {
        reasons: local_reasons,
    }
}

fn has_shell_branching(cmd: &str) -> bool {
    cmd.contains("&&") || cmd.contains("||") || has_word(cmd, "if ") || has_word(cmd, "case ")
}

fn has_shell_chaining(cmd: &str) -> bool {
    // `;` outside of quotes; `|` that isn't `||`.
    let mut in_squote = false;
    let mut in_dquote = false;
    let bytes = cmd.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'\'' if !in_dquote => in_squote = !in_squote,
            b'"' if !in_squote => in_dquote = !in_dquote,
            b';' if !in_squote && !in_dquote => return true,
            b'|' if !in_squote && !in_dquote => {
                // Skip `||` — that's branching, handled above.
                if i + 1 < bytes.len() && bytes[i + 1] == b'|' {
                    i += 1;
                } else {
                    return true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

fn has_subshell(cmd: &str) -> bool {
    cmd.contains("$(") || cmd.contains('`')
}

fn has_word(haystack: &str, needle: &str) -> bool {
    // Crude word-boundary check: needle preceded by start/space + followed
    // by space (the needle here always ends with a space already).
    if let Some(pos) = haystack.find(needle) {
        if pos == 0 {
            return true;
        }
        let prev = haystack.as_bytes()[pos - 1];
        return prev == b' ' || prev == b';' || prev == b'\n';
    }
    false
}

/// Estimate fires/day from a 5-field cron expression. Rough — the
/// goal is just to put a job in one of three buckets (≤4 / 5-24 /
/// >24). We don't pull in the `cron` crate's stepper for this
/// since the heuristic only needs an order-of-magnitude answer.
fn estimate_fires_per_day(expr: &str) -> u32 {
    let parts: Vec<&str> = expr.split_whitespace().collect();
    if parts.len() < 5 {
        // Unparseable → conservative default that doesn't tip the
        // verdict either way.
        return 4;
    }
    let minute = parts[0];
    let hour = parts[1];
    let minute_per_hour = field_density(minute, 60);
    let hours_per_day = field_density(hour, 24);
    minute_per_hour * hours_per_day
}

/// Estimate how many distinct values a single cron field expands to.
/// Recognises:
///   - `*`            → max (all values)
///   - `*/N`          → max/N
///   - `1,3,5`        → comma-count
///   - `1-5`          → range size
///   - single integer → 1
/// Conservative: any unparseable shape returns 1 so we don't
/// inflate the estimate.
fn field_density(field: &str, max: u32) -> u32 {
    if field == "*" {
        return max;
    }
    if let Some(rest) = field.strip_prefix("*/") {
        if let Ok(step) = rest.parse::<u32>() {
            if step == 0 {
                return 1;
            }
            return (max + step - 1) / step;
        }
    }
    if field.contains(',') {
        return field.split(',').count() as u32;
    }
    if let Some((a, b)) = field.split_once('-') {
        if let (Ok(lo), Ok(hi)) = (a.parse::<u32>(), b.parse::<u32>()) {
            if hi >= lo {
                return hi - lo + 1;
            }
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec<'a>(command: &'a str, cron_expr: &'a str) -> JobSpec<'a> {
        JobSpec {
            command,
            cron_expr,
            has_external_trigger: false,
            operator_will_tweak_often: false,
        }
    }

    #[test]
    fn simple_neoth_command_routes_to_local_cron() {
        let r = classify(&spec("neoth recall \"today\"", "0 9 * * 1-5"));
        match r {
            Recommendation::UseLocalCron { reasons } => {
                assert!(reasons.iter().any(|s| s.contains("CLI command")));
            }
            other => panic!("expected UseLocalCron, got {other:?}"),
        }
    }

    #[test]
    fn external_trigger_routes_to_n8n() {
        let mut s = spec("neoth chat send brief", "* * * * *");
        s.has_external_trigger = true;
        let r = classify(&s);
        assert!(matches!(r, Recommendation::UseN8n { .. }));
        assert!(r.reasons().iter().any(|s| s.contains("external trigger")));
    }

    #[test]
    fn shell_branching_routes_to_n8n() {
        for cmd in &[
            "neoth a && neoth b",
            "neoth a || neoth b",
            "if [ -f /tmp/x ]; then neoth a; fi",
            "case $X in foo) neoth a;; esac",
        ] {
            let r = classify(&spec(cmd, "0 * * * *"));
            assert!(
                matches!(r, Recommendation::UseN8n { .. }),
                "expected n8n for: {cmd}",
            );
            assert!(
                r.reasons()
                    .iter()
                    .any(|s| s.contains("branching") || s.contains("chains")),
                "missing branching/chains reason: {:?}",
                r.reasons(),
            );
        }
    }

    #[test]
    fn pipe_routes_to_n8n_but_double_pipe_is_branching_not_chain() {
        // `|` alone = chain; `||` = branch. Both should route to n8n
        // but for DIFFERENT documented reasons.
        let pipe = classify(&spec("neoth recall x | jq .", "0 * * * *"));
        assert!(matches!(pipe, Recommendation::UseN8n { .. }));
        assert!(
            pipe.reasons()
                .iter()
                .any(|s| s.contains("chains multiple processes")),
            "got: {:?}",
            pipe.reasons(),
        );
        let or = classify(&spec("neoth a || neoth b", "0 * * * *"));
        assert!(matches!(or, Recommendation::UseN8n { .. }));
        assert!(
            or.reasons().iter().any(|s| s.contains("branching")),
            "got: {:?}",
            or.reasons(),
        );
    }

    #[test]
    fn subshell_routes_to_n8n() {
        let r = classify(&spec("neoth chat send \"$(date)\"", "0 9 * * *"));
        assert!(matches!(r, Recommendation::UseN8n { .. }));
        assert!(r.reasons().iter().any(|s| s.contains("subshell")));
    }

    #[test]
    fn high_frequency_routes_to_n8n() {
        // Every minute = 1440 fires/day → way over the 24 threshold.
        let r = classify(&spec("neoth chat ping", "* * * * *"));
        assert!(matches!(r, Recommendation::UseN8n { .. }));
        assert!(r.reasons().iter().any(|s| s.contains("fires/day")));
    }

    #[test]
    fn operator_will_tweak_often_tilts_to_could_go_either() {
        // Simple command that would route to local cron BUT operator
        // hint moves it to could-go-either.
        let mut s = spec("neoth chat send brief", "30 7 * * *");
        s.operator_will_tweak_often = true;
        let r = classify(&s);
        assert!(matches!(r, Recommendation::CouldGoEither { .. }));
        assert!(r.reasons().iter().any(|s| s.contains("tweak often")));
    }

    #[test]
    fn estimate_fires_per_day_handles_basic_shapes() {
        // 5 fields: minute / hour / dom / mon / dow
        assert_eq!(estimate_fires_per_day("0 9 * * *"), 1, "daily at 09:00");
        assert_eq!(estimate_fires_per_day("0 * * * *"), 24, "hourly");
        assert_eq!(estimate_fires_per_day("* * * * *"), 60 * 24, "every minute");
        assert_eq!(estimate_fires_per_day("0 9,17 * * *"), 2, "twice a day");
        assert_eq!(estimate_fires_per_day("0 9-17 * * *"), 9, "business hours");
        assert_eq!(
            estimate_fires_per_day("*/15 * * * *"),
            4 * 24,
            "every 15min"
        );
    }

    #[test]
    fn estimate_fires_per_day_unparseable_returns_conservative_default() {
        // No panics on bad input; returns a low number so a bogus
        // expression doesn't accidentally tip the verdict to n8n.
        assert_eq!(estimate_fires_per_day(""), 4);
        assert_eq!(estimate_fires_per_day("garbage"), 4);
        assert_eq!(estimate_fires_per_day("0 9 * *"), 4, "too few fields");
    }

    #[test]
    fn no_strong_signal_returns_could_go_either() {
        // Bare command (not "neoth ..." → no local signal) +
        // middle-frequency (5-24 fires/day, outside both the ≤4
        // local-anchor and the >24 n8n-anchor bands) + no
        // operator-hint = nothing tips the verdict.
        let r = classify(&spec("some-third-party-tool", "0 8-15 * * *"));
        match r {
            Recommendation::CouldGoEither { reasons } => {
                assert!(reasons.iter().any(|s| s.contains("no strong signal")));
            }
            other => panic!("expected CouldGoEither, got {other:?}"),
        }
    }

    #[test]
    fn recommendation_as_str_pinned_for_audit() {
        // Drift guard: a future GUI/CLI consumer renders these
        // strings into widgets / WAL audit. Don't change them
        // without bumping a doc reference.
        assert_eq!(
            Recommendation::UseLocalCron { reasons: vec![] }.as_str(),
            "use_local_cron",
        );
        assert_eq!(
            Recommendation::UseN8n { reasons: vec![] }.as_str(),
            "use_n8n",
        );
        assert_eq!(
            Recommendation::CouldGoEither { reasons: vec![] }.as_str(),
            "could_go_either",
        );
    }
}
