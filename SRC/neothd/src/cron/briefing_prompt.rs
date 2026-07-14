//! OH-06 — Morning-briefing system-prompt engineering.
//!
//! Pure module: no I/O, no async, no external crate dependencies beyond `std`.
//! Adapts the behavioural rules from
//! `QUELLEN/openhuman/src/openhuman/agent/agents/morning_briefing/prompt.md`.
//!
//! ## What this module provides
//!
//! - `GREETING_POOL` — 8 varied German/English greeting fragments that rotate
//!   daily so the briefing doesn't open with the same sentence every morning.
//! - `pick_greeting(seed)` — deterministic daily pick (seed = UTC day number).
//! - `render_briefing_system_prompt(tz_name, local_datetime)` — assembles the
//!   full system prompt injected into the provider `Request::system` field for
//!   every `CronRole::Briefing` job. Enforces:
//!   - Greeting variety (cites `GREETING_POOL` instruction, not the literal text).
//!   - Scannable structure (headers + bullets).
//!   - 200–400 word target.
//!   - Honest-about-gaps rule (never fabricate missing data).
//!   - No-fabricate rule (state "not connected" / "unavailable" explicitly).
//!   - Timezone injection (IANA name + local datetime, so the model knows the
//!     operator's morning context without being asked).

/// Greeting fragments to rotate across. Each is the opening phrase only;
/// the model composes the rest of the first sentence. Deliberately mixed
/// DE/EN to match the NEOTH operator language profile (German cues +
/// English code / commit commentary).
pub const GREETING_POOL: &[&str] = &[
    "Guten Morgen!",
    "Moin!",
    "Hey,",
    "Hi —",
    "Morning.",
    "Guten Morgen —",
    "Hello,",
    "Moin moin —",
];

/// Pick a greeting fragment that is stable within a UTC calendar day but
/// rotates daily. `seed` should be `now_unix_secs / 86400` (the UTC day
/// number) — callers already have `now` so this costs one division.
///
/// Deterministic, no `rand` dependency.
pub fn pick_greeting(seed: u64) -> &'static str {
    GREETING_POOL[(seed as usize) % GREETING_POOL.len()]
}

/// Build the system prompt injected into every `CronRole::Briefing` provider
/// call. The prompt encodes the OH behavioural rules verbatim so the model
/// never needs to infer them from the operator's job prompt alone.
///
/// `tz_name`       — IANA timezone name (e.g. "Europe/Berlin"). Obtained from
///                   `job.schedule.timezone().name()`. Falls back to "UTC" when
///                   the job has no explicit `tz` field.
/// `local_datetime` — Formatted local time string, e.g. "Monday, 2026-06-22 07:15".
///                   Callers format via `now_local.format("%A, %Y-%m-%d %H:%M")`.
pub fn render_briefing_system_prompt(tz_name: &str, local_datetime: &str) -> String {
    // Explain the UTC-fallback case so the operator sees it in their system
    // prompt and can add an explicit tz to their job if desired.
    let tz_note = if tz_name == "UTC" {
        " (timezone not configured on this job — defaulting to UTC; \
add `tz: Europe/Berlin` or your local timezone under `schedule:` to localise the briefing)"
    } else {
        ""
    };

    format!(
        r#"You are NEOTH's morning-briefing agent. Your role is to deliver a clear, \
honest, and scannable briefing that the operator can absorb in under 30 seconds \
over their morning coffee.

## Context

- Current local time: {local_datetime}
- Operator timezone: {tz_name}{tz_note}

## Output structure

Use Markdown headings and bullets so the briefing is scannable at a glance:

```
## Morning Brief — <date>

### <Section 1 — e.g. Tech / News / Calendar>
- …

### <Section 2>
- …

### Summary
One or two sentences.
```

## Greeting

Open with a varied, warm-but-efficient greeting. Do NOT repeat the same \
opening phrase every day — vary the phrasing, language (German or English), \
and register (casual "Moin!" vs. formal "Guten Morgen"). Keep the greeting \
to one short sentence; the operator wants the briefing immediately after it.

## Length

Target 200–400 words. A briefing shorter than 150 words is too thin to be \
useful. A briefing longer than 500 words costs the operator time they don't \
have in the morning.

## Honest-about-gaps rule (critical)

If a data source, calendar, or feed is not connected or not available at \
call time, say so explicitly in the relevant section — for example: \
"Calendar: not connected — skipping." or "News feed: unavailable.". \
Do NOT invent, approximate, or hallucinate content for missing sources. \
It is far better to note a gap than to fabricate plausible-sounding events.

## No-fabricate rule (critical)

Never invent facts, events, statistics, or citations. If you do not have \
real data for a section, state "No data available" and move on. The operator \
relies on this briefing to start their day — a confident-sounding fabrication \
is worse than silence.

## Tone

Professional but warm. Efficient — the operator is busy. No filler phrases \
("Certainly!", "Of course!", "As an AI …"). Deliver the information; the \
operator will ask follow-up questions if they need them."#,
        local_datetime = local_datetime,
        tz_name = tz_name,
        tz_note = tz_note,
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_pool_is_non_empty_and_all_entries_non_empty() {
        assert!(!GREETING_POOL.is_empty());
        for g in GREETING_POOL {
            assert!(!g.is_empty(), "greeting entry must not be empty");
        }
    }

    #[test]
    fn pick_greeting_is_deterministic_for_same_seed() {
        let g1 = pick_greeting(42);
        let g2 = pick_greeting(42);
        assert_eq!(g1, g2);
    }

    #[test]
    fn pick_greeting_rotates_across_consecutive_days() {
        // Over POOL_LEN consecutive days we must see at least 2 distinct greetings.
        let len = GREETING_POOL.len() as u64;
        let greetings: std::collections::HashSet<&str> = (0..len).map(pick_greeting).collect();
        assert!(
            greetings.len() == GREETING_POOL.len(),
            "all greetings should appear once across len days: {greetings:?}"
        );
    }

    #[test]
    fn pick_greeting_wraps_cleanly_for_large_seeds() {
        // Must not panic for large seed values (overflow-safe via wrapping %).
        let g = pick_greeting(u64::MAX);
        assert!(GREETING_POOL.contains(&g));
    }

    #[test]
    fn render_prompt_contains_tz_name() {
        let prompt = render_briefing_system_prompt("Europe/Berlin", "Monday, 2026-06-22 07:15");
        assert!(
            prompt.contains("Europe/Berlin"),
            "system prompt must embed the tz name: {prompt}"
        );
    }

    #[test]
    fn render_prompt_contains_local_datetime() {
        let prompt = render_briefing_system_prompt("Europe/Berlin", "Monday, 2026-06-22 07:15");
        assert!(
            prompt.contains("Monday, 2026-06-22 07:15"),
            "system prompt must embed the local datetime: {prompt}"
        );
    }

    #[test]
    fn render_prompt_contains_word_count_target() {
        let prompt = render_briefing_system_prompt("UTC", "Sunday, 2026-06-22 06:00");
        assert!(
            prompt.contains("200") && prompt.contains("400"),
            "system prompt must state 200-400 word target: {prompt}"
        );
    }

    #[test]
    fn render_prompt_contains_no_fabricate_rule() {
        let prompt = render_briefing_system_prompt("UTC", "Sunday, 2026-06-22 06:00");
        assert!(
            prompt.to_ascii_lowercase().contains("fabricat")
                || prompt.to_ascii_lowercase().contains("invent"),
            "system prompt must include no-fabricate rule: {prompt}"
        );
    }

    #[test]
    fn render_prompt_contains_honest_about_gaps() {
        let prompt = render_briefing_system_prompt("UTC", "Sunday, 2026-06-22 06:00");
        assert!(
            prompt.to_ascii_lowercase().contains("gap")
                || prompt.to_ascii_lowercase().contains("not connected")
                || prompt.to_ascii_lowercase().contains("unavailable"),
            "system prompt must include honest-about-gaps rule: {prompt}"
        );
    }

    #[test]
    fn render_prompt_utc_fallback_contains_config_hint() {
        let prompt = render_briefing_system_prompt("UTC", "Sunday, 2026-06-22 06:00");
        assert!(
            prompt.contains("timezone not configured"),
            "UTC prompt must include config hint: {prompt}"
        );
    }

    #[test]
    fn render_prompt_non_utc_no_config_hint() {
        let prompt = render_briefing_system_prompt("Europe/Berlin", "Monday, 2026-06-22 07:00");
        assert!(
            !prompt.contains("timezone not configured"),
            "non-UTC prompt must not include the UTC fallback hint: {prompt}"
        );
    }
}
