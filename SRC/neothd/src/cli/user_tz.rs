//! GOLD-ADAPT-ODY-28 — User-local TZ context injection.
//!
//! Prepends a concise time-context paragraph to the user-role message on every
//! provider turn when a valid IANA timezone is configured. Prevents training-year
//! hallucination and anchors scheduling references to the operator's local time.
//!
//! # Design notes
//!
//! - The block lands in the **USER-role** message, not the system prompt. The
//!   system prompt is prefix-cached per session; injecting per-turn time content
//!   there would bust the cache on every message. The user turn already busts
//!   prefix cache on every message, so per-turn time content adds no cache cost.
//! - Resolution order: `NEOTH_TZ` env var > `freedom.yaml::user_tz` > None (no-op).
//! - Invalid IANA names produce a `tracing::warn!` and skip the inject (fail-open:
//!   the user message is passed through unchanged).
//! - No `chrono::Local` — uses `chrono::Utc::now().with_timezone(&tz)` via the
//!   `chrono-tz` crate already declared in `Cargo.toml`. No `iana-time-zone` dep.

use chrono_tz::Tz;

/// Resolve the configured IANA timezone name.
///
/// Priority: `NEOTH_TZ` env var > `config.user_tz` field.
/// Returns `None` when neither is set or the name is invalid.
pub fn resolve_tz_name(config: &crate::config::FreedomConfig) -> Option<String> {
    // Env var wins over config field.
    let raw = std::env::var("NEOTH_TZ")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| config.user_tz.clone())?;

    // Validate: parse as chrono_tz::Tz. Unknown names → warn + None.
    match raw.parse::<Tz>() {
        Ok(_) => Some(raw),
        Err(_) => {
            tracing::warn!(
                tz = %raw,
                "GOLD-ADAPT-ODY-28: invalid IANA timezone name — TZ context inject skipped"
            );
            None
        }
    }
}

/// Format the UTC offset string for a given IANA timezone name as `±HH:MM`.
///
/// Uses the offset at `Utc::now()` — DST-aware, not a static fixed offset.
/// Computes offset as the difference between local naive time and UTC naive time
/// (avoids any dependency on the specific `Offset` trait impl of `chrono_tz`).
fn format_utc_offset(tz: Tz) -> String {
    let now_utc = chrono::Utc::now();
    let local = now_utc.with_timezone(&tz);
    // Compute total offset seconds: (local naive) - (utc naive).
    let diff = local.naive_local() - now_utc.naive_utc();
    let total_secs = diff.num_seconds();
    let sign = if total_secs < 0 { '-' } else { '+' };
    let abs_secs = total_secs.unsigned_abs();
    let hours = abs_secs / 3600;
    let minutes = (abs_secs % 3600) / 60;
    format!("{sign}{hours:02}:{minutes:02}")
}

/// Render the TZ context paragraph for a given IANA timezone name.
///
/// Returns a single concise paragraph the model reads as the opening of the
/// user-role message turn. The date+time changes each turn (intentional — the
/// user turn busts prefix cache anyway); the IANA name + UTC offset are stable
/// within a DST window.
pub fn format_tz_context(tz_name: &str) -> String {
    // parse is guaranteed valid at this call site (resolve_tz_name already validated).
    let tz: Tz = match tz_name.parse() {
        Ok(t) => t,
        Err(_) => return String::new(),
    };
    let now_utc = chrono::Utc::now();
    let local = now_utc.with_timezone(&tz);
    let utc_offset = format_utc_offset(tz);
    // ISO weekday name (Mon/Tue/…) + ISO date + HH:MM local time.
    let weekday = local.format("%a").to_string();
    let date = local.format("%Y-%m-%d").to_string();
    let time = local.format("%H:%M").to_string();
    format!(
        "Current time context: {weekday} {date} {time} UTC{utc_offset} ({tz_name}). \
         When referencing dates or scheduling, use this timezone."
    )
}

/// Return the UTC offset string for a resolved IANA tz name (e.g. `"+02:00"`).
///
/// Returns `"+00:00"` on any parse failure (already validated by `resolve_tz_name`,
/// so failure here is unreachable in the normal flow).
pub fn utc_offset_for(tz_name: &str) -> String {
    match tz_name.parse::<Tz>() {
        Ok(tz) => format_utc_offset(tz),
        Err(_) => "+00:00".to_owned(),
    }
}

/// Prepend a TZ context block to `prompt` when a valid timezone is configured.
///
/// Returns `prompt.to_owned()` unchanged when no TZ is configured or valid.
/// When TZ is active, returns `"<context>\n\n<prompt>"`.
pub fn maybe_prepend_tz(prompt: &str, config: &crate::config::FreedomConfig) -> String {
    match resolve_tz_name(config) {
        None => prompt.to_owned(),
        Some(tz_name) => {
            let context = format_tz_context(&tz_name);
            if context.is_empty() {
                prompt.to_owned()
            } else {
                format!("{context}\n\n{prompt}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FreedomConfig;

    fn cfg_with_tz(tz: Option<&str>) -> FreedomConfig {
        FreedomConfig {
            user_tz: tz.map(|s| s.to_owned()),
            ..Default::default()
        }
    }

    /// Mutex that serialises all env-var-touching tests in this module.
    /// Tests that read/write NEOTH_TZ must hold this lock for their entire body
    /// — env vars are process-global, so parallel test threads race otherwise.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> =
            std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .expect("env_lock poisoned")
    }

    /// Run `f` with NEOTH_TZ unset, then restore whatever was set before.
    fn without_env<F: FnOnce() -> R, R>(f: F) -> R {
        let _guard = env_lock();
        let was = std::env::var("NEOTH_TZ").ok();
        // SAFETY: we hold `env_lock`, so no other test is racing this env var.
        unsafe { std::env::remove_var("NEOTH_TZ") };
        let r = f();
        match was {
            Some(v) => unsafe { std::env::set_var("NEOTH_TZ", &v) },
            None => {}
        }
        r
    }

    #[test]
    fn no_tz_returns_none() {
        without_env(|| {
            let cfg = cfg_with_tz(None);
            assert!(resolve_tz_name(&cfg).is_none());
        });
    }

    #[test]
    fn config_field_resolves() {
        without_env(|| {
            let cfg = cfg_with_tz(Some("America/New_York"));
            assert_eq!(
                resolve_tz_name(&cfg).as_deref(),
                Some("America/New_York")
            );
        });
    }

    #[test]
    fn env_var_wins_over_config_field() {
        let _guard = env_lock();
        // SAFETY: serialised by env_lock.
        unsafe { std::env::set_var("NEOTH_TZ", "Asia/Tokyo") };
        let cfg = cfg_with_tz(Some("America/New_York"));
        let result = resolve_tz_name(&cfg);
        unsafe { std::env::remove_var("NEOTH_TZ") };
        assert_eq!(result.as_deref(), Some("Asia/Tokyo"));
    }

    #[test]
    fn invalid_iana_returns_none() {
        without_env(|| {
            let cfg = cfg_with_tz(Some("Not/A/Real/Timezone"));
            assert!(resolve_tz_name(&cfg).is_none());
        });
    }

    #[test]
    fn format_tz_context_contains_utc_offset_and_iana_name() {
        // format_tz_context is pure (no env reads) — no lock needed.
        let ctx = format_tz_context("Europe/Berlin");
        // Must contain the IANA name.
        assert!(ctx.contains("Europe/Berlin"), "missing IANA name: {ctx}");
        // Must contain a UTC± offset in ±HH:MM form.
        assert!(
            ctx.contains("UTC+") || ctx.contains("UTC-"),
            "missing UTC offset: {ctx}"
        );
        // Must start with "Current time context:".
        assert!(ctx.starts_with("Current time context:"), "wrong prefix: {ctx}");
        // Must end with scheduling hint.
        assert!(
            ctx.contains("use this timezone"),
            "missing scheduling hint: {ctx}"
        );
    }

    #[test]
    fn maybe_prepend_noop_when_no_tz() {
        without_env(|| {
            let cfg = cfg_with_tz(None);
            let prompt = "Hello, NEOTH!";
            assert_eq!(maybe_prepend_tz(prompt, &cfg), prompt);
        });
    }

    #[test]
    fn maybe_prepend_inserts_context_paragraph_separator() {
        without_env(|| {
            let cfg = cfg_with_tz(Some("Europe/Berlin"));
            let prompt = "Schedule a meeting for tomorrow";
            let result = maybe_prepend_tz(prompt, &cfg);
            // Context block must precede original prompt, separated by \n\n.
            assert!(result.contains("\n\nSchedule a meeting for tomorrow"),
                "separator missing: {result}");
            assert!(result.starts_with("Current time context:"),
                "no context prefix: {result}");
            assert!(result.contains("Europe/Berlin"),
                "no IANA name: {result}");
        });
    }

    #[test]
    fn utc_offset_format_is_hhmm() {
        // Etc/UTC is always +00:00 — deterministic regardless of host DST.
        let tz: Tz = "Etc/UTC".parse().unwrap();
        let offset = format_utc_offset(tz);
        assert_eq!(offset, "+00:00", "UTC offset wrong: {offset}");

        // Europe/London is UTC+0 or UTC+1 depending on DST — either is ±HH:MM.
        let tz2: Tz = "Europe/London".parse().unwrap();
        let offset2 = format_utc_offset(tz2);
        // Must start with + or -.
        assert!(
            offset2.starts_with('+') || offset2.starts_with('-'),
            "no sign: {offset2}"
        );
        assert_eq!(offset2.len(), 6, "wrong length: {offset2}");
        // HH and MM are ASCII digits (colon at index 3).
        let digits: String = offset2.chars().skip(1).filter(|c| c.is_ascii_digit()).collect();
        assert_eq!(digits.len(), 4, "expected 4 digits: {offset2}");
    }
}
