//! UX-05 — Day-30 "unlock moment" check-in banner.
//!
//! Shown ONCE, at chat session start, after the operator has been
//! running NEOTH for 30+ days, IFF they still haven't switched on one of
//! the opt-in power features (profile learning / dreaming / proactive
//! messaging). A consume-once marker file suppresses it after the first
//! display — the same pattern as the first-tour banner. Pure stdout +
//! one marker file: no WAL frame, no wire format, no persisted protocol.

use std::path::Path;

use crate::config::FreedomConfig;

/// Consume-once marker; its presence suppresses the banner forever.
pub const UNLOCK_MARKER: &str = "unlock_moment_shown";

const THIRTY_DAYS_SECS: u64 = 30 * 86_400;

/// Minimal view of `~/.neoth/.initialized` — only the field we need.
/// `#[serde(default)]` so a marker missing the field (or any extra
/// fields) parses without error.
#[derive(serde::Deserialize)]
struct InitMarker {
    #[serde(default)]
    init_time_unix: u64,
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build the Day-30 check-in banner IFF: (a) it hasn't been shown
/// (marker absent), (b) the install is ≥30 days old per `.initialized`,
/// (c) at least one opt-in feature is still inactive. Returns the banner
/// AND writes the suppress marker (best-effort) when it fires; `None`
/// otherwise (any read/parse failure folds to `None` — the banner is a
/// nicety, never load-bearing).
pub fn maybe_unlock_banner(neoth_dir: &Path, config: &FreedomConfig) -> Option<String> {
    if neoth_dir.join(UNLOCK_MARKER).exists() {
        return None;
    }
    let body = std::fs::read_to_string(neoth_dir.join(".initialized")).ok()?;
    let marker: InitMarker = serde_json::from_str(&body).ok()?;
    if marker.init_time_unix == 0 {
        return None;
    }
    if now_unix_secs().saturating_sub(marker.init_time_unix) < THIRTY_DAYS_SECS {
        return None;
    }
    let inactive = inactive_features(config);
    if inactive.is_empty() {
        return None;
    }
    // Suppress-once (best-effort — a write failure just means the banner
    // may show again next session, which is harmless).
    let _ = std::fs::write(neoth_dir.join(UNLOCK_MARKER), b"");
    Some(render_banner(&inactive))
}

/// The opt-in power features still inactive in `config`, as
/// `(label, enable-hint)` pairs.
fn inactive_features(config: &FreedomConfig) -> Vec<(&'static str, &'static str)> {
    let mut out = Vec::new();
    if !config.profile.learn_enabled {
        out.push((
            "profile learning",
            "profile.learn_enabled: true in freedom.yaml",
        ));
    }
    if !config.dreaming.enabled {
        out.push((
            "dreaming pipeline",
            "dreaming.enabled: true in freedom.yaml",
        ));
    }
    if !config.proactive.enabled {
        out.push((
            "proactive messaging",
            "proactive.enabled: true in freedom.yaml",
        ));
    }
    out
}

fn render_banner(inactive: &[(&str, &str)]) -> String {
    let mut s = String::from(
        "[neoth] Day-30 check-in: you've been running NEOTH for 30+ days.\n\
         Power features you haven't switched on yet:",
    );
    for (label, hint) in inactive {
        s.push_str(&format!("\n  • {label}  →  {hint}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_initialized(dir: &Path, init_time_unix: u64) {
        std::fs::write(
            dir.join(".initialized"),
            format!("{{\"init_time_unix\": {init_time_unix}}}"),
        )
        .unwrap();
    }

    fn cfg_all_inactive() -> FreedomConfig {
        let mut c = FreedomConfig::default();
        c.profile.learn_enabled = false;
        c.dreaming.enabled = false;
        c.proactive.enabled = false;
        c
    }

    #[test]
    fn ux05_silent_before_30_days() {
        let dir = tempdir().unwrap();
        write_initialized(dir.path(), now_unix_secs()); // just initialized
        assert!(maybe_unlock_banner(dir.path(), &cfg_all_inactive()).is_none());
    }

    #[test]
    fn ux05_surfaces_after_30_days_then_suppresses() {
        let dir = tempdir().unwrap();
        write_initialized(dir.path(), now_unix_secs().saturating_sub(31 * 86_400));
        let banner = maybe_unlock_banner(dir.path(), &cfg_all_inactive()).expect("banner");
        assert!(banner.contains("Day-30"));
        assert!(banner.contains("profile learning"));
        assert!(banner.contains("dreaming"));
        assert!(banner.contains("proactive"));
        // Marker written → suppressed on the next call.
        assert!(dir.path().join(UNLOCK_MARKER).exists());
        assert!(maybe_unlock_banner(dir.path(), &cfg_all_inactive()).is_none());
    }

    #[test]
    fn ux05_silent_when_all_features_active() {
        let dir = tempdir().unwrap();
        write_initialized(dir.path(), now_unix_secs().saturating_sub(60 * 86_400));
        let mut c = FreedomConfig::default();
        c.profile.learn_enabled = true;
        c.dreaming.enabled = true;
        c.proactive.enabled = true;
        assert!(maybe_unlock_banner(dir.path(), &c).is_none());
    }

    #[test]
    fn ux05_silent_when_marker_present() {
        let dir = tempdir().unwrap();
        write_initialized(dir.path(), now_unix_secs().saturating_sub(60 * 86_400));
        std::fs::write(dir.path().join(UNLOCK_MARKER), b"").unwrap();
        assert!(maybe_unlock_banner(dir.path(), &cfg_all_inactive()).is_none());
    }

    #[test]
    fn ux05_silent_when_initialized_absent() {
        let dir = tempdir().unwrap();
        // No .initialized file at all → fold to None.
        assert!(maybe_unlock_banner(dir.path(), &cfg_all_inactive()).is_none());
    }
}
