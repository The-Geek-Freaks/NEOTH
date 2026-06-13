//! GOLD-FEAT-01b — the zero-friction onboarding preset.
//!
//! Collapses the DAU-hostile onboarding choices into one maximally-permissive,
//! all-in default set: **Full autonomy**, **every bundled skill active** (no
//! eval-suppression), **single-provider inference** (one provider drives all
//! three hemispheres — no per-hemisphere setup). [`apply_zero_friction`] is a
//! pure config transform the wizard's zero-friction path applies before writing
//! `freedom.yaml`; it never touches secrets (those live in `credentials.yaml`).

use crate::config::inference::TopologyMode;
use crate::config::FreedomConfig;
use crate::permissions::AutonomyLevel;

/// Return a copy of `cfg` with the zero-friction preset applied: Full autonomy,
/// skills fully active, single-provider inference.
pub fn apply_zero_friction(mut cfg: FreedomConfig) -> FreedomConfig {
    cfg.autonomy = AutonomyLevel::Full;
    // Every bundled skill stays injected — eval-suppression OFF.
    cfg.skills.disabled_for_eval_sessions = false;
    cfg.skills.eval_session_active = false;
    // One provider drives all three hemispheres — no per-hemisphere wiring.
    cfg.inference.mode = TopologyMode::Single;
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_friction_preset_sets_full_autonomy_and_enables_all_skills() {
        // Start from a deliberately NON-zero-friction base: strict autonomy +
        // eval-suppressed skills + (whatever default inference mode).
        let mut base = FreedomConfig::default();
        base.autonomy = AutonomyLevel::Strict;
        base.skills.disabled_for_eval_sessions = true;
        base.skills.eval_session_active = true;

        let z = apply_zero_friction(base);

        assert_eq!(z.autonomy, AutonomyLevel::Full, "Full autonomy");
        assert!(!z.skills.disabled_for_eval_sessions, "skills not eval-suppressed");
        assert!(!z.skills.eval_session_active, "no active eval session");
        assert!(matches!(z.inference.mode, TopologyMode::Single), "single-provider");
    }

    #[test]
    fn preset_is_idempotent() {
        let once = apply_zero_friction(FreedomConfig::default());
        let twice = apply_zero_friction(once.clone());
        assert_eq!(once.autonomy, twice.autonomy);
        assert_eq!(
            once.skills.disabled_for_eval_sessions,
            twice.skills.disabled_for_eval_sessions
        );
        assert!(matches!(twice.inference.mode, TopologyMode::Single));
    }
}
