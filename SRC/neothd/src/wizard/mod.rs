//! Wizard primitives — pure-fn engines the GUI + CLI wizard
//! surfaces consult before asking the operator anything.
//!
//! Modules:
//!   - [`recommend`] — W-03 RecommendationEngine.

pub mod detect_step;
pub mod env_probe;
pub mod install_step;
pub mod ipc;
pub mod recommend;
pub mod shared_state;
/// GOLD-FEAT-01b — zero-friction onboarding preset (Full autonomy + all skills
/// + single-provider). `apply_zero_friction` is a pure config transform.
pub mod zero_friction;
