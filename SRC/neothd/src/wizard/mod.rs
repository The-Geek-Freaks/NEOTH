//! Wizard primitives — pure-fn engines the GUI + CLI wizard
//! surfaces consult before asking the operator anything.
//!
//! Modules:
//!   - [`recommend`] — W-03 RecommendationEngine.

pub mod detect_step;
pub mod install_step;
pub mod ipc;
pub mod recommend;
pub mod shared_state;
