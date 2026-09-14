//! Read-only OpenClaw inspection is implemented by the shared custody crate.
//!
//! The migration binary deliberately re-exports only redacted report types and
//! rendering. It cannot borrow or inspect a raw merged OpenClaw document.

pub use neoth_openclaw_custody::{inspect_openclaw_config, render_human};
