//! Exercise the production desktop coding controller without linking Slint.
//! Sharing the actual module keeps cancellation and reservation regressions
//! coupled to the controller used by Settings and Buddy.
//! Keep its public desktop API reachable from this integration crate; the
//! desktop's callers live in the separately checked Slint application.

#[path = "../../neothd-gui/src/coding_controller.rs"]
pub mod coding_controller;
