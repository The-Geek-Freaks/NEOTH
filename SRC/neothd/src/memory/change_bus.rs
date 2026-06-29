//! GOLD-ADAPT-TRAIL-02 — views.db change-bus (push not GUI-poll).
//!
//! Thin wrapper around `tokio::sync::watch` that signals "views.db was
//! mutated" so in-process consumers (kanban_sse relay task) can push
//! updates without polling.
//!
//! `gui_stream` (child process) cannot share an in-process channel with
//! the daemon; it uses file-mtime polling on views.db separately (see
//! `cli/gui_stream.rs`).
//!
//! Semantics:
//! - `watch::Sender` coalesces: if the indexer replays 50 frames in one
//!   pass, `change_rx.changed()` fires exactly once. The relay wakes once
//!   and reads the latest state — correct for "push current board" use.
//! - `Sender::send` when there are no receivers is silently discarded
//!   (`let _ =`). No panic, no error propagation.

/// Create a `(Sender, Receiver)` pair for the views.db change signal.
///
/// Call once at daemon boot in `cli/serve.rs`; pass the `Sender` to
/// `spawn_indexer` and the `Receiver` to the kanban-SSE relay task.
pub fn channel() -> (
    tokio::sync::watch::Sender<()>,
    tokio::sync::watch::Receiver<()>,
) {
    tokio::sync::watch::channel(())
}
