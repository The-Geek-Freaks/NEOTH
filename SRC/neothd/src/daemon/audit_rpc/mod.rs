//! AUDIT-RPC-01 — loopback audit-RPC listener + client.
//!
//! ## Why this exists
//! The daemon owns the SINGLE WAL writer (the single-writer invariant). So when
//! `neoth serve` is running, a one-shot CLI (`neoth os launch`, `fs read/write`,
//! `autonomy set`, `lease …`) cannot open a second writer to record its own
//! gated action — it passes `writer: None` and the action runs gated but
//! UN-audited. This module closes that gap: the one-shot CLI forwards an *audit
//! intent* to the running daemon over a loopback socket, and the daemon (which
//! owns the writer) appends the frame on its behalf.
//!
//! ## Security model — anti-audit-poisoning
//! The audit chain is NEOTH's verifiable-loyalty wedge, so a forged frame is a
//! real threat. Defenses, all fail-closed:
//!   1. **Loopback-only.** The listener binds `127.0.0.1:0`; every connection's
//!      peer is re-checked `is_loopback()` at accept time (403 otherwise).
//!   2. **Per-boot bearer token.** 32 bytes from the OS CSPRNG, base64url, freshly
//!      minted on every daemon start (a token captured before a restart is dead
//!      after it), written `0600` on unix / DPAPI-wrapped+DACL on Windows via the
//!      same `write_key_securely` path as the WAL HMAC key. Only a SAME-UID
//!      process can read it. Checked constant-time; 5-strike cooldown on failure.
//!   3. **Compile-time event-type allowlist.** Only the one-shot-emittable
//!      permission-band codes are acceptable over IPC; anything else
//!      (daemon-lifecycle, cluster, quota, …) is refused 422. The allowlist is a
//!      `const` — not operator-tunable, since an operator who could widen it
//!      could already forge frames directly.
//!   4. **Body cap** 4096 bytes (audit payloads are small structured JSON).
//!
//! ## Residual (documented, accepted)
//! A process running as the SAME OS user can read the token file and submit
//! frames — but a same-uid process is already inside NEOTH's trust boundary (it
//! could read the WAL HMAC key, or simply BE `neoth`). The token closes the
//! cross-uid forgery vector, which is the real boundary. Same precedent as the
//! WAL HMAC key (`wal/compaction.rs`).
//!
//! Gated behind `freedom.yaml::audit_rpc.enabled` (default OFF). The listener is
//! spawned from `cli/serve.rs` and aborted on shutdown; the sidecar is removed
//! by [`SidecarGuard`] on drop.
//!
//! ## Module layout (the file was split once it crossed ~800 LOC)
//!   - [`token`]   — the per-boot bearer secret (mint / read / path).
//!   - [`sidecar`] — port advertisement + the stale-sidecar guard + `SidecarGuard`.
//!   - [`server`]  — the daemon listener: bind, accept, auth, allowlist, append.
//!   - [`client`]  — the one-shot CLI side: reachability, required-audit gate,
//!                   `try_post_audit_frame`.
//!
//! Every public item keeps its previous `crate::daemon::audit_rpc::<name>` path
//! via the re-exports below, so the split is internal-only.

mod client;
mod server;
mod sidecar;
mod token;

#[cfg(test)]
mod tests;

pub use client::{AuditRpcClientError, enforce_required_audit, is_reachable, try_post_audit_frame};
pub use server::{
    ALLOWED_CLIENT_EVENT_TYPES, AuditRpcState, bind_and_serve, is_allowed_client_event,
};
pub use sidecar::{SidecarGuard, read_sidecar, remove_sidecar, sidecar_path, write_sidecar};
pub use token::{init_rpc_token, read_rpc_token, rpc_token_path};
