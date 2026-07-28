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
//! The approval-token endpoints use that same operator-authority boundary. A
//! jobs-run token is bound to one canonical request digest, expires quickly,
//! and is consumed once. Its CLI mint path re-reads the live autonomy policy
//! and cannot override a static `Deny`; the daemon also appends a mandatory WAL
//! proof before it releases the token. This is deliberately not an OS sandbox
//! against the operator who owns both `freedom.yaml` and the RPC credential.
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
mod fullauto_token;
mod server;
mod sidecar;
mod token;

#[cfg(test)]
mod tests;

pub(crate) use client::try_post_skill_mutation_frame;
pub use client::{
    AuditRpcClientError, consume_fullauto_token, consume_jobs_run_token, enforce_required_audit,
    is_reachable, mint_fullauto_token, mint_jobs_run_token, try_post_audit_frame,
    try_post_audit_frame_with_subtype,
};
#[cfg(feature = "cluster")]
pub use client::{
    membership_confirm, membership_invite, membership_legacy_pending, membership_revocation_status,
    membership_revoke, membership_runtime_health, membership_snapshot,
};
pub use fullauto_token::{FULLAUTO_TOKEN_TTL, FullAutoTokenStore, JOBS_RUN_TOKEN_TTL};
pub use server::{
    ALLOWED_CLIENT_EVENT_TYPES, ALLOWED_CLIENT_EXTENDED_SUBTYPES, AuditRpcState, bind_and_serve,
    is_allowed_client_event, is_allowed_client_event_pair,
};
pub use sidecar::{SidecarGuard, read_sidecar, remove_sidecar, sidecar_path, write_sidecar};
pub use token::{init_rpc_token, read_rpc_token, rpc_token_path};
