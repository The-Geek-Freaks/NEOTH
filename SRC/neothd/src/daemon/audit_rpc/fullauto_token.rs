//! GR-RESID-D34 — daemon-minted single-use, short-TTL token gating the
//! FULL-AUTO `--gui-confirmed` bypass.
//!
//! ## Why
//!
//! `confirm_full_auto` fails closed on a non-TTY stdin so the bare CLI can't
//! enable FULL-AUTO unattended (GR-101). The GUI passes a hidden
//! `--gui-confirmed` flag to skip the TTY check — but flag PRESENCE alone was
//! the whole bypass, so a script could bake `neoth autonomy full-auto
//! --gui-confirmed` into a cron and silently flip the most permissive mode.
//!
//! This closes that: the bypass now also requires a token the DAEMON minted in
//! response to a live request (the GUI's confirm dialog). The token is
//! single-use AND short-TTL, so it can NOT be pre-baked into a script/cron — by
//! the time a stale token reaches the CLI it has expired or been consumed. A
//! same-uid attacker who reads the audit-RPC bearer could still mint+consume in
//! a tight live sequence (fundamentally unpreventable on a single-user box —
//! they could also just edit freedom.yaml), but the persistent/unattended
//! vector GR-101 actually targets is closed.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;

/// How long a minted token stays valid. Short on purpose — the GUI mints it
/// then immediately spawns the `neoth autonomy full-auto --gui-token <t>` call,
/// so a couple of minutes is generous while keeping the pre-bake window tiny.
pub const FULLAUTO_TOKEN_TTL: Duration = Duration::from_secs(120);

#[derive(Debug)]
struct StoredToken {
    token: String,
    expires: Instant,
}

/// At-most-one outstanding FULL-AUTO token. A fresh `mint` replaces any prior
/// (un-consumed) token, so a token is never reusable and never accumulates.
#[derive(Debug, Default)]
pub struct FullAutoTokenStore {
    inner: Mutex<Option<StoredToken>>,
}

impl FullAutoTokenStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    /// Mint a fresh single-use token valid for `ttl`. 32 bytes from the OS
    /// CSPRNG → base64url-nopad. Returns `None` (fail-closed) if the RNG is
    /// unavailable — a predictable token would defeat the gate. Replaces any
    /// previously-minted-but-unconsumed token.
    pub fn mint(&self, ttl: Duration) -> Option<String> {
        let mut raw = [0u8; 32];
        if getrandom::getrandom(&mut raw).is_err() {
            tracing::error!("OS RNG unavailable — refusing to mint a weak FULL-AUTO token");
            return None;
        }
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        *guard = Some(StoredToken {
            token: token.clone(),
            expires: Instant::now() + ttl,
        });
        Some(token)
    }

    /// Validate + CONSUME a candidate token against `now`. Returns `true` only
    /// when a stored token matches (constant-time) AND has not expired; the
    /// match is removed so a second consume of the same token fails (single-use).
    /// A mismatch leaves the stored token intact (a wrong guess must not burn a
    /// legitimate pending token).
    pub fn consume(&self, candidate: &str, now: Instant) -> bool {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let Some(stored) = guard.as_ref() else {
            return false;
        };
        if now >= stored.expires {
            // Expired → clear it (no point keeping a dead token) + reject.
            *guard = None;
            return false;
        }
        if crate::n8n_api::constant_time_token_eq(candidate, &stored.token) {
            *guard = None; // single-use
            true
        } else {
            false // wrong guess — keep the legitimate pending token
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_then_consume_succeeds_once_only() {
        let store = FullAutoTokenStore::new();
        let tok = store.mint(FULLAUTO_TOKEN_TTL).expect("mint");
        assert!(tok.len() >= 43, "base64url-nopad of 32 bytes is 43 chars");
        // First consume succeeds.
        assert!(store.consume(&tok, Instant::now()));
        // Second consume of the SAME token fails (single-use).
        assert!(!store.consume(&tok, Instant::now()));
    }

    #[test]
    fn wrong_token_rejected_and_does_not_burn_the_pending_one() {
        let store = FullAutoTokenStore::new();
        let tok = store.mint(FULLAUTO_TOKEN_TTL).expect("mint");
        assert!(!store.consume("not-the-token", Instant::now()));
        // The legitimate token still works after a wrong guess.
        assert!(store.consume(&tok, Instant::now()));
    }

    #[test]
    fn expired_token_rejected() {
        let store = FullAutoTokenStore::new();
        let tok = store.mint(Duration::from_millis(0)).expect("mint");
        // `now` strictly after the (now+0) deadline → expired.
        std::thread::sleep(Duration::from_millis(2));
        assert!(!store.consume(&tok, Instant::now()));
    }

    #[test]
    fn consume_on_empty_store_is_false() {
        let store = FullAutoTokenStore::new();
        assert!(!store.consume("anything", Instant::now()));
    }

    #[test]
    fn mint_replaces_prior_token() {
        let store = FullAutoTokenStore::new();
        let old = store.mint(FULLAUTO_TOKEN_TTL).expect("mint old");
        let new = store.mint(FULLAUTO_TOKEN_TTL).expect("mint new");
        assert_ne!(old, new);
        // The OLD token is dead after a re-mint.
        assert!(!store.consume(&old, Instant::now()));
        assert!(store.consume(&new, Instant::now()));
    }
}
