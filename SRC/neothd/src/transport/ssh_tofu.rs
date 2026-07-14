//! TERMIX-04 — SSH host-key TOFU (trust-on-first-use) verifier + store.
//!
//! The first time NEOTH connects to an SSH host it records the server's offered
//! public key. On every later connection the offered key is compared against the
//! stored one: a match proceeds, a *changed* key is refused (the classic
//! man-in-the-middle signal) and left for the operator to resolve deliberately.
//!
//! The store is a DEDICATED SQLite db (default `~/.neoth/ssh_known_hosts.db`),
//! NOT the shared memory store — so it carries no `SCHEMA_VERSION` coupling and
//! its table self-creates on open. One row per `(host, algo)`. Pure rusqlite:
//! this module compiles + unit-tests on the default build with no `russh`
//! dependency; the SSH tunnel ([`super::ssh_tunnel`], feature `ssh-tunnel`) is
//! the consumer that calls [`TofuStore::check_and_update`] from its host-key
//! callback.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine;
use rusqlite::{Connection, OptionalExtension, params};

/// Outcome of checking a server's offered host key against the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TofuOutcome {
    /// Host never seen before — the key was stored; the caller should proceed.
    Accepted,
    /// Host known and the offered key MATCHES the stored one — `last_seen`
    /// refreshed; proceed.
    Matched,
    /// Host known but the offered key DIFFERS. The caller MUST refuse the
    /// connection (possible MITM); the store is left UNCHANGED so an operator
    /// can inspect / rotate the trusted key deliberately.
    Changed {
        /// The base64 of the key currently trusted for this `(host, algo)`.
        stored_key_base64: String,
    },
}

/// Trust-on-first-use store for SSH server host keys, one row per `(host, algo)`.
pub struct TofuStore {
    conn: Connection,
}

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS ssh_known_hosts (
        host        TEXT NOT NULL,
        algo        TEXT NOT NULL,
        key_base64  TEXT NOT NULL,
        first_seen  INTEGER NOT NULL,
        last_seen   INTEGER NOT NULL,
        PRIMARY KEY (host, algo)
    );";

impl TofuStore {
    /// Default on-disk path: `<home>/.neoth/ssh_known_hosts.db`.
    pub fn default_path(home: &Path) -> PathBuf {
        home.join(".neoth").join("ssh_known_hosts.db")
    }

    /// Open (creating if needed) the TOFU store at `path` and ensure the schema.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create TOFU store dir {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("open SSH TOFU store {}", path.display()))?;
        conn.execute_batch(SCHEMA)
            .context("create ssh_known_hosts table")?;
        Ok(Self { conn })
    }

    /// In-memory store (tests / ephemeral sessions).
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("open in-memory TOFU store")?;
        conn.execute_batch(SCHEMA)
            .context("create ssh_known_hosts table")?;
        Ok(Self { conn })
    }

    /// TOFU check for one offered host key. `host` is the canonical
    /// `"hostname:port"`, `algo` the key algorithm (e.g. `"ssh-ed25519"`),
    /// `key_bytes` the raw public-key bytes. See [`TofuOutcome`]. A first sight
    /// stores + `Accepted`; an exact re-sight refreshes `last_seen` + `Matched`;
    /// a divergent key returns `Changed` WITHOUT mutating the store.
    pub fn check_and_update(
        &mut self,
        host: &str,
        algo: &str,
        key_bytes: &[u8],
    ) -> Result<TofuOutcome> {
        let offered = base64::engine::general_purpose::STANDARD.encode(key_bytes);
        let now = crate::time::now_unix_i64();
        let stored: Option<String> = self
            .conn
            .query_row(
                "SELECT key_base64 FROM ssh_known_hosts WHERE host = ?1 AND algo = ?2",
                params![host, algo],
                |r| r.get(0),
            )
            .optional()
            .context("query ssh_known_hosts")?;
        match stored {
            None => {
                self.conn.execute(
                    "INSERT INTO ssh_known_hosts (host, algo, key_base64, first_seen, last_seen) \
                     VALUES (?1, ?2, ?3, ?4, ?4)",
                    params![host, algo, offered, now],
                )?;
                Ok(TofuOutcome::Accepted)
            }
            Some(existing) if existing == offered => {
                self.conn.execute(
                    "UPDATE ssh_known_hosts SET last_seen = ?3 WHERE host = ?1 AND algo = ?2",
                    params![host, algo, now],
                )?;
                Ok(TofuOutcome::Matched)
            }
            Some(existing) => Ok(TofuOutcome::Changed {
                stored_key_base64: existing,
            }),
        }
    }

    /// Number of trusted host keys (diagnostics).
    pub fn len(&self) -> Result<usize> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM ssh_known_hosts", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    /// Whether the store holds no trusted keys yet.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_then_match() {
        let mut s = TofuStore::in_memory().unwrap();
        let key = b"ed25519-pubkey-bytes";
        assert_eq!(
            s.check_and_update("host.example:22", "ssh-ed25519", key)
                .unwrap(),
            TofuOutcome::Accepted
        );
        // Re-sight of the SAME key matches.
        assert_eq!(
            s.check_and_update("host.example:22", "ssh-ed25519", key)
                .unwrap(),
            TofuOutcome::Matched
        );
        assert_eq!(s.len().unwrap(), 1);
    }

    #[test]
    fn changed_key_is_refused_and_store_unchanged() {
        let mut s = TofuStore::in_memory().unwrap();
        s.check_and_update("h:22", "ssh-ed25519", b"original")
            .unwrap();
        match s
            .check_and_update("h:22", "ssh-ed25519", b"DIFFERENT")
            .unwrap()
        {
            TofuOutcome::Changed { stored_key_base64 } => {
                let want = base64::engine::general_purpose::STANDARD.encode(b"original");
                assert_eq!(
                    stored_key_base64, want,
                    "must report the trusted key, not the new one"
                );
            }
            other => panic!("expected Changed, got {other:?}"),
        }
        // The store must NOT have adopted the changed key — a later sight of the
        // ORIGINAL still matches.
        assert_eq!(
            s.check_and_update("h:22", "ssh-ed25519", b"original")
                .unwrap(),
            TofuOutcome::Matched
        );
    }

    #[test]
    fn same_host_different_algo_is_independent() {
        let mut s = TofuStore::in_memory().unwrap();
        assert_eq!(
            s.check_and_update("h:22", "ssh-ed25519", b"k1").unwrap(),
            TofuOutcome::Accepted
        );
        // A different algorithm on the same host is a separate first-sight.
        assert_eq!(
            s.check_and_update("h:22", "ssh-rsa", b"k2").unwrap(),
            TofuOutcome::Accepted
        );
        assert_eq!(s.len().unwrap(), 2);
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = TofuStore::default_path(dir.path());
        {
            let mut s = TofuStore::open(&path).unwrap();
            s.check_and_update("h:22", "ssh-ed25519", b"k").unwrap();
        }
        // Reopen: the trusted key survives, so the same key matches.
        let mut s = TofuStore::open(&path).unwrap();
        assert_eq!(
            s.check_and_update("h:22", "ssh-ed25519", b"k").unwrap(),
            TofuOutcome::Matched
        );
    }
}
