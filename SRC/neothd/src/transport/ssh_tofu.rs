//! TERMIX-04 — SSH host-key TOFU (trust-on-first-use) verifier + store.
//!
//! The first time NEOTH connects to an SSH host it records the server's offered
//! public key. On every later connection the offered key is compared against the
//! stored one: a match proceeds, a *changed* key or algorithm is refused (the
//! classic man-in-the-middle/downgrade signal) and left for the operator to
//! resolve deliberately.
//!
//! The store is a DEDICATED SQLite db (default `~/.neoth/ssh_known_hosts.db`),
//! NOT the shared memory store — so it carries no `SCHEMA_VERSION` coupling and
//! its table self-creates on open. New hosts get exactly one pin. Existing
//! databases may contain multiple legacy `(host, algo)` pins; those exact pins
//! remain valid, but a never-pinned algorithm is never adopted implicitly.
//! Pure rusqlite: this module compiles + unit-tests on the default build with no
//! `russh` dependency; the SSH tunnel ([`super::ssh_tunnel`], feature
//! `ssh-tunnel`) is the consumer that calls [`TofuStore::check_and_update`] from
//! its host-key callback.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use rusqlite::{Connection, TransactionBehavior, params};

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
    /// The host is already pinned, but not for the offered algorithm. The
    /// caller MUST refuse the connection: silently adding an algorithm would
    /// make algorithm negotiation a one-retry TOFU bypass.
    AlgorithmChanged {
        /// Algorithm offered by the current handshake.
        offered_algorithm: String,
        /// Algorithms already pinned for the host, sorted for diagnostics.
        stored_algorithms: Vec<String>,
    },
}

/// Trust-on-first-use store for SSH server host keys.
pub struct TofuStore {
    conn: Connection,
}

const DB_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

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
        conn.busy_timeout(DB_BUSY_TIMEOUT)
            .context("configure SSH TOFU store busy timeout")?;
        conn.execute_batch(SCHEMA)
            .context("create ssh_known_hosts table")?;
        Ok(Self { conn })
    }

    /// In-memory store (tests / ephemeral sessions).
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("open in-memory TOFU store")?;
        conn.busy_timeout(DB_BUSY_TIMEOUT)
            .context("configure in-memory SSH TOFU store busy timeout")?;
        conn.execute_batch(SCHEMA)
            .context("create ssh_known_hosts table")?;
        Ok(Self { conn })
    }

    /// TOFU check for one offered host key. `host` is the canonical
    /// `"hostname:port"`, `algo` the key algorithm (e.g. `"ssh-ed25519"`),
    /// `key_bytes` the raw public-key bytes. See [`TofuOutcome`]. A first sight
    /// stores + `Accepted`; an exact re-sight refreshes `last_seen` + `Matched`;
    /// a divergent key or a never-pinned algorithm is refused WITHOUT adopting
    /// it. The complete decision is serialized in an `IMMEDIATE` transaction,
    /// so concurrent processes cannot both claim first sight.
    pub fn check_and_update(
        &mut self,
        host: &str,
        algo: &str,
        key_bytes: &[u8],
    ) -> Result<TofuOutcome> {
        if host.trim().is_empty() {
            bail!("SSH TOFU host must not be empty");
        }
        if algo.trim().is_empty() {
            bail!("SSH TOFU host-key algorithm must not be empty");
        }
        if key_bytes.is_empty() {
            bail!("SSH TOFU host key must not be empty");
        }

        let offered = base64::engine::general_purpose::STANDARD.encode(key_bytes);
        let now = crate::time::now_unix_i64();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("begin serialized SSH TOFU decision")?;
        let pins = {
            let mut statement = tx
                .prepare(
                    "SELECT algo, key_base64, first_seen, last_seen \
                     FROM ssh_known_hosts WHERE host = ?1 ORDER BY algo",
                )
                .context("prepare SSH TOFU host-pin query")?;
            let rows = statement
                .query_map(params![host], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })
                .context("query SSH TOFU host pins")?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .context("read SSH TOFU host pins")?
        };

        for (stored_algo, stored_key, first_seen, last_seen) in &pins {
            if stored_algo.trim().is_empty() {
                bail!("corrupt SSH TOFU row for {host}: empty host-key algorithm");
            }
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(stored_key)
                .with_context(|| {
                    format!("corrupt SSH TOFU row for {host}/{stored_algo}: invalid base64 key")
                })?;
            if decoded.is_empty()
                || base64::engine::general_purpose::STANDARD.encode(&decoded) != *stored_key
            {
                bail!("corrupt SSH TOFU row for {host}/{stored_algo}: non-canonical host key");
            }
            if *first_seen < 0 || *last_seen < *first_seen {
                bail!("corrupt SSH TOFU row for {host}/{stored_algo}: invalid timestamps");
            }
        }

        let outcome = if let Some((_, existing, first_seen, last_seen)) = pins
            .iter()
            .find(|(stored_algo, _, _, _)| stored_algo == algo)
        {
            if *existing == offered {
                let refreshed_at = now.max(*first_seen).max(*last_seen);
                tx.execute(
                    "UPDATE ssh_known_hosts SET last_seen = ?3 \
                         WHERE host = ?1 AND algo = ?2",
                    params![host, algo, refreshed_at],
                )
                .context("refresh SSH TOFU pin")?;
                TofuOutcome::Matched
            } else {
                TofuOutcome::Changed {
                    stored_key_base64: existing.clone(),
                }
            }
        } else if pins.is_empty() {
            tx.execute(
                "INSERT INTO ssh_known_hosts (host, algo, key_base64, first_seen, last_seen) \
                     VALUES (?1, ?2, ?3, ?4, ?4)",
                params![host, algo, offered, now],
            )
            .context("insert first SSH TOFU pin")?;
            TofuOutcome::Accepted
        } else {
            TofuOutcome::AlgorithmChanged {
                offered_algorithm: algo.to_owned(),
                stored_algorithms: pins
                    .iter()
                    .map(|(stored_algo, _, _, _)| stored_algo.clone())
                    .collect(),
            }
        };

        tx.commit().context("commit SSH TOFU decision")?;
        Ok(outcome)
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
    fn known_host_rejects_never_pinned_algorithm_without_mutation() {
        let mut s = TofuStore::in_memory().unwrap();
        assert_eq!(
            s.check_and_update("h:22", "ssh-ed25519", b"k1").unwrap(),
            TofuOutcome::Accepted
        );
        assert_eq!(
            s.check_and_update("h:22", "ssh-rsa", b"k2").unwrap(),
            TofuOutcome::AlgorithmChanged {
                offered_algorithm: "ssh-rsa".into(),
                stored_algorithms: vec!["ssh-ed25519".into()],
            }
        );
        assert_eq!(s.len().unwrap(), 1);
    }

    #[test]
    fn legacy_multi_algorithm_pins_survive_reopen_but_third_algorithm_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = TofuStore::default_path(dir.path());
        {
            let mut s = TofuStore::open(&path).unwrap();
            s.check_and_update("h:22", "ssh-ed25519", b"ed-key")
                .unwrap();
            let legacy_key = base64::engine::general_purpose::STANDARD.encode(b"ecdsa-key");
            s.conn
                .execute(
                    "INSERT INTO ssh_known_hosts \
                     (host, algo, key_base64, first_seen, last_seen) \
                     VALUES (?1, ?2, ?3, 1, 2)",
                    params!["h:22", "ecdsa-sha2-nistp256", legacy_key],
                )
                .unwrap();
        }

        let mut reopened = TofuStore::open(&path).unwrap();
        assert_eq!(
            reopened
                .check_and_update("h:22", "ssh-ed25519", b"ed-key")
                .unwrap(),
            TofuOutcome::Matched
        );
        assert_eq!(
            reopened
                .check_and_update("h:22", "ecdsa-sha2-nistp256", b"ecdsa-key")
                .unwrap(),
            TofuOutcome::Matched
        );
        assert_eq!(
            reopened
                .check_and_update("h:22", "ssh-dss", b"third-key")
                .unwrap(),
            TofuOutcome::AlgorithmChanged {
                offered_algorithm: "ssh-dss".into(),
                stored_algorithms: vec!["ecdsa-sha2-nistp256".into(), "ssh-ed25519".into(),],
            }
        );
        match reopened
            .check_and_update("h:22", "ssh-ed25519", b"changed-ed-key")
            .unwrap()
        {
            TofuOutcome::Changed { .. } => {}
            other => panic!("expected exact legacy pin change, got {other:?}"),
        }
        assert_eq!(reopened.len().unwrap(), 2);
    }

    #[test]
    fn corrupt_sibling_pin_fails_closed_before_exact_pin_is_used() {
        let mut s = TofuStore::in_memory().unwrap();
        s.check_and_update("h:22", "ssh-ed25519", b"valid-key")
            .unwrap();
        s.conn
            .execute(
                "INSERT INTO ssh_known_hosts \
                 (host, algo, key_base64, first_seen, last_seen) \
                 VALUES (?1, ?2, ?3, 1, 2)",
                params!["h:22", "ecdsa-sha2-nistp256", "not base64!"],
            )
            .unwrap();

        let error = s
            .check_and_update("h:22", "ssh-ed25519", b"valid-key")
            .unwrap_err();
        assert!(
            error.to_string().contains("corrupt SSH TOFU row"),
            "unexpected corruption error: {error:#}"
        );
        assert_eq!(s.len().unwrap(), 2);
    }

    #[test]
    fn concurrent_first_sight_serializes_to_one_host_pin() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let path = TofuStore::default_path(dir.path());
        drop(TofuStore::open(&path).unwrap());
        let barrier = Arc::new(Barrier::new(3));
        let workers = [
            ("ssh-ed25519", b"ed-key".as_slice()),
            ("ecdsa-sha2-nistp256", b"ecdsa-key".as_slice()),
        ]
        .into_iter()
        .map(|(algo, key)| {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let mut store = TofuStore::open(&path).unwrap();
                barrier.wait();
                store.check_and_update("race:22", algo, key).unwrap()
            })
        })
        .collect::<Vec<_>>();
        barrier.wait();
        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, TofuOutcome::Accepted))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, TofuOutcome::AlgorithmChanged { .. }))
                .count(),
            1
        );
        assert_eq!(TofuStore::open(&path).unwrap().len().unwrap(), 1);
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
