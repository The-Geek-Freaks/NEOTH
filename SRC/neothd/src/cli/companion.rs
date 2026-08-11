//! GOLD-COMPANION-P2P-01 — `neoth companion pair-phone`.
//!
//! Mints a one-time [`CompanionInvite`] (a fresh rendezvous topic + PSK) and:
//!   1. Renders a `neoth://companion/pair` URL as a terminal QR code.
//!   2. Spawns the v2 HyperDHT rendezvous / authenticated Noise-IK listener
//!      (when the `cluster` feature is active). The topic + PSK HKDF-derive
//!      the only admitted client static key before connection allocation; the
//!      encrypted application PSK remains a defense-in-depth confirmation.
//!   3. Waits up to `PAIR_INVITE_TTL_SECS` seconds for a pairing to complete,
//!      then exits whether or not a phone connected.
//!
//! When `cluster` is NOT compiled in, the command still prints the QR/URL but
//! informs the operator that P2P is unavailable and suggests the loopback HTTP
//! path instead.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::daemon::companion::{
    CompanionInvite, CompanionState, ensure_private_companion_home, render_pairing_qr,
    spawn_companion_p2p_listener,
};

/// Invite TTL advertised in the pairing URL, in seconds. 300s (5 min) is long
/// enough to pick up the phone and scan, short enough that a leaked QR/URL
/// expires quickly. It is part of the server-side v2 QR/URL preview contract;
/// no NEOTH phone client is shipped yet.
const PAIR_INVITE_TTL_SECS: u64 = 300;

/// Extra grace period beyond the TTL before we cancel the listener task.
const PAIR_INVITE_GRACE_SECS: u64 = 10;

#[derive(Args, Debug, Clone)]
pub struct CompanionArgs {
    #[command(subcommand)]
    pub command: CompanionCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CompanionCommand {
    /// Preview a one-time v2 pairing QR/URL; NEOTH ships no phone client yet.
    /// The server-side HyperDHT / authenticated Noise-IK transport accepts only
    /// the topic-and-PSK-HKDF-derived client static key before allocation, then
    /// verifies the encrypted application PSK as defense in depth. The invite
    /// is single-use, short-lived, and requires the `cluster` feature.
    PairPhone {
        /// Hand the invite to a RUNNING `neoth serve` daemon instead of driving
        /// the pairing in this short-lived CLI process. Writes the invite
        /// atomically to `~/.neoth/companion_pending_invite.json`, which the
        /// daemon's serve-side P2P coordinator (`companion.p2p_enabled: true`)
        /// polls every ~2s, consumes single-use, and completes the handshake —
        /// minting the token into the daemon-lifetime in-memory store so it is
        /// also valid on the loopback HTTP path while that daemon runs. Neither
        /// the token nor the pairing persists or recovers across a daemon
        /// restart. Create a new invite and pair again. Without this flag the
        /// CLI drives a transient in-process
        /// listener whose token dies when the command exits.
        #[arg(long)]
        write_invite_for_serve: bool,
    },
}

pub async fn run_companion(args: CompanionArgs, output: OutputFormat) -> Result<()> {
    match args.command {
        CompanionCommand::PairPhone {
            write_invite_for_serve,
        } => run_pair_phone(write_invite_for_serve, output).await,
    }
}

async fn run_pair_phone(write_invite_for_serve: bool, output: OutputFormat) -> Result<()> {
    if matches!(output, OutputFormat::Json | OutputFormat::Jsonl) && !write_invite_for_serve {
        anyhow::bail!(
            "structured companion pairing requires `--write-invite-for-serve`; \
             the standalone listener is an interactive terminal flow"
        );
    }
    // Validate the daemon-backed contract before minting or displaying a
    // secret invite. Otherwise the default `p2p_enabled: false` configuration
    // leaves a live-looking QR and an invite file that no process consumes.
    let serve_handoff = if write_invite_for_serve {
        let home = crate::config::FreedomConfig::default_neoth_home();
        let cfg = crate::config::FreedomConfig::load_from_path(&home.join("freedom.yaml"))
            .context("load companion configuration; run `neoth init` first")?;
        validate_serve_handoff_config(&cfg)?;
        ensure_private_companion_home(&home)
            .context("verify private NEOTH_HOME before writing companion invite")?;
        let pid = crate::daemon::pidfile::live_daemon_pid(&home.join("neothd.pid"))
            .context("check whether `neoth serve` is running")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no running `neoth serve` daemon found; start it before using \
                     `--write-invite-for-serve`"
                )
            })?;
        Some((home, pid))
    } else {
        None
    };

    let invite = CompanionInvite::generate()?;
    let url = invite.pairing_url(PAIR_INVITE_TTL_SECS);

    if matches!(output, OutputFormat::Table) {
        // QR first when stdout is a TTY; render_pairing_qr returns "" on failure /
        // non-TTY, so the URL fallback below is always printed regardless.
        let qr = render_pairing_qr(&url);
        if !qr.is_empty() {
            println!("{qr}");
        }

        println!("Server-side pairing preview (no NEOTH phone client is shipped yet):");
        println!("Use this QR/URL with a compatible v2 client:");
        println!();
        println!("  {url}");
        println!();
        println!("This invite is single-use and expires in {PAIR_INVITE_TTL_SECS}s.");
        println!();
    }

    // `--write-invite-for-serve`: hand the invite to a RUNNING daemon rather
    // than driving the pairing here. Write it to the well-known path the
    // serve-side P2P coordinator polls, then exit — the daemon owns the listener
    // and mints the token into its daemon-lifetime in-memory store (so it is
    // valid on the loopback HTTP path while the daemon runs). Neither the token
    // nor the pairing survives or recovers across a daemon restart. This is the
    // daemon-backed flow; the transient in-process path below only fits a
    // no-daemon one-shot.
    if let Some((home, daemon_pid)) = serve_handoff {
        let invite_path = home.join("companion_pending_invite.json");
        let _lock = crate::util::locked_file::lock_file_blocking(
            &home.join("companion_pending_invite.lock"),
            "companion pending invite",
        )?;
        let expires_at = crate::time::now_unix_secs()
            .checked_add(PAIR_INVITE_TTL_SECS)
            .ok_or_else(|| anyhow::anyhow!("companion invite expiry overflow"))?;
        let record = invite.pending_invite_record(expires_at)?;
        match crate::util::atomic_write::write_private_create_new_durable(&invite_path, &record) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => anyhow::bail!(
                "a companion invite is already pending at {}; wait for daemon pid {} \
                 to consume it or remove it after confirming that pairing has expired",
                invite_path.display(),
                daemon_pid
            ),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "create pending companion invite {} (is `neoth serve` initialised?)",
                        invite_path.display()
                    )
                });
            }
        }
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "action": "pair_phone",
                    "pair_url": url,
                    "expires_in_secs": PAIR_INVITE_TTL_SECS,
                    "handed_to_daemon": true,
                })
            ),
            OutputFormat::Table => println!(
                "Invite handed to daemon pid {} at {}.\n\
                 The serve-side coordinator (companion.p2p_enabled: true) picks it up \
                 within ~2s and completes the pairing into the daemon-lifetime in-memory \
                 token store. A daemon restart requires a fresh invite and pairing.",
                daemon_pid,
                invite_path.display()
            ),
        }
        return Ok(());
    }

    // Spawn a transient CompanionState (token store) and a transient WAL writer
    // for this standalone CLI invocation. The CLI runs outside of `neoth serve`,
    // so it cannot share the daemon's live in-memory state — it mints its own
    // in-process token store that lives for the duration of this command.
    //
    // WAL: use an isolated temporary instance home. Its key/recovery namespace
    // must never bind to the real operator home merely because this command is
    // running in the same process.
    let wal_home = tempfile::tempdir().map_err(|e| anyhow::anyhow!("tempdir: {e}"))?;
    let wal_dir = wal_home.path().join("wal");
    std::fs::create_dir_all(&wal_dir)
        .with_context(|| format!("create temporary companion WAL {}", wal_dir.display()))?;
    let seg = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "companion-pair");
    let (writer, wal_join) = crate::wal::writer::spawn_for_home(seg, wal_home.path().to_path_buf())
        .map_err(|e| anyhow::anyhow!("spawn WAL writer: {e}"))?;

    // The transient state shares port 0 (unused in P2P path — port is only
    // relevant for the HTTP companion server's CSRF check).
    let state = Arc::new(CompanionState::new(writer.clone(), 0));

    // Spawn the P2P listener. Under `cluster` this drives the full Noise accept
    // loop; under non-cluster it exits immediately with a warning.
    let mut task =
        spawn_companion_p2p_listener(invite, Arc::clone(&state), writer, PAIR_INVITE_TTL_SECS);

    println!("Waiting for companion app to connect (up to {PAIR_INVITE_TTL_SECS}s)...");
    println!("(Press Ctrl-C to abort early)");
    println!();

    // Wait for the listener to finish (paired / TTL expiry / transport close) OR for
    // the grace timeout. We do NOT simply `.await` the task in case the
    // listener stalls beyond the TTL due to a slow network teardown.
    let grace = tokio::time::Duration::from_secs(PAIR_INVITE_TTL_SECS + PAIR_INVITE_GRACE_SECS);
    let listener_finished = tokio::select! {
        res = task.await_terminal() => {
            match res {
                Ok(()) => println!("Pairing complete (check daemon logs for details)."),
                Err(e) => println!("Pairing listener exited with error: {e}"),
            }
            true
        }
        _ = tokio::time::sleep(grace) => {
            task.request_stop();
            println!("Invite expired — no companion connected within {PAIR_INVITE_TTL_SECS}s.");
            false
        }
        _ = tokio::signal::ctrl_c() => {
            task.request_stop();
            println!("Aborted by operator (Ctrl-C).");
            false
        }
    };
    if !listener_finished {
        let shutdown_grace = tokio::time::Duration::from_secs(PAIR_INVITE_GRACE_SECS);
        if task.observe_grace(shutdown_grace).await.is_none() {
            // A timeout observes only the grace budget; it never transfers or
            // drops ownership. Retain and await the same listener so its WAL
            // audit acknowledgement and in-memory token publication reach a
            // terminal state before the temporary writer/home are released.
            let _ = task.await_terminal().await;
        }
    }

    // Release the final CompanionState writer clone, then drain the WAL task
    // before the temporary instance home is deleted.
    drop(state);
    wal_join
        .await
        .context("temporary companion WAL writer task panicked")?;
    Ok(())
}

fn validate_serve_handoff_config(cfg: &crate::config::FreedomConfig) -> Result<()> {
    if !cfg.companion.enabled {
        anyhow::bail!(
            "daemon-backed companion pairing requires `companion.enabled: true`; \
             enable it and restart `neoth serve`"
        );
    }
    if !cfg.companion.p2p_enabled {
        anyhow::bail!(
            "daemon-backed companion pairing requires `companion.p2p_enabled: true`; \
             enable it and restart `neoth serve`"
        );
    }
    #[cfg(not(feature = "cluster"))]
    anyhow::bail!("daemon-backed companion pairing requires a build with the `cluster` feature");
    #[cfg(feature = "cluster")]
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serve_handoff_rejects_default_disabled_config() {
        let err = validate_serve_handoff_config(&crate::config::FreedomConfig::default())
            .expect_err("default companion config must fail closed");
        assert!(err.to_string().contains("companion.enabled"));
    }

    #[test]
    fn serve_handoff_rejects_disabled_p2p_before_creating_invite() {
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.companion.enabled = true;
        let err = validate_serve_handoff_config(&cfg).expect_err("P2P must be enabled");
        assert!(err.to_string().contains("companion.p2p_enabled"));
    }

    #[test]
    fn standalone_pair_segments_are_unique_canonical_children_of_the_isolated_home() {
        let home = tempfile::tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        let first = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "companion-pair");
        let second = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "companion-pair");

        assert_eq!(first.parent(), Some(wal_dir.as_path()));
        assert_eq!(second.parent(), Some(wal_dir.as_path()));
        assert_ne!(first, second);
        assert!(crate::wal::scan::canonical_segment_name(
            first.file_name().unwrap()
        ));
        assert_ne!(
            wal_dir,
            crate::config::FreedomConfig::default_wal_dir(),
            "temporary pairing must not bind WAL state to the real operator home"
        );
    }

    #[test]
    fn pending_invite_create_new_never_overwrites_an_existing_capability() {
        let home = tempfile::tempdir().unwrap();
        ensure_private_companion_home(home.path()).unwrap();
        let path = home.path().join("companion_pending_invite.json");
        let invite = CompanionInvite::generate().unwrap();
        let record = invite.pending_invite_record(1_700_000_300).unwrap();

        crate::util::atomic_write::write_private_create_new_durable(&path, &record).unwrap();
        let original = std::fs::read(&path).unwrap();
        let replacement = CompanionInvite::generate()
            .unwrap()
            .pending_invite_record(1_700_000_301)
            .unwrap();
        let error =
            crate::util::atomic_write::write_private_create_new_durable(&path, &replacement)
                .expect_err("a second producer must not replace a pending invite");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), original);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn serve_handoff_accepts_fully_enabled_cluster_config() {
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.companion.enabled = true;
        cfg.companion.p2p_enabled = true;
        validate_serve_handoff_config(&cfg).unwrap();
    }
}
