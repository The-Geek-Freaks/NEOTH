//! GOLD-COMPANION-P2P-01 — `neoth companion pair-phone`.
//!
//! Mints a one-time [`CompanionInvite`] (a fresh rendezvous topic + PSK) and:
//!   1. Renders a `neoth://companion/pair` URL as a terminal QR code.
//!   2. Spawns a Hyperswarm/Noise-XX P2P listener (when the `cluster` feature
//!      is active) that announces the topic on the DHT, waits for the phone to
//!      connect, verifies the PSK, and writes a JSON bearer token over the
//!      encrypted channel.
//!   3. Waits up to `PAIR_INVITE_TTL_SECS` seconds for a pairing to complete,
//!      then exits whether or not a phone connected.
//!
//! When `cluster` is NOT compiled in, the command still prints the QR/URL but
//! informs the operator that P2P is unavailable and suggests the loopback HTTP
//! path instead.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use tokio::sync::Notify;

use crate::daemon::companion::{
    CompanionInvite, CompanionState, render_pairing_qr, spawn_companion_p2p_listener,
};

/// Invite TTL advertised in the pairing URL, in seconds. 300s (5 min) is long
/// enough to pick up the phone and scan, short enough that a leaked QR/URL
/// expires quickly. Matches the `ttl=300` the companion app expects.
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
    /// Mint a one-time phone-pairing invite, show a QR code, and wait for the
    /// companion app to connect over the Hyperswarm P2P mesh. The invite is
    /// single-use and expires after a short TTL. Requires the `cluster` feature.
    PairPhone {
        /// Hand the invite to a RUNNING `neoth serve` daemon instead of driving
        /// the pairing in this short-lived CLI process. Writes the invite
        /// atomically to `~/.neoth/companion_pending_invite.json`, which the
        /// daemon's serve-side P2P coordinator (`companion.p2p_enabled: true`)
        /// polls every ~2s, consumes single-use, and completes the handshake —
        /// minting the token into the daemon's LONG-LIVED store so it is also
        /// valid on the loopback HTTP path. Without this flag the CLI drives a
        /// transient in-process listener whose token dies when the command exits.
        #[arg(long)]
        write_invite_for_serve: bool,
    },
}

pub async fn run_companion(args: CompanionArgs) -> Result<()> {
    match args.command {
        CompanionCommand::PairPhone {
            write_invite_for_serve,
        } => run_pair_phone(write_invite_for_serve).await,
    }
}

async fn run_pair_phone(write_invite_for_serve: bool) -> Result<()> {
    // Validate the daemon-backed contract before minting or displaying a
    // secret invite. Otherwise the default `p2p_enabled: false` configuration
    // leaves a live-looking QR and an invite file that no process consumes.
    let serve_handoff = if write_invite_for_serve {
        let home = crate::config::FreedomConfig::default_neoth_home();
        let cfg = crate::config::FreedomConfig::load_from_path(&home.join("freedom.yaml"))
            .context("load companion configuration; run `neoth init` first")?;
        validate_serve_handoff_config(&cfg)?;
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

    // QR first when stdout is a TTY; render_pairing_qr returns "" on failure /
    // non-TTY, so the URL fallback below is always printed regardless.
    let qr = render_pairing_qr(&url);
    if !qr.is_empty() {
        println!("{qr}");
    }

    println!("Scan the QR above with the NEOTH companion app, or open this URL on your phone:");
    println!();
    println!("  {url}");
    println!();
    println!("This invite is single-use and expires in {PAIR_INVITE_TTL_SECS}s.");
    println!();

    // `--write-invite-for-serve`: hand the invite to a RUNNING daemon rather
    // than driving the pairing here. Write it to the well-known path the
    // serve-side P2P coordinator polls, then exit — the daemon owns the listener
    // and mints the token into its long-lived store (so it is valid on the
    // loopback HTTP path too). This is the daemon-backed flow; the transient
    // in-process path below only fits a no-daemon one-shot.
    if let Some((home, daemon_pid)) = serve_handoff {
        let invite_path = home.join("companion_pending_invite.json");
        let _lock = crate::util::locked_file::lock_file_blocking(
            &home.join("companion_pending_invite.lock"),
            "companion pending invite",
        )?;
        if invite_path.exists() {
            anyhow::bail!(
                "a companion invite is already pending at {}; wait for daemon pid {} \
                 to consume it or remove it after confirming that pairing has expired",
                invite_path.display(),
                daemon_pid
            );
        }
        let json = serde_json::to_vec(&invite.to_pending_invite_json(PAIR_INVITE_TTL_SECS))
            .map_err(|e| anyhow::anyhow!("serialise pending invite: {e}"))?;
        crate::util::atomic_write::atomic_write(&invite_path, &json).map_err(|e| {
            anyhow::anyhow!(
                "write pending invite {} (is `neoth serve` initialised?): {e}",
                invite_path.display()
            )
        })?;
        println!(
            "Invite handed to daemon pid {} at {}.\n\
             The serve-side coordinator (companion.p2p_enabled: true) picks it up \
             within ~2s and completes the pairing into the daemon's token store.",
            daemon_pid,
            invite_path.display()
        );
        return Ok(());
    }

    // Spawn a transient CompanionState (token store) and a transient WAL writer
    // for this standalone CLI invocation. The CLI runs outside of `neoth serve`,
    // so it cannot share the daemon's long-lived state — it mints its own
    // in-process token store that lives for the duration of this command.
    //
    // WAL: we use a tempfile-backed WAL writer so the 0x0D/0x0E audit frames
    // land somewhere, even in the standalone case. The operator can redirect
    // the daemon's WAL for the session-start approach if needed.
    let wal_dir = tempfile::tempdir().map_err(|e| anyhow::anyhow!("tempdir: {e}"))?;
    let seg = wal_dir.path().join("companion_pair.wal");
    let (writer, _wal_join) =
        crate::wal::writer::spawn(seg).map_err(|e| anyhow::anyhow!("spawn WAL writer: {e}"))?;

    // The transient state shares port 0 (unused in P2P path — port is only
    // relevant for the HTTP companion server's CSRF check).
    let state = Arc::new(CompanionState::new(writer.clone(), 0));

    let shutdown = Arc::new(Notify::new());

    // Spawn the P2P listener. Under `cluster` this drives the full Noise accept
    // loop; under non-cluster it exits immediately with a warning.
    let task = spawn_companion_p2p_listener(
        invite,
        Arc::clone(&state),
        writer,
        PAIR_INVITE_TTL_SECS,
        Arc::clone(&shutdown),
    );

    println!("Waiting for companion app to connect (up to {PAIR_INVITE_TTL_SECS}s)...");
    println!("(Press Ctrl-C to abort early)");
    println!();

    // Wait for the listener to finish (paired / rejected / TTL expiry) OR for
    // the grace timeout. We do NOT simply `.await` the task in case the
    // listener stalls beyond the TTL due to a slow network teardown.
    let grace = tokio::time::Duration::from_secs(PAIR_INVITE_TTL_SECS + PAIR_INVITE_GRACE_SECS);
    tokio::select! {
        res = task => {
            match res {
                Ok(()) => println!("Pairing complete (check daemon logs for details)."),
                Err(e) => println!("Pairing listener exited with error: {e}"),
            }
        }
        _ = tokio::time::sleep(grace) => {
            shutdown.notify_waiters();
            println!("Invite expired — no companion connected within {PAIR_INVITE_TTL_SECS}s.");
        }
        _ = tokio::signal::ctrl_c() => {
            shutdown.notify_waiters();
            println!("Aborted by operator (Ctrl-C).");
        }
    }

    // `_wal_join` and `wal_dir` drop here; WAL writer flushes its final frame.
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

    #[cfg(feature = "cluster")]
    #[test]
    fn serve_handoff_accepts_fully_enabled_cluster_config() {
        let mut cfg = crate::config::FreedomConfig::default();
        cfg.companion.enabled = true;
        cfg.companion.p2p_enabled = true;
        validate_serve_handoff_config(&cfg).unwrap();
    }
}
