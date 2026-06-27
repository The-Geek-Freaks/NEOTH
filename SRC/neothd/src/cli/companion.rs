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

use anyhow::Result;
use clap::{Args, Subcommand};
use tokio::sync::Notify;

use crate::daemon::companion::{CompanionInvite, CompanionState, render_pairing_qr,
    spawn_companion_p2p_listener};

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
    PairPhone,
}

pub async fn run_companion(args: CompanionArgs) -> Result<()> {
    match args.command {
        CompanionCommand::PairPhone => run_pair_phone().await,
    }
}

async fn run_pair_phone() -> Result<()> {
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
    let (writer, _wal_join) = crate::wal::writer::spawn(seg)
        .map_err(|e| anyhow::anyhow!("spawn WAL writer: {e}"))?;

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
