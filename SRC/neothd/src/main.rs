// Thin binary wrapper for the `neothd` library target.
//
// V03-06 / D14b-5 (Session 21): the crate is now lib+bin so the criterion
// bench harness + downstream consumers can reach internal modules via
// `use neothd::*;`. All the original main.rs body — clippy lints +
// module declarations + helpers + the body of `fn main` — lives in
// `src/lib.rs` (see `pub async fn run`). This file is the public `neoth`
// binary target. The legacy `neothd` target includes this same launcher, so
// both executable names stay behaviourally identical while the Rust library
// keeps its established `neothd` name.
//
// Why split (V03-06): adding a `[lib]` section unblocks criterion benches
// that need to `use neothd::wal::writer;` etc. Without the split,
// `cargo bench -p neoth` had no entry point for the p99 / latency
// benches the V03-06 GA requirement names. Now they do.

use anyhow::{Context, Result};

/// Stack for the worker thread that drives `neothd::run()`. Clap renders help
/// for a very large command tree (100+ subcommands); in DEBUG builds that
/// recursion can exceed the default 8 MiB main-thread stack — observed as
/// `neothd --help` aborting with a stack overflow (0xC00000FD) under the
/// `cli_*_binary` integration tests. A roomy worker stack gives clap's
/// help/parse recursion + the async runtime headroom. Release builds (smaller
/// frames) never hit this, but the headroom is harmless there.
const MAIN_STACK_BYTES: usize = 32 * 1024 * 1024;

fn main() -> Result<()> {
    // The Graphify guardian is a private, transient-service-only pre-exec
    // verifier. It must run before Clap and Tokio so untrusted Python cannot
    // start until its effective Linux boundary has been attested.
    #[cfg(target_os = "linux")]
    if let Some(exit_code) = neothd::graphify_runner::run_linux_graphify_containment_guard_if_requested() {
        std::process::exit(exit_code);
    }

    // Private media-worker modes must run before Clap or the long-lived Tokio
    // runtime is constructed. They are intentionally absent from the public
    // command tree and exit immediately after one resource-bounded operation.
    if let Some(result) = neothd::media::pdf::run_internal_pdf_worker_if_requested() {
        result.map_err(anyhow::Error::msg)?;
        return Ok(());
    }

    // Run everything on a child thread with a large stack rather than the
    // default `#[tokio::main]` main thread, so the clap help/parse pass that
    // happens at the top of `run()` (before the first await) can't overflow.
    let worker = std::thread::Builder::new()
        .name("neoth-main".to_string())
        .stack_size(MAIN_STACK_BYTES)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("build the tokio runtime")?
                .block_on(neothd::run())
        })
        .context("spawn the neoth main worker thread")?;
    let outcome: Result<()> = worker
        .join()
        .map_err(|_| anyhow::anyhow!("neoth main worker thread panicked"))?;

    // GOLD-COR-01 / A-03: a subcommand that wants a non-zero status code
    // returns `QuietExit(code)` instead of calling `std::process::exit` deep in
    // the stack. By the time we get here the worker thread has fully returned —
    // every Drop ran (WAL flush, DB close, tokio runtime drain) — so it is now
    // safe to translate the marker into the requested exit code without the
    // anyhow Debug crash dump that a plain `Err` would print.
    if let Err(e) = &outcome
        && let Some(neothd::QuietExit(code)) = e.downcast_ref::<neothd::QuietExit>()
    {
        std::process::exit(*code);
    }
    outcome
}
