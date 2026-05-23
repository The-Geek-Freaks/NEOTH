// Thin binary wrapper for the `neothd` library target.
//
// V03-06 / D14b-5 (Session 21): the crate is now lib+bin so the criterion
// bench harness + downstream consumers can reach internal modules via
// `use neothd::*;`. All the original main.rs body — clippy lints +
// module declarations + helpers + the body of `fn main` — lives in
// `src/lib.rs` (see `pub async fn run`). This file is the binary target
// the operator-facing `neothd` executable resolves to; it delegates
// straight into the lib.
//
// Why split (V03-06): adding a `[lib]` section unblocks criterion benches
// that need to `use neothd::wal::writer;` etc. Without the split,
// `cargo bench -p neothd` had no entry point for the p99 / latency
// benches the V03-06 GA requirement names. Now they do.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    neothd::run().await
}
