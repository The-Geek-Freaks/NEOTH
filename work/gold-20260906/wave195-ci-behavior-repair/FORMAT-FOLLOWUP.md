# W195 hosted format follow-up

GitHub Preflight `35721484401` reached the hosted `cargo fmt --all -- --check` gate and reported only 15 formatting hunks in the already modified research lifecycle files:

- `SRC/neothd/src/cli/research.rs` (10 hunks)
- `SRC/neothd/src/daemon/research_runs.rs` (5 hunks)

Each expected formatted hunk from the full GitHub failure log was found exactly once in the working tree and each stale hunk zero times. This follow-up publishes only that formatting state. No local Rust formatter, compiler, test, fixture, GUI, or product executable was run under the BSOD hold.
