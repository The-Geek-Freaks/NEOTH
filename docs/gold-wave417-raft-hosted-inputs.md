# W417 — hosted OpenRaft input qualification

W417 provides a manually dispatched, `main`-only GitHub Actions workflow for the
dependency evidence needed before the real three-node budget authority slice. It
does not add Raft code, modify a checked-in manifest or lockfile, build NEOTH, or
claim P2-19 complete.

The workflow copies `SRC` to runner scratch, records the exact commit, index
entries, SHA-256 manifest/lock hashes, and Git blob hashes for only
`SRC/neothd/Cargo.toml` and `SRC/Cargo.lock`. It then makes this isolated proposal:

```toml
cluster = ["dep:peeroxide", "dep:openraft"]
openraft = { version = "=0.9.25", default-features = false, features = ["serde", "storage-v2"], optional = true }
```

The source proof is fetched from the official
`databendlabs/openraft` `v0.9.25` tag, specifically its root manifest and
`openraft/Cargo.toml`. The workflow records their hashes and rejects the run unless
the tagged workspace version is `0.9.25` and that exact crate source declares both
`serde = ["dep:serde"]` and `storage-v2 = []`. This intentionally excludes the
0.10 alpha line that does not qualify the design in
`work/gold-20260906/W416-budget-consensus-design.md`.

`cargo metadata` runs only against the copied workspace and uses Cargo's ordinary
resolution. The acceptance script fails if any pre-existing Cargo.lock package
identity or checksum disappears or changes; only newly added closure entries are
permitted. It exports locked metadata, the new-package list, and an OpenRaft
dependency-closure Rust-version report. Every declared `rust-version` in that
closure must be no higher than Rust 1.91.

The runner also creates a separate, minimal probe crate with exactly
OpenRaft `=0.9.25`, `default-features = false`, and `serde` plus `storage-v2`.
It saves the exported workspace lockfile as evidence, copies it into the isolated
probe, then lets `cargo metadata --offline` normalize the probe root while
preserving existing dependency selections after workspace metadata fetched them. The workflow proves the entire OpenRaft
closure has identical identities and checksums in both locks before running
`cargo check --locked` under Rust 1.91. This verifies the pinned package
configuration can compile on the supported compiler without compiling the
application or treating a successful resolver run as an application integration
proof.

The artifact is uploaded even after a failure. It includes command logs, source
and final hash manifests, upstream source copies and hashes, metadata, new package
list, Rust-version report, probe inputs/logs, and `source-bound.patch`. The patch
contains full Git index blob IDs before and after for precisely the proposed
`SRC/neothd/Cargo.toml` and `SRC/Cargo.lock` changes. A later implementation must
review this artifact against its then-current source; it must not import it or
overwrite production manifests automatically.

`SHA256SUMS` covers the completed evidence files and intentionally excludes the
still-open streamed `runner.log`; the log itself remains in the uploaded artifact.

Dispatch **W417 Raft budget hosted inputs** from `main`. A passing artifact is a
bounded dependency qualification only. The W416 requirements for a real OpenRaft
store, authenticated carrier, fixed three voters, persisted committed grants, and
three-node partition/restart evidence remain open.
