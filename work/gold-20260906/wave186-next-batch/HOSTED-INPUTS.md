# W186 Hosted supply-input workflow

`.github/workflows/live-audio-inputs.yml` is a manual `workflow_dispatch`
workflow intended to be dispatched from `main`. It has read-only repository
contents permission, checks out without persisted credentials, uses one
Ubuntu worker and Rust `1.91.0`, and never commits or pushes.

The runner copies `SRC` into `$RUNNER_TEMP`, preserving the checked-out source.
Only that copy receives the two direct entries in `neothd/Cargo.toml`:
`cpal = "=0.18.2"` and `tract-onnx = "=0.23.8"`. Cargo metadata resolves only the
missing entries while retaining the valid existing lock; the workflow never
uses `cargo generate-lockfile`. It fails if any pre-existing Cargo lock entry
changes in its complete `(name, version, source)` identity or registry checksum.
It deliberately does not compare package dependency-display lists: `neothd`
must acquire the two direct edges and Cargo may disambiguate those strings.
New resolution entries are retained in the output evidence.

The workflow performs no build, test, formatter, device action, or model
execution. It invokes Cargo only to resolve the temporary lock and emit
metadata, using the Rust-1.91-compatible resolver policy. Its metadata check
examines only packages newly added to the lock by the W186 inputs and rejects a
declared MSRV newer than 1.91; the existing workspace has unrelated optional
packages for newer release targets. A subsequent native selected-target build
is still required to prove the complete graph. It never uses
`--ignore-rust-version`.

It downloads the immutable model and MIT license directly from
`snakers4/silero-vad` commit `60b7ffa243625ebdc1070275a29f18c87843786a`.
The model must be exactly 1,289,603 bytes and match Git blob SHA-1
`625ad8909b1abdba2292f3a9a10db6864fd5d561`, calculated with Git's
`blob <size>\0` prefix. The artifact includes the source HEAD; input and output
copies of every Cargo manifest and the workspace lock; all manifest/lock/evidence
SHA-256 digests; the ONNX model; the upstream MIT license; and generated
model/license provenance with the model SHA-256.

Root review and a deliberate push/dispatch remain required before this workflow
can create any hosted evidence. This file and the workflow do not import the
asset into `SRC/neothd/assets`, modify `Cargo.lock` in the repository, or close
a roadmap item.
