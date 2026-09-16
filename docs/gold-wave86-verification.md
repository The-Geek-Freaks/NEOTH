# W86 - bounded Windows preview feedback

The earlier preview [35069306601](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35069306601)
on `e6f24af8` reached GitHub's 100-minute whole-job deadline. Compilation reached
the `neoth` crate at 08:22:59 UTC and was cancelled at 09:15:36 UTC. Its log has
no Rust compiler diagnostic, completed preview artifact or product-acceptance
result. This establishes a deadline failure, not an OOM or a particular compiler
subphase as its cause.

The preview workflow now applies four local-to-workflow Cargo release-profile
overrides: opt-level 1, debug 0, LTO false and 16 codegen units. The artifact calls
this configuration `preview-fast-v1` and records each override plus Rust 1.93.0.
The published release profile and release workflow are unchanged. Any performance
benefit remains to be measured; preview results cannot establish optimized-release
performance.

The job retains one Cargo build worker, static MSVC CRT, the locked
`release-desktop` feature bundle, all existing native and Keet executables,
source-SHA binding, payload inventory and ZIP checksum. It remains manual,
unsigned, unreleased and separate from installation acceptance.

The 240-minute job bound contains independent CLI/auxiliary/GUI build bounds of
90/15/25 minutes. The sum of all explicitly bounded steps is 205 minutes, leaving
35 minutes for setup and recovery overhead. Cache namespaces bind compiler,
CRT, preview profile and lock hash; run/attempt keys are immutable. Completed
Rust phases have restore priority. Interrupted targets are the final compatible
recovery option and are never marked complete. Cargo must still validate its
fingerprints and complete the requested build after restoration.

Independent review approved the two exact producer files. Four focused preview
contracts pass locally without compiling. The paired WORK-only lifecycle and
diff-impact helpers require the new provenance before extraction or execution
and retain the exact source, inventory, path, process and isolated-home bounds.
They have not executed an artifact; the new remote build must produce one first.

The [source manifest](verification/gold-wave86-source-manifest.json) retains 290
inputs. The [test matrix](verification/gold-wave86-test-matrix.json) preserves
48 native and 6 GUI identities pending the next exact-source CI run. ROAD and
PROGRESS retain all checkbox states: 1324 total / 1015 checked / 307 open /
2 partial, raw309 / pre-tag308. Local Cargo, compiler, Clippy and linker execution
remain suspended.
