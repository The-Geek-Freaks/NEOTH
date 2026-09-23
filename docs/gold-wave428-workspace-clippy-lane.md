# W428 — opt-in workspace Clippy lane

The existing **Generate CLI reference** workflow now exposes a `workspace_clippy` boolean input, defaulting to `false`. Existing dispatches therefore retain the former 50-minute budget and perform the same CLI-export steps.

With `workspace_clippy=true`, the job budget is 90 minutes. It installs the same Linux build dependencies used by FullCI Linux quality and restores the Linux-quality cache. Default dispatches retain the existing Gold-smoke cache; the job performs one cache restore in either mode. After the existing core-test type check and before the public CLI build, it runs the exact FullCI workspace command with a 30-minute step budget:

```text
cargo clippy --workspace --all-targets --features "wizard wasm-plugin-host" --locked -- -D warnings
```

This supplies a manually dispatched, narrowly scoped hosted proof without changing FullCI or its cancellation state. No local executable validation was run under the BSOD hold; hosted validation is pending dispatch.
