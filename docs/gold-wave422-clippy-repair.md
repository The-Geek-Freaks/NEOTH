# W422 — Linux quality Clippy repair

## Diagnosis

FullCI bc9 run 35871801240 failed only its Linux quality job 107217501778. The exact GitHub log was downloaded to work/gold-20260906/wave422-clippy/job-107217501778.log.

The job first passed the slim production command:

cargo clippy -p neoth --lib --bins --no-default-features --locked --no-deps -- -D warnings

It then failed the workspace quality command:

cargo clippy --workspace --all-targets --features "wizard wasm-plugin-host" --locked -- -D warnings

Exact diagnostic:

error: this function has too many arguments (9/8)
--> neothd/src/cli/serve_tasks.rs:4249:1
note: -D clippy::too-many-arguments is implied by -D warnings

The failing function was spawn_audit_rpc. Its nine arguments were the daemon configuration, home, WAL writer, two runtime handles, PID guard, endpoint nonce, and two cluster-only controllers.

## Repair

The repair introduces the crate-visible module-level AuditRpcInputs argument bundle in SRC/neothd/src/cli/serve_tasks.rs and changes spawn_audit_rpc to accept that one value. The two feature-gated call sites in SRC/neothd/src/cli/serve.rs now construct the bundle.

The values, ownership, cluster feature gating, endpoint nonce publication, sidecar guard, and listener behavior are unchanged. This removes the Clippy trigger without an allow attribute or a behavior change.

## Validation boundary

Text and Git inspection confirms there are exactly two call sites and both now supply every previous argument. git diff --check is clean.

No local Cargo, compiler, rustfmt, parser, tests, or runtime were run under the BSOD hold. The required next proof is the hosted Linux quality rerun of the same workspace Clippy command. FullCI was not cancelled; its other platforms remain useful.

## Hosted rerun scope

The only existing workflow containing that exact command is FullCI in .github/workflows/ci.yml, job linux-quality (Linux quality / Rust 1.91). It supports workflow_dispatch, but has no job-selection input, and no separate existing workflow reruns this workspace Clippy lane. A manual FullCI dispatch is therefore the smallest existing hosted option, but it restarts the rest of that workflow too; it remains pending authorization.
