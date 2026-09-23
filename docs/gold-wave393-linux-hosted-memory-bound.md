# W393 Linux hosted resource mitigation

FullCI954's original Linux job and targeted retry job `107173647501` both
stopped during workspace Clippy after the hosted runner reported a shutdown
signal and exit code 143. Neither log supplies a Rust compiler diagnostic, so
the root cause is unproven.

`linux-quality` now sets `CARGO_BUILD_JOBS: 1` for its whole job. This is a
serial frontend-compilation mitigation only. It preserves the existing checks,
feature set, step and per-test timeouts, and the explicit one-job nextest
override. Windows and macOS matrix settings are unchanged.

This does not claim the hosted failure is fixed. A hosted Linux rerun must
complete the workspace Clippy step before the mitigation can be accepted as
effective.
