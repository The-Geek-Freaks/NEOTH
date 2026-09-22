# W241 — Cancellation source-guard reconciliation

Hosted Group402 run `35796828600` at `671511cf6f12af5336339ea8dde28b136027841c`
executed 402 source-bound cases: 400 passed and two guard expectations failed.

The additional `ProviderDispatchPermit::authorized` occurrence is the
`Provider::complete_authorized_cancellable` entry in
`SRC/neothd/src/providers/mod.rs`. It follows the same mandatory sequence as
the ordinary completion entry: `authorize_leaf`, `begin_dispatch`, permit
construction, consent/effect and role-dispatch checks, then a cancellation
check before `complete_raw`. Cancellation settles the permit with
`stream_cancelled`; a successful completion reaches `complete_success`.

The fourth Babel submitter is
`ProviderCallAuditGuard::wrap_event_stream_cancellable` in
`SRC/neothd/src/providers/cost_authorization.rs`. It collects only visible
text, calls `audit.finish(ProviderCallTerminal::Success { .. })` before
submitting, and returns immediately after the terminal event. Its biased
cancellation branch instead calls `audit.failure("stream_cancelled")` and
returns an error before the submitter. Reasoning payloads remain excluded and
the existing incognito gate remains in force.

Accordingly, the two source guards enumerate the new mandatory lifecycle
entry and its success-only sample site. They still reject raw permit minting
outside `providers/mod.rs` and Babel submission outside
`providers/cost_authorization.rs`.
