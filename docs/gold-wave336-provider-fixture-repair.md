# Gold wave 336 provider fixture repair

The Group684 fixture repair covers two historical test failures from run
`35838862993` at `b6090b1f71ce4ca2926494b9f77389c56ecdb7d9`.

- `production_transports_cannot_override_the_safe_dispatch_entry` now records
  all eight explicit permit constructors: ordinary completion, direct retry,
  cancellation-aware completion, two stream paths, and three inline test
  compatibility paths. Direct retry is included because it calls
  `begin_dispatch` before constructing its permit.
- `direct_retry_entrypoint_preserves_configured_fallback_hops` now creates a
  real home-bound WAL writer for its fail-closed authorizer. After draining the
  writer, it verifies the quota and fallback-hop audit frames as well as the
  retained fallback result and route.

No production authorization or fallback behavior changed.
