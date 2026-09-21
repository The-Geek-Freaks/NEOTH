# W172 — exact Hosted test-compilation and lint repairs

GitHub CI 35653174520 on 61eaa58fc060d211e73e1535caf3dcd04b80d7f0
exposed two distinct failures before the complete native suites could run.

- The channel-adapters job 106510251649 reported four E0308 errors in the
  existing throughput producer test. W168 made the control token optional so
  daemon-GUI events can share the producer. The CLI test now explicitly passes
  `Some(token)` to its four calls, preserving its token-bound frame assertions.
  Production call sites already pass the optional token.
- Linux quality job 106510251267 passed workspace formatting and slim-core
  Clippy, then rejected an unfulfilled `expect(dead_code)` on the public
  `gui_action` module imported by the impact-controller integration test.
  The obsolete expectation is removed. No lint is suppressed or disabled.

The source-bound logs and independent review are retained under
`work/gold-20260906/wave172-hosted-repair/`. These changes require fresh
GitHub compilation and test execution. They do not establish native, GUI,
portable, or release acceptance and close no Road item.

The unaffected Windows preview 35653179383 remains a separate source-bound
run. The small cadence-only correction 9c2a4215 passed Preflight 35653959335
and Code Quality 35653958110 before these Rust test repairs.

No local compiler, formatter, tests, fixtures, or product execution ran.
