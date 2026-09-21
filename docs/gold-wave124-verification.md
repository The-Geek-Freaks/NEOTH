# W124 — observed cross-platform CI recovery

CI `35543099210` on `55ec92254c0223c4d64e9eb7c42a32aa18c80c2a` finished.
Windows executed 16800 tests: 16799 passed (one leaky), one failed, 22 skipped.
The remaining failure is the isolated configured ReadPath provider-loop fixture.
Linux and macOS stopped during GUI test compilation with three `E0433` errors:
the nested callback-test module used `panel_logic` without importing it. The
repair adds only that missing module import and preserves all callback tests.

The isolated MCP fixture clears its environment but configures a real bare
`python` stdio launcher. It now retains only the inherited `PATH` while keeping
the rest of the environment cleared. The exact external tools/call counter is
asserted before the iteration count, so a future early exit exposes the external
call boundary first. All provider, snapshot, receipt and sidecar assertions remain.
The Windows log reports one iteration rather than two; it does not expose the
inner spawn error. PATH loss is the source-supported diagnosis, and a successful
fresh Windows run is still required to confirm the repair.

The prior W123 tuple correction compiled and the SSH-feature job passed in this
run. This does not convert the failed full CI, Linux or macOS tests into passes.
All local validation remains suspended. Independent source review and fresh
GitHub compilation/runtime gates remain distinct; no Road checkbox closes.
