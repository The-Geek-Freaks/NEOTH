# W58-W59 verification

W58 shares automatic-context readiness across CLI, Doctor, Coding, Main and
Buddy. It distinguishes disabled context from missing, stale, corrupt or
unmapped index state and eligible context for the selected canonical root.
Accepted configuration is displayed only after the typed persisted update;
late results remain fenced by root/configuration revisions.

W59 captures one immutable requested-context policy before use by the context
consumers. Generated codegraph children receive the exact impact/requested-policy
trailers, preserve the original tool JSON and retain the four established public
result shapes. Depth, result rows and rendered context are independently bounded.
A partial stored snapshot is diagnosed before a generic stale result.

The accompanying CI repair retains the original combined cache paths and legacy
restores, saves a complete cache only after compilation succeeds, and keeps a
unique partial cache only for compilation failure. Windows and macOS build/test
limits are unchanged. Cache-save behavior on a new remote run remains a separate
observation from the local workflow contract tests.

## Final source validation

All final compiler/runtime gates use the same frozen 262-input source set.
The generated CLI reference is separately verified and becomes input 263 in the
post-docgen manifest. Builds use one Cargo job, Idle priority and CPU affinity
61440 (four logical CPUs), with the existing 32-GiB resource guard.

| Gate | Result | Evidence |
| --- | --- | --- |
| Native Clippy07 | PASS, 1m44s | Minimum free 219.69 GiB; peak build working set 7.32 GiB |
| Native TestBuild03 | PASS, 1m19s | Minimum free 216.86 GiB; peak 8.87 GiB |
| Native selected03 | 2597 passed, 0 failed, 0 ignored; 126.84s | One 19-filter invocation; 14706-test catalog; all twelve required fixtures |
| Seven integration targets01 | 750 passed, 0 failed, 0 ignored | 5m10s build; minimum free 214.91 GiB; peak 11.48 GiB |
| Generated CLI reference | 1 passed, 0 failed, 0 ignored; 0.03s | Existing exact docgen test |
| Real GUI/Buddy callback04 | 1 passed, 0 failed, 0 ignored; 0.52s | 4m12s build; minimum free 215.59 GiB; peak 10.95 GiB; exact 740-test GUI catalog |
| Final GUI Clippy01 | PASS, 8m25s | Last compiler gate; minimum free 214.25 GiB; peak 12.30 GiB; 13 existing GUI dead-code warnings and one vendor warning |
| Python45 and fresh GUI lint | PASS | 19 + 11 + 8 + 7 tests; unchanged CI matrix limits; fresh token/motion source lint |
| Final source and binary binding | PASS | 263 source inputs and nine test executables; staged bytes are checked against the exact publication whitelist before commit |

The native test executable is SHA-256
`B24BB40D2B24B226806CD28F54D1F39CB84126587B51270EEBEDF4A34F06F0BC`
(293,031,936 bytes). The GUI test executable is
`BAFA3EE06D87D1F5459E33931AAD8479F593C47F7742C6887AB25DD3EEEAF4F4`
(273,068,032 bytes). The publication artifacts bind those executables, all seven
integration executables, exact tests, source snapshots and retained logs in the
[source manifest](verification/gold-wave58-59-source-manifest.json) and
[test matrix](verification/gold-wave58-59-test-matrix.json).

The selected fixtures include CLI/Doctor readiness and repair guidance,
Skip-recall after a filesystem change, real two-root MCP dispatch under N/N+1
policy snapshots, all four public tool shapes, typed bounds, pre-tool denial and
cancellation, channel receipt acknowledgement, and actual Coding provider input
under distinct context budgets. Positive MCP fixtures use 256/512-token summary
budgets to admit a legitimate 622-byte result; the 128-token negative case still
proves bounded refusal. The Coding 128-vs-512 comparison remains unchanged.

## Diagnostic history

Earlier failed captures are retained as diagnostics, not successful evidence.
The seven selected01 failures led to reviewed fixture corrections and the
production partial-snapshot diagnostic ordering fix. GUI compile attempts found
an explicit nested-module trait import, a lossless u32/u64 comparison and an
owned timer capture. GUI runtime03 then exposed an unseeded fixture config:
`FreedomConfig::update_at` correctly requires existing `freedom.yaml` bytes.
The final test seeds the standard default config and reports configuration
status on timeout. It retains the production worker/event-loop path.
No final completed build stopped for memory pressure.

## Remaining boundaries

No roadmap checkbox changes: **1324 / 1014 / 308 / 2**, raw **310**, pre-tag **309**.
The W58 visibility/actionability leaf remains open. This GUI callback verifies
Disabled, Missing and Eligible states; W60 composed05 separately prepares actual
Stale, Corrupt and Unmapped callback cases and Chat/Channel final-result binding.
W60 is not part of this source admission. W61 direct-MCP result receipts and W62
installed-Windows CLI lifecycle acceptance are likewise subsequent work.

Native callback tests do not establish visual/accessibility review, installed
GUI/Buddy interaction, external provider/channel delivery or cross-platform
release acceptance. Exact-head GitHub results must name the commit they tested;
prior W54-W57 results cannot validate this batch.
