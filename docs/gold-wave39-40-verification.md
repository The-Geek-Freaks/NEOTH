# Gold Waves 39–40 — daemon plain chat and native CLI probe

**Receipt status:** LOCAL VALIDATION COMPLETE.

This receipt covers eighteen admitted source files in a retained
204-input union based on published Waves 35–38 `20423301`. It records local
validation, not a roadmap closure or cross-platform acceptance.

## Admitted behavior

Wave 39 introduces a sealed, same-user daemon plain-chat route. Command forms
are rejected before capacity admission or provider, configuration, local-action,
or WAL work. The daemon retains turn resources and the CLI may fall back only
when the RPC attempt has not written. Completion guards and bounded response
writes keep a client from holding shutdown indefinitely.

Wave 40 adds an authority-bound native CLI version probe. It binds the accepted
descriptor, recaptures it before contained execution, uses a fixed version-only
command, and records durable intent and terminal receipts. Cancellation and
timeout prevent later component admission and reap the contained child before
terminal classification. npm, Git, OSV, installers, and automatic SelfApply are
outside this lane; unsupported wrappers produce typed outcomes.

## Validation boundary

Clippy07 passed in 2m49s with 218.03 GiB minimum free and 6.72 GiB peak use.
TestBuild03 passed in 3m44s with 214.04 GiB minimum free and 10.77 GiB peak use.
The final selected run passed 639/0/1 in 48.33s from the 14,528-test catalog.
Its ignored health-probe child-listener check is an explicit helper exercised by
its parent through a real OS subprocess. The 13 contract targets passed 157/0/0
after 4m20s compilation, with 213.89 GiB minimum free and 11.05 GiB peak use.
GUI check passed in 5m50s with no GUI link or native-GUI claim; the existing 13
GUI test dead-code and vendor warnings remain. Python19+11+8 passed.

`docs/verification/gold-wave39-40-source-manifest.json` and
`docs/verification/gold-wave39-40-test-matrix.json` record 204 inputs and 14
executables. The unit executable is
`153B78EEBC401C4EC818663783F561DB20955FCE184DC7B8B5C7A65E01BF246B`
(285,750,272 bytes). Builder helpers04 verified source and executable evidence,
including the exact nested-child parser. The earlier selected hang and 636/3/1
run were repaired before this final run; neither is pass evidence.

The published W35–38 CI snapshot `34836363982` is not replacement evidence for
this batch: Windows and macOS succeeded. Linux's known audit-RPC fixture-race
repair now passes locally and is included in this changeset. No full-CI or cross-platform
pass is recorded. A full CI run for the published commit remains required.

## Limits

This work does not establish daemon replay, status, or cancel APIs; native GUI
or live-provider behavior; cross-platform acceptance; or a change to the open
R3-18B, P2-26, P1-16, and P1-17 obligations. Roadmap counts remain
**1324 total / 1012 done / 310 open / 2 partial**.

Wave 41's GUI/RPC/runtime, HTTP, MCP, and process-start work remains a proposal
with no admitted source, although its B1 and GUI07 slices are approved;
lifecycle/owned-cleanup integration and real tests remain pending. Wave 42's
approved three-file v5 channel-health proposal is also not admitted; its partial
parent remains open.
