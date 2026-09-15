# W61/W63/W64/W65 verification

## Scope and resulting behavior

This batch adds thirteen independently reviewed Rust source changes on W60
`aad9a9165fc45dcd4f4e5e2184225460f6c4492d`, plus the Linux CI virtual-display
repair and its build-cadence documentation. The final native composition is
`wave61-65-composed-06`. W62 installed-CLI work and W66–W69 remain separate.

- **W61:** generated MCP results carry scoped root/index/graph metadata from the
  child's actual SQLite snapshot, including empty results. The existing called
  audit precedes metadata validation. A durable `final_tool_result_prepared`
  receipt binds the child's raw result commitment to the sanitized public
  projection before return. Invalid metadata and receipt-append failure cannot
  return ordinary prepared success. The authenticated audit RPC accepts the
  narrow observational receipt contract.
- **W63:** coding workers receive the request's immutable prepared repository
  context. The selector stays context-free; the task envelope has one fixed
  required context field. Re-sanitization and the 64 KiB byte ceiling precede
  both selector and task calls.
- **W64:** dispatch-loop compaction wraps complete older history in a canonical
  ModelOutput envelope and measures the escaped request before choosing UTF-8
  chunks. Excess fan-out is refused before provider dispatch and start audit.
  The real UTF-8 midpoint defect is fixed: the search advances to a valid
  boundary instead of prematurely rejecting a fitting final scalar.
- **W65:** the separate utility-compaction provider wraps complete older history
  and enforces the ModelOutput class cap before utility or main dispatch. It
  retains the identifier guard, fallback and tail. This is not a claim of W64's
  dynamic rendered-request capacity check in this separate owner.

## Final local checks

| Check | Result |
| --- | --- |
| Native TestBuild03 | PASS, 3m08s; minimum free 212.29 GiB, peak build working set 10.21 GiB. |
| Native selected03 | 2,894 passed / 0 failed / 1 ignored in 176.40s. One invocation, 24 filters, exact 2,895-test selection from a 14,739-test catalog; all 21 mandatory fixtures passed. |
| Native Clippy05 | PASS, 3m05s; minimum free 215.54 GiB, peak 7.02 GiB. |
| Seven contracts01 | 750 passed / 0 failed / 0 ignored after a 4m52s build. |
| CLI docgen | 1 passed / 0 failed / 0 ignored, 0.03s. |
| GUI Clippy01, last compiler gate | PASS, 7m33s; minimum free 211.42 GiB, peak 11.67 GiB. Existing guardian/dependency warnings remain. |
| Python checks | 45 passed: lost-feature integrity 19, roadmap 11, release contract 8, CI cadence 7; CI matrix assertions also passed. |
| Fresh GUI lint | PASS; source token/motion checks only. |

Compiler gates ran serially with one Cargo job, Idle priority, affinity 61440
and a 32 GiB free-memory stop threshold. No memory-stop guard fired.
The one ignored test is the existing live-listener child helper
`daemon::audit_rpc::tests::health_probe_child_process_checks_live_listener`;
its parent invokes it explicitly. The added UTF-8 exact-cap regression and the
full-history reconstruction case also passed in the final selection.

The retained source union has **267 pre-docgen / 268 post-docgen inputs**.
[The source manifest](verification/gold-wave61-65-source-manifest.json) and
[test matrix](verification/gold-wave61-65-test-matrix.json) bind source rows,
executables, exact selected tests, gate snapshots and locally retained logs.
The final GUI snapshot is explicitly post-docgen; the evidence verifier checks
all 268 rows, while native compile inputs exclude only the generated CLI doc.
Staging requires exact current/index byte identity, with the existing narrowly
specified `_gui_lint.ps1` line-ending exception.

## Repair evidence and limits

Earlier native selections are diagnostic: selection01 had 2,883/10/1;
selection02 had 2,893/1/1. Their logs, input snapshots and binary commitments are
retained locally. Repairs corrected test-child MCP initialization, authenticated
WAL segment selection, JSON fixture ownership, the existing RPC type allowlist
and payload status expectations, and the real UTF-8 search defect. The last
positive fixture now derives its minimum cap from the actual canonical emoji
rendering: the escaped surrogate pair needs twelve bytes. Failure assertions
and provider-call refusal checks remain enforced.

GUI source is byte-identical to W60. Its previous runtime evidence is historical;
this batch adds a fresh GUI compilation check, not a new GUI runtime, visual,
accessibility, installed-CLI or provider-delivery acceptance result.

[W60 GitHub run 34991863633](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/34991863633)
is old-head evidence. Linux reported 16,759 passed / 1 failed / 20 skipped
because the real GUI callback had no display. The admitted Linux workflow repair
provides Xvfb. Windows reported 16,692 passed / 1 failed / 22 skipped because the
OpenGL driver lacked `glCreateShader`; its software-renderer repair is queued
for W69. The macOS compile step failed after 100m14s at the configured 100-minute
bound; no nextest tests had started when the interrupted cache save began.
No full remote CI pass is claimed for W60 or this batch.

No ROAD leaf closes. Counts remain **1,324 total / 1,015 checked / 307 open /
2 partial** (raw309/pre-tag308). Other consumer result-provenance, packaged
installation, interaction, cross-platform and parent acceptance requirements
remain open.
