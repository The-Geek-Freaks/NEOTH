# W60 verification — retained context and final replies

This batch builds on W58/W59 `752031cb478b102c19f52cb0eb6951c202744ebf`.
It changes five Rust owners and their architecture documentation.

Chat and Channel retain a context binding only when the complete canonical
repository/architecture envelope survives final prompt budgeting. Raw text,
changed data, wrong source/class, omitted or renderer-truncated envelopes cannot
create that claim. Once recovery, reply hooks and teacher replacement finish,
the metadata-only `CodeMapRecallResolved` status `final_reply_prepared` binds the
prepared final body to that retained input. Chat appends before authenticated
terminal success; Channel appends before ordinary reply release. Append failure
suppresses normal success. Preparation is distinct from external delivery.

Main and Buddy accept the optional v3 `done` field `code_map_binding_sha256`
only on authenticated terminal completion and only as 64 lowercase hexadecimal
characters. Existing finalization/reply hashes and protocol version are retained;
this adds no provider-wire or new cryptographic final-body attestation.

Exact-target rebuild recall now passes its immutable include/exclude scope into
the initial freshness preflight. General automatic readiness still checks the
whole selected root. Edited target data remains stale; runtime siblings outside
the authorized rebuild scope cannot falsely invalidate the scoped receipt.

| Local gate | Recorded result |
| --- | --- |
| Native Clippy05 | PASS; 1m57s; min free 216.42 GiB, peak 6.82 GiB |
| Native TestBuild03 | PASS; 1m20s; min free 213.45 GiB, peak 9.33 GiB |
| Native selected03 | 2757 passed / 0 failed / 0 ignored in 160.13s; 14716 catalog, 20 filters, ten required fixtures, all 150 Self-Improve tests |
| Seven contracts02 | 750 passed / 0 failed / 0 ignored; build 22.89s |
| CLI docgen | 1 passed / 0 failed / 0 ignored |
| Real GUI/Buddy callback02 | Six states, 1 passed in 0.64s; build 7m58s; min free 205.41 GiB, peak 18.61 GiB |
| GUI catalog and terminal field | 741 catalogued; exact terminal test passed in 0.01s on the same executable |
| GUI Clippy01, last compiler | PASS; 7m 37s; min free 211.73 GiB, peak 11.75 GiB |
| Python and fresh source lint | 45 checks passed; GUI token/motion source lint passed |

Every final compiler/runtime gate uses the same 265 pre-docgen source rows.
The [source manifest](verification/gold-wave60-source-manifest.json) has 266
post-docgen inputs; the [test matrix](verification/gold-wave60-test-matrix.json)
records exact selections, required fixtures, nine executable hashes and retained
gate artifacts. Publication compares current, staged and recorded source bytes;
the sole existing GUI-lint line-ending exception is explicitly bound. All builds
used one job, Idle priority and four CPUs. The known thirteen GUI dead-code
warnings and one vendor warning remain; no memory guard stopped a build.

Earlier attempts are diagnostic only: selected01 had five failures (two raw
versus canonical-context mismatches and three fixture WAL/turn-budget defects).
The reviewed repairs passed selected02, then GUI callback01 exposed a trait
import in the wrong test module. Its import-only move passed callback02 and the
fresh final native/contract gates above. The speculative config seed was rejected.

Only the CRG-01 enabled-but-missing/stale/corrupt/unmapped visibility/actionability
child closes: the real callback covers Disabled, Missing, Eligible, Stale,
Unmapped and Unreadable states through the production selected-root route and
joins the native CLI, Doctor and Channel evidence. Current counts are
1324 total / 1015 checked / 307 open / 2 partial, raw 309 and pre-tag 308.
Its parent and other policy, coding-action, result-citation and clean-install
children remain open. Callback and source lint are not visual/a11y, installed
GUI/Buddy, live provider/channel or release acceptance.

The preceding W58/W59 full CI is separate: Linux and Windows each failed the
same twenty Self-Improve stale-receipt cases. This batch repairs their common
cause and passes all 150 local Self-Improve tests. macOS reached its 100-minute
compile deadline before any workspace test execution. Its log shows no compiler
error or OOM, and the interrupted target cache was retained; the timeout remains
an unresolved remote acceptance boundary. No remote W60 success is claimed
until the published W60 commit is tested. Next is the independently
reviewed 13-source W61+W63+W64+W65 candidate; W62 installed CLI and W66 session
memory framing remain separate, unadmitted work.
