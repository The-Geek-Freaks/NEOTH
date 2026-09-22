# W203: repair the first complete grouped failure inventory

Hosted Grouped60 run `35729827037` on `737b9835` compiled and executed 55
selected identities: 50 passed and five failed. It then stopped because the
first Cron identity selected the nonexistent `cron::runner::tests` namespace.
All five Cron fixtures live in `cron::runner::workstream_c_tests`; the current
matrix now uses those exact identities. None was removed or ignored.

The actual log, source receipt and selection were downloaded. Every one of
sixty source bindings matched the published matrix and source manifest. Actual
pass/fail identities account for all 55 executed tests. In particular W190
10/10, W191 5/5, W194 4/4, W196 4/4 and W197 11/11 passed. W192 was 9/10,
W193 4/5 and W198 3/6; W199 did not execute. Admission receipt:
`work/gold-20260906/wave201-hosted-followup/GROUPED60-ADMISSION.json`.

The missing `attempt_started_unix_ms` case exposed a production defect:
Serde permits an absent Option as None, but the durable schema requires an
explicit timestamp or null. The store now checks presence of all three budget
consumption fields before deserialization, retaining the existing rejection
and byte-preservation test. A malformed record can no longer masquerade as a
valid inactive reservation.

The Drawio resource fixture used `drawio`, which is not an exact declared
trigger. It now uses the unique bundled `drawio xml` phrase; resolver behavior
and materialized-resource assertions are unchanged. Three n8n assertions now
inspect decoded typed payloads instead of escaped envelope JSON; negative
private-field assertions do the same. Equivalent Cron assertions decode the
existing envelope and preserve the one-envelope and generation checks.
Independent source review passed. The repaired sixty identities still require
a fresh complete Hosted run; no local compiler, formatter or test ran.

Core/CLI run `35729831467` on `737b9835` passed test-target checking, public
CLI compilation and export. Its downloaded CLI reference SHA-256 is
`75f0c99d5e32cfbb4d673a97ded91a207a5469bbf1296708349ce0e10a8cae1b`, identical
to committed `docs/cli-commands.md`. Follow-up `17b2a9f8` Preflight
`35730857086` also passed; its test-only loader helper change is separate.

The old Windows preview `35713923652` timed out after ninety GUI-build minutes,
without a compiler error. Its final diagnostics appeared around minute 86 and
its interrupted cache was saved. Only the Hosted GUI step ceiling increases
to 120 minutes; the GitHub-hosted six-hour job maximum, one-worker build,
features, preview profile and all acceptance steps remain intact. No preview,
installed-product or release success is claimed. Road boxes remain unchanged.

W203 Hosted Preflight `35731939537` passed Rust formatting, then exposed two
stale preview-contract expectations for the old90-minute GUI ceiling. Both
contract suites now assert the intentional120-minute GUI limit while retaining
the360-minute outer bound, serial build, unchanged command and acceptance
checks. The contract correction needs a fresh Hosted Preflight; no Python or
other local validation ran. New grouped/core/preview runs on `a68442cb` remain
independent and are preserved.

**W203 second behavior follow-up (2026-09-22):** Grouped60 `35731968545` on
`a68442cb` executed all sixty identities:58 passed, two failed. W190/W191/
W192/W193/W194/W196/W197 now passed their complete selections. The remaining
n8n pin assertion now compares decoded Skill IDs against a proven nonempty
baseline; the Cron failure fixture now obstructs the mandatory bundled-resource
directory instead of supplying an unsigned manifest the loader correctly
excludes. Both focused changes passed independent static review; their new
Hosted execution is pending. Core/CLI `35731972532` passed on the same source
and exported the unchanged reference. `c82fc033` Preflight `35732446246` and
Code Quality `35732446029` passed. No Road checkbox changed.
