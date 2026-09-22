# W219 — Buddy provider retry history compatibility

W217 added `provider_retry` to canonical Buddy status. The GUI intentionally
rejects unknown status fields, so that otherwise valid new status could not
refresh Buddy Config. W219 adds a strict typed block without relaxing the
status boundary. An absent block becomes explicitly unavailable for older
CLI versions and existing fixtures. Invalid present blocks fail the whole
refresh and leave the last safe projection visible with invalid/stale status.

## Input and presentation

Known schema, tagged availability and closed class/disposition/lifecycle enums
are required. The projection checks attempt >= 1, at most 16 receipts and
nonempty identifiers bounded to 128 bytes without control characters.
Auth is accepted if and only if disposition is `auth_non_retryable`.
Observed successor lifecycle is accepted only after `retry_intent_closed`.
Chain and session identifiers are validated but discarded before the GUI DTO.
Only class, attempt, provider, wire model, disposition and follow-up lifecycle
reach the card. There is no retry button, new reader or provider policy.

The card states that a later admitted lifecycle is not proof of a send,
delivery or successful retry. It marks incomplete authenticated history and
stale last-known-good data explicitly. It uses existing Theme tokens and
components. Static source evidence does not establish screenshot or
accessibility acceptance.

## Verification boundary

- `panel_logic::tests::w219_provider_retry_is_strict_bounded_redacted_and_absence_compatible`
  covers missing and explicit unavailable history, safe projection, invalid
  combinations, unknown kind/fields, zero attempt, controls, identifier length
  and the receipt cap.
- `w58_gui_callback_runtime_tests::w219_provider_retry_status_callback_projects_only_safe_rows_and_retains_last_known_good`
  invokes production `refresh_buddyconfig` with the staged CLI and actual
  MainWindow/eventloop. It checks publication and rejected-output preservation.
- Linux/macOS selections include the native callback; macOS list, exact
  dispatcher and packaging discovery verifier now agree on 26 cases.
- Independent source review passed for the DTO, actual callback path,
  incomplete-history labels and class/disposition follow-up.

Current inventories: 531 sources, 814 universal native cases, 94 universal GUI
names, 22 Linux/22 macOS GUI extras. Grouped selection remains 272.
No local compiler, formatter, parser, test, fixture or GUI execution ran.
Hosted full native CI must compile and execute these GUI changes.
No Road item is marked complete solely on this source batch.

## Existing Hosted evidence recovered during this batch

Core/CLI run `35778911671` on `28cdd082` succeeded. Grouped270 run
`35778908791` on the same source executed all 270 exact identities. Git source
hashes for 56 paths, matrix, lock and individual terminal results were checked;
269 passed. All four W217 retry cases, six W198 cases (four actual n8n paths
plus two size boundaries), five W199 Cron cases, five W191 loop cases and
three W215 Sub-Agent cases passed. The sole failure remains the loader
aggregate-overflow rollback fixture: `alpha` persists against the exact bundled
baseline. Diagnosis must establish whether that fixture reaches aggregate
rather than individual admission overflow. It is not dismissed as a count change.
The local receipt is `work/gold-20260906/wave217-retry-receipts/grouped270-28/ADMISSION.json`.

## Aggregate Skill rollback correction

Grouped272 `35779348058` on `6739784f` independently reproduces the same sole
failure (271/272 passed, all 56 source identities/matrix/lock/terminals bound).
The original artifact download was damaged by the workstation restart;
it was downloaded afresh and admitted from the `grouped272-673-recovery`
directory. Changed source and docs were checked for NUL corruption: none found.

The fixture genuinely crosses the shared validation limit after admitting
alpha. The production error branch returned its partially populated `by_id`
map. It now rebuilds the trusted bundled-only map under the same accepted
policy, preserving the independent bundled fallback and accepted-epoch check.
The existing regression still requires exact baseline identity, trusted-only
entries and absence of both installed candidates. No test assertion was relaxed.
Independent static review passed; Hosted regression execution remains pending.

The macOS acceptance class map now also includes the already-dispatched W185
local-model callback under its existing custom binary owner; this corrects
inventory drift without adding or duplicating a runtime test.

Published 35c410a870fa43246043cb96ed7146bc79ca47fc. Hosted formatter receipt
35782374142 imported after source/SHA256 and Git pre/postimage checks.
Grouped272 repair 35782455869 runs against the published source; no local formatter ran.
