# W183: Yearly synthesis from canonical period reflections

W183 connects the existing hygiene planner to the real CLI and daemon yearly
consumers. Both call one bounded archive-only composer. The exact contributing
Daily archive bytes and effective synonym map are hashed into the yearly record;
exclusive atomic publication through retained directory capabilities prevents
duplicate records. Same-input retries retain a source-derived timestamp and
converge even when wall-clock time advances. Changed candidates cannot overwrite
an existing yearly snapshot.

The automatic cadence retains once-per-current-UTC-year snapshot semantics.
It skips only when the completion marker has a matching, strictly validated
yearly receipt. Later Daily input does not cause endless cron conflicts; a
manual digest still reports a changed-source conflict. Daily composition,
admission and the read-only retention inventory remain unchanged.

Six new native regression identities cover planner year selection, strict
archive parsing, conflict handling, concurrent settlement, CLI without a
database, and the real cron/CLI sequence with advancing time and new Daily data.
Existing planner and retention guards are also registered for this batch.

Independent reviews:

- `work/gold-20260906/wave183-next-batch/REVIEW-01.md`, SHA-256
  `79FC9DC3905AD6D2A22F1F1E0CFE00920A502C8C5B068B1183E2771EB8E574E9`:
  shared composer and source-stable retry correction.
- `work/gold-20260906/wave183-next-batch/REVIEW-02.md`, SHA-256
  `AE7A610E730CD7061E7E7B292D882962BD6C10ECE8733D3708DA496DA8F1C378`:
  validated automatic cadence and manual conflict behavior.

Both are static approvals. No local compiler, formatter, parser, fixture or
test was executed. Hosted formatting, core compilation and behavioral execution
remain required. GOLD-LF-P2-04 stays open, including its separate retention and
migration requirements. See [the operator behavior](reflection-yearly.md).

This publication also imports the single exact formatting hunk reported by
Preflight `35672248701` on `a2bd1b37`, in the W177 chat test's database-open call.
It does not change that fixture's assertions or runtime behavior. The preceding
core check `35672248518` is tracked separately from W183 acceptance.

Hosted follow-up: Code Quality `35672664825` passed on `5ff3689b`.
Preflight `35672664943` reported 23 formatting hunks across the four W183
Rust sources. All 23 exact, uniquely matched hunks have been imported, with
zero foreign paths. Receipt `FORMAT-HOSTED-5FF.json` has SHA-256
`7E6AFEA3D6D73F861383CDB712BB37CED68CF194AB7B16E5236791AFE4AFCE92`.
The preceding W182 core test typecheck on `a2bd1b37` passed; its CLI build and
the queued W183 check remain separate gates. No behavioral completion is claimed.
