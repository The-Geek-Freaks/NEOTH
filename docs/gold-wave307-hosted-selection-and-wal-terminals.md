# W307 — exact Cron selection and authenticated WAL completion

Group564 on 4528557c (run35826131329) selected564 identities but executed556:
538 passed,18 failed,8 never started. Source bindings for117 files, matrix/lock,
ordered executed prefix and every actual terminal were admitted in
work/gold-20260906/wave295-publication/group564452/ADMISSION.json.

The eight W289 fixtures live in cron::runner::workstream_c_tests, while the
matrix mistakenly used cron::runner::tests. This batch corrects the exact
identities without changing fixture bodies or reducing selection.

The same hosted compile emitted three unused-result warnings in authenticated
WAL fixtures: two role-dispatch drains and one mixed-retry denial drain waited
for the task but ignored its inner persistence result. They now require both
the join and actual WAL completion to succeed before reading lifecycle frames.

W304 repairs the17 private-home retention fixtures; W305 reviews the remaining
raw-callsite fingerprint mismatch. No failed or unstarted test is accepted.
No local compiler, formatter, parser, tests or runtime ran under the BSOD hold.
