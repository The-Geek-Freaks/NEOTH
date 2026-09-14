# Gold Waves 24–26 and 28 — factory isolation, bounded updater, OpenClaw import, and skill-route capture

**Receipt status:** **LOCAL VALIDATION COMPLETE.** The source builds on
W21–23 published at `9dac2ee235690fa7c3c9a0e02cc5a60c53426a7c`. Publication
identity is the Git commit containing this receipt. Exact-commit Preflight
`34787856392` and Code Quality `34787856139` passed. Full CI
`34787875712` is terminal **FAILED**: Windows and Linux succeeded; macOS job
`103806563594` ran 16,036 tests (16,034 pass / 2 fail / 23 skip) before its
90/105-minute timeouts. The two failures are
`memory::session_start_recall::tests::{checked_query_error_never_becomes_empty,missing_home_is_no_data_and_never_births_sqlite_or_wal}`.
W24–28 do not change that memory path.

## W24 — factory A/B isolation

W24 adds actual factory A/B isolation coverage. No broader factory acceptance
or live-provider behavior is claimed.

## W25 — finite updater deadline and outcome

W25 bounds updater work with a finite deadline/outcome contract. Late work joins
before WAL closure, HTTP cancellation follows receipt order, and expired work
cannot become a successful terminal outcome. A later review found that the old
classifier treated a planned reload cancellation as fatal; the standalone HTTP
test did not exercise generation replacement. Repair06 now requires a
control-originated typed cancellation to reach the normal Cancel terminal via
the real lane/supervisor loopback, while unexpected cancellation remains fatal.
The final loopback regression proves that only a control-originated typed cancel
reaches the normal Cancel terminal, while unexpected cancellation stays fatal.
R3-18B remains open because runtime enforcement and process containment are
separate acceptance work.

## W26 — selected OpenClaw account import

The importer accepts `--config`, `--source-account`, `--account`, and
`--telegram-user-id`. It reads only the selected token in memory, prepares and
probes the exact target, rechecks the source set, and then uses the existing
prepared CAS commit. A shared raw-JSON custody crate preserves canonical
redacted migration reporting. Manual publish/release contracts consume the
crate without any actual registry publication.

Custody final coverage is 108 migration and 21 custody tests; Python 19/11/8/6/3
also passes. Manual publish/release integration does not publish a registry
artifact.

## W28 — skill-route capture

The independently approved three-file change moves skill bodies behind
`Arc<SkillBody>` and captures the resolved route. Manual serialization preserves
the existing wire shape, while a real concurrent A/B regression covers the new
sharing behavior. The real concurrent reload regression proves A retains its
body/config snapshot while B can publish later. This closes P2-16 only; it does
not close R3-18B.

## Local evidence

| Evidence | Result |
| --- | --- |
| Final selection | **PASS** — 1,492 pass / 0 fail / 1 existing Unix-only ignored; 1,493 selected from catalogue 14,415 in 122.04s |
| Binary | SHA-256 `A86E26373FA025E96FFDCB5F0FB8701A34B638680A3B6A44A9664840BE831F90`; 280,607,232 bytes |
| Build04 | **PASS** — 4m15s; 205.6 GiB minimum free; 10.7 GiB peak |
| Final Compound Clippy | **PASS** — 5m08s; 205.37 GiB minimum free; 9.72 GiB peak |
| 13 AccountConfigContracts | **PASS** — 157 tests; build 5m06s; 206.53 GiB minimum free; 8.27 GiB peak |
| Custody integration | **PASS** — migration 108 + custody 21; doc 0; 286 total across 16 rows and 16 physical executables |
| Formatting, GUI lint, GUI self-test, CLI docgen | **PASS** |
| Python | **PASS** — 19/11/8/6/3 |

The verified artifacts cover 176 source inputs and 16 physical executables:
[source manifest](verification/gold-wave24-26-source-manifest.json) and
[test matrix](verification/gold-wave24-26-test-matrix.json).

## Limits

This batch does not claim a full OpenClaw configuration or transcript migration,
pairing migration, a physical provider live import, native GUI acceptance,
registry publication, or cross-platform validation.
P1-16 and R3-18B remain open. Counts are 1,324 total / 1,011 complete / 311
open / 2 partial (313 raw; 312 pre-tag blockers). P2-16 is complete.
