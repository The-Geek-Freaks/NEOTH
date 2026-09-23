# W385 Windows FullCI test window

FullCI954 Windows run `35850855062`, job `107147926721`, completed compilation
and planned 17,712 tests. Its `Run nextest workspace tests` step was terminated
by the configured 30-minute step limit near test 15,181, so nextest did not
write `SRC/target/nextest/ci/junit.xml` for artifact upload.

The Windows matrix entry now retains its 80-minute compile allowance,
single-build-job memory boundary, serial test execution, and all per-test
timeouts. Only the separate nextest execution window changes from 30 to 60
minutes. The matrix job budget changes from 120 to 150 minutes, preserving the
same 10-minute checkout, toolchain, cache, and artifact margin. macOS matrix
values are unchanged.

The adjustment addresses a job-level deadline, not the separately diagnosed
retention-test timeout. A hosted Windows FullCI rerun must confirm a completed
nextest run and a JUnit artifact.
