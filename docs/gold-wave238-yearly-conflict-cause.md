# W238 — Exact Unix yearly-receipt conflict cause

Grouped398 run35795048502 on480ff458 executed all398 selected cases:397 passed
and one failed. All83 source paths, matrix, Cargo.lock and exact per-test result
terminals were verified. The retained result is
work/gold-20260906/wave234-native-gui/grouped398-480/ADMISSION.json.

The sole failure was
reflection::periodic::tests::concurrent_yearly_settlers_converge_to_one_atomic_receipt.
The actual cause returned by Unix renameat_with(RENAME_NOREPLACE) is
rustix::io::Errno::EXIST. W234 reached PrivateChildPreCommitError::root_cause but
checked only std::io::Error, so the real no-replace conflict was still rejected.

The Unix branch now recognizes that exact typed errno too. This recognition only
allows the existing retained-directory bounded readback: AlreadyMatching still
requires exact bytes. Different contents, unsafe targets and read failures remain
errors. No string matching or bare numeric errno creates a success.

The existing real concurrency regression is already in Group402. New Hosted
execution remains required; this repair alone is not a test pass or release gate.
No local executable validation ran.
