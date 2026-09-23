# Gold Wave 345: bounded-retention fixture setup repair

The Windows750 hosted watchdog terminated
`v2_bounded_batches_preserve_unselected_expired_records_for_later_ticks` at
120.008 seconds. Its log contains no in-fixture assertion or panic before the
watchdog, so it identifies excess setup work but does not attribute a measured
phase duration.

The fixture now creates its current record through the real
`settle_daily_admission` transaction and writes the 130 historical
`PeriodReflection` records through the existing exact JSONL fixture helper.
That helper preserves every field retention consumes: the serialized complete
period reflection is parsed, tagged, digested, compared to hygiene period
input, selected deterministically, journaled, and moved by the normal v2
executor. `preserve_period_inputs` remains unchanged, so candidate authority
continues to require the exact persisted period input.

The test still presents 131 active archives and executes the same three
retention ticks with the production batch cap. It now asserts active archive
counts of 131, 67, 3, and 1 around the ticks, alongside the unchanged receipt
counts 64, 128, and 130, absence of every expired active leaf, and oldest/newest
yearly-synthesis source evidence. These counts show that each batch leaves its
unselected records available for the next tick; no archive count, batch cap,
watchdog, production retention code, or timeout was changed.

No local executable validation was performed under the absolute BSOD hold. The
required proof is the exact Windows-hosted fixture completing below the
unchanged 120-second watchdog with these existing behavioral assertions.