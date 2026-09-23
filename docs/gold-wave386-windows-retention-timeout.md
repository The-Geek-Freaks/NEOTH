# W386 Windows retention timeout repair

## Hosted evidence

Full CI `35850855062`, Windows job `107147926721`, terminated
`reflection::periodic::retention_v2_tests::v2_bounded_batches_preserve_unselected_expired_records_for_later_ticks`
at `120.009s`. The fixture produced no assertion or panic before the
nextest watchdog terminated it.

This is not the former expensive historical-admission setup: the committed
fixture already creates its 130 historical records with
`write_daily_retention_archive_fixture` and preserves the real period-input
authority once. It still exercises the production execution path in three
batches: 64, then 64, then 2 effects.

## Cause and correction

Before every execution, `reconcile_retention_effect_journals` inspected the
complete durable journal inventory. For every `Committed` journal it called
`list_effect_receipts` again. By the third fixture tick this caused 128
full receipt-directory scans, each parsing up to 128 capability-relative
receipt files, before the last two retention effects could start. Windows
therefore performed roughly 16,384 receipt reads in that one recovery phase,
in addition to the required durability writes and archive moves.

The correction loads the bounded receipt inventory only when the first
committed journal needs it, then reuses it for every committed-journal
match/conflict decision. This preserves the earlier nonterminal-recovery
error order.
Recovery can only create a receipt for the journal currently being recovered;
the journal namespace permits one durable journal per tag, so that newly
written same-tag receipt cannot validate or hide a different journal in the
same pass. The repair does not increase a timeout, reduce 64/64/2 batch
coverage, or weaken receipt, journal, archive, or yearly-synthesis checks.

## Required hosted proof

On the exact committed source, run the named fixture on Windows with the
normal nextest CI profile. It must finish before the existing 120-second
watchdog while preserving the existing 64, 128, and 130 receipt counts;
131, 67, 3, and 1 active-archive counts; removal of all expired active
archives; and oldest/newest quarantined sources in yearly synthesis. Run the
same named fixture on Linux and macOS as cross-platform regression evidence.

No local compiler, Cargo, formatter, test, runtime, parser, or network
operation was run for this diagnosis or repair.
