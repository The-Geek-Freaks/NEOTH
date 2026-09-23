# Gold wave 350 Dream outbox fixtures

W350 adds fixture-only coverage in `cli/dreaming_task.rs` for the bridge from
Dream phase SQLite outboxes to the home-bound append-once WAL writer.

The delivery fixture uses real `prepare_for_day` and `resume_existing_for_day`
to create all three completed phase outboxes: Light, REM, and Repair. It sends
each one through `deliver_dream_phase_audit`, then proves every receipt is
marked delivered. Replaying the same prepared day yields no pending outbox,
adds no WAL bytes, and leaves the consolidated phase effect count unchanged.

The ACK-loss fixture pauses the actual extended audit frame after it becomes
durable and before the caller receives the writer acknowledgement. Cancelling
that caller retains all SQLite outboxes as pending. After writer restart, the
same descriptor reports `ExistingExact`; only then does the delivery bridge
mark the matching row delivered. A descriptor passed with another home is
refused and leaves the original home outboxes pending.

This is test-only coverage. Production visibility and the Dream phase, WAL,
and receipt contracts are unchanged. No local Cargo, compiler, parser,
formatter, test, or runtime command ran under the BSOD hold; hosted validation
remains required.