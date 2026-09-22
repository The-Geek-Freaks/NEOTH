# Gold Wave 189 — persisted capability-quality history

W189 adds an explicit persisted history to the read-only W188 operational
observation. The existing capability list remains available. With an existing
NEOTH home, the new commands are:

```text
neoth --output json capabilities --home <existing> quality
neoth --output json capabilities --home <existing> quality snapshot
neoth --output json capabilities --home <existing> quality history
```

The current report and snapshot producer derive content-free operational data
from a complete authenticated provider-terminal WAL prefix. Snapshot is the
only mutating action. History opens existing records without creating,
repairing, migrating or rewriting them. Stored records are local observations,
not a renewed authentication of the source WAL (`reauthenticated: false`).

Each v1 snapshot retains its capture clock, exact 24-hour/recent and preceding
seven-day/baseline windows, algorithm version, ordered terminal-metadata SHA-256
receipt and accepted sample count. The receipt covers provider, wire model,
closed workflow, invocation id, terminal timestamp, outcome and latency only.
No prompts, responses, provider error bodies or credentials are retained.
Human and JSON output expose failure counts, p90 latencies and sample counts.
They do not measure answer quality or change routing, availability or retries.

The store is `capability_quality/history-v1.json` under the capability-bound,
owner-private home namespace. Capture uses a process mutex, bound file lock,
bounded read, strict validation and atomic private-child publication. It keeps
at most 32 snapshots with at most 128 identities each and a 256-KiB file cap.
Timestamps must increase; an identical same-second observation is idempotent.
Unknown fields, future versions, unsafe paths, impossible counts/windows and
corrupt state are refused without overwriting the existing history. Namespace
bindings are checked before read/dedup returns and after atomic publication.
No scheduler or background service is added.

Eight new Hosted regression identities:

- `daemon::capability_decay::history::tests::authenticated_terminal_snapshot_persists_and_reopens`
- `daemon::capability_decay::history::tests::history_retains_the_newest_32_captured_snapshots`
- `daemon::capability_decay::history::tests::torn_wal_refuses_capture_without_overwrite`
- `daemon::capability_decay::history::tests::corrupt_or_future_store_refuses_read_and_capture_without_repair`
- `daemon::capability_decay::history::tests::held_store_lock_refuses_capture_without_repair`
- `daemon::capability_decay::history::tests::empty_authenticated_history_persists_no_false_sample`
- `daemon::capability_decay::history::tests::capture_refuses_a_missing_home_without_creating_it`
- `cli::capabilities::tests::clap_keeps_plain_list_and_quality_actions_separate`

The manual `capability-quality.yml` lane binds eight W188, eight W189 and two
Doctor tests (18 total) to the canonical source-SHA matrix. Ubuntu/Rust 1.91
uses one Cargo worker and serial exact discovery/execution; an empty or
ambiguous test filter cannot pass. Logs and selection/execute receipts are
retained. Independent source review is complete.

Hosted run `35712523037` passed all 18 selected tests on `2cef8239`. Downloaded
source/name/selection/execution receipts agree, with 18 distinct passing rows.
Core test-target check, public CLI build and reference export `35712525811`
passed on that same source; the SHA-bound generated reference is imported.
The 19 exact formatting hunks subsequently imported from Hosted Preflight
are tracked separately from behavior evidence. Preflight `35713254534` and
Code Quality `35713254483` passed on `2888e87e`. GUI, supported-platform and
release gates remain separate; no Road checkbox closes.
