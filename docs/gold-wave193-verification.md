# W193 durable budget verification

W193 closes pause/resume budget replenishment for `neoth research`.

`provider_calls_used` is durable and reserved before each provider dispatch.
The record's `max_provider_calls` therefore applies across every attempt of the
same run. The source test `provider_call_cap_rejects_next_call_without_inner_invocation`
uses a store-backed attempt and a provider spy: after the one allowed call, the
next call fails and the spy remains at one invocation.

`wall_elapsed_ms` plus the attempt's persisted active-start timestamp are settled
at every terminal or pause boundary. Runs receive only the remaining active
duration; pause/resume never restores elapsed wall time or charges pause dwell.
The serialized record schema is version 2; every version 1 record is refused
without rewrite because it could not contain the new durable fields.
Settlement caps a minor timeout-finalization overshoot at the immutable limit so
the terminal state is still persisted and a later attempt has no time to spend.

WAL finalization errors remain failures even if a cooperative control transition
has already made a run Paused or Cancelled. Local execution remains prohibited
by the BSOD hold; the proof boundary is source inspection and hosted tests.

Daemon source tests cover durable provider reservations across pause/reopen,
cumulative active time without pause dwell, capped timeout overshoot, and byte-
preserving refusal of records missing any consumption field or using schema v1.
The CLI source test injects a WAL-finalization error after Paused and Cancelled
transitions and confirms that it is returned without changing the settled record.
