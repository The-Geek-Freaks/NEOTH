# W153A - provider reasoning events and metadata-only audit

This subsystem adds the provider event and audit foundation for
`GOLD-LF-P1-10`. The complete CLI, Main, Buddy and daemon integration remains
a separate working batch; the Road item remains open.

`ProviderEventStream` carries full visible `CompletionChunk` values and a
separate reasoning plane. Legacy providers retain their existing stream
contract and explicitly report unsupported reasoning. The adapter preserves
usage-only intermediate chunks and emits a final text delta exactly once.
Authorization, retained token limits, dispatch identity, accounting,
compaction, fallback and circuit-breaker decorators forward the new event
plane without adding another provider authorization or transport start.

Claude CLI parsing accepts its native `assistant.message.content[]` and
`result.result` records. Result text is a fallback only when no earlier
visible text was emitted. Typed thinking and redacted-thinking blocks remain
separate from visible text. The raw line bytes, decoded frame and successfully
parsed JSON values are cleared through zeroizing owners; Debug redacts
reasoning values and parse errors do not quote raw frames. Stream cancellation
and its operator-visible terminal are owned by the consumer; a dropped
provider stream cannot emit a later event.

The new extended WAL subtype `reasoning_stream_audit_v1` (`0x2D` under the
extended event type) stores bounded metadata only. Authenticated leaf identity
is distinct from `Unobserved`; the latter has zero counters and cannot claim
successful completion. Strict decoding rejects unknown fields, invalid state
combinations and oversized receipts. Model identifiers remain opaque bounded
strings, including valid Windows model paths.

Independent provider and codec review records and exact hashes are retained
in `work/gold-20260906/wave153-next-batch/`. The canonical source manifest and
test matrix bind the admitted provider/audit files and their regression
identities. Concurrent CLI, daemon and GUI edits are excluded.

All executable checks run on GitHub-hosted runners. Source review is not
native, live-provider, UI or release acceptance. Fresh hosted formatting,
compilation and the listed regression tests remain required for this source.

## Hosted compiler repair

GitHub core/reference run 35608152765 on 772a6019 failed before producing
a reference. The eight compiler diagnostics and unused-binding warning are
repaired in three provider files. The UTF-8 view now borrows a live zeroizing
byte owner; async-stream failures propagate through the stream error path;
terminal chunks move once and preserve text and usage. The independent repair
review and complete failed log are retained in
`work/gold-20260906/wave153-provider-compile/`. A new hosted build must verify
these repaired sources. Preflight 35608485779 and Code Quality 35608485777
passed on the earlier formatting commit 96b97515 only.
