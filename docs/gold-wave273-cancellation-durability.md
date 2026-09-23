# W273 cancellation durability fixture

The macOS cancellation fixtures in `cli/chat.rs` cover a provider that remains
pending during stream open and one that remains pending after its first stream
item. A 250-ms end-to-end deadline previously combined two independent claims:
cancellation must win over that pending provider operation, and the resulting
provider terminal must be durably acknowledged.

The two cancellation fixtures now attach the existing test-only
`TestAckGate::once(EVENT_TYPE_PROVIDER_ERROR)` to their fixture WAL writer.
After closing the turn, each waits for the gate's post-fsync/pre-ack state while
also polling the dispatch future. Reaching that gate proves the admitted
provider invocation has one durable `stream_cancelled` terminal; the dispatch
must still be pending until the test releases the acknowledgement gate. It then
uses the existing multi-second durability bounds to drain dispatch and writer
ownership.

This is test instrumentation only. Production cancellation continues to await
its terminal provider audit before exposing the cancellation error. The fixture
also verifies that the terminal and the original provider request have the same
`invocation_id`, preventing a terminal from being attributed to another call.

## Hosted Linux result — 2026-09-23

Run [35813951622](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/35813951622) on source4162c45bd4f619edd5dd684d6f3d54e4ef2f5d6a passed465/465 exact cases, including both acknowledgement-gated cancellation fixtures. The admission binds all103 source paths, matrix/lock and each actual terminal. Its SHA-256 is E461AE2716858B6895DA8EB40DAA89DBC41B80179AEE7F2D023A0C8BDB18A8D2. macOS evidence remains pending in the preserved FullCIce0 run; this Linux result is not a platform-wide claim.
