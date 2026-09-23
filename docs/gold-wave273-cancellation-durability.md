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
