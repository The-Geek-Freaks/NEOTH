# W164 — response-bound quality feedback

Status: integrated source independently reviewed; GitHub-hosted checks remain
required. GOLD-LF-P2-28 remains open. No local executable validation is allowed
under the workstation stability hold.

## Response identity and lifecycle

The successful terminal producer issues a random opaque response ID, bound to
its exact terminal session. Prompt event IDs, response text, provider metadata
and displayed history never serve as response authority. The direct CLI issues
only after its writer drain succeeds. The long-lived daemon uses an ordered
WAL flush request, acknowledged after sync_data, and keeps its writer open.
Incognito performs no feedback-store access and publishes no target. Failure
to issue a feedback target leaves the completed response explicitly unavailable
for feedback; it never reissues the provider request.

The GUI control carries a bounded authenticated v3 response_feedback_target
record after the existing done boundary. The daemon RPC, GUI protocol and public
bridge transport the same terminal-issued identity. Each consumer must preserve
its request and surface binding, including after a session change or a late
callback. No adapter may mint a replacement for a missing identity.

## Private reversible selection

The existing feedback module owns a private bounded projection with at most
128 response targets. It persists only opaque identity/session bindings,
fixed selected signal, revision and timestamps. Set supports needs-correction
or not-helpful. Selecting a different signal replaces the previous selection;
Remove clears the active signal. Repeating the same operation at the current
revision is unchanged. A stale expected revision cannot overwrite a newer
selection. Active feedback is never evicted for a new response; a full active
store makes new target issuance unavailable.

No prompt, response, freeform note, rating stars or provider content enters the
projection. Creation, lock, bounded read and atomic replacement use the same
private directory capability. Malformed, foreign and missing bindings fail
before a feedback mutation, and failed persistence is never a successful receipt.

## CLI, Chat and Buddy

The CLI exposes feedback response status/set/remove with the explicit response
and terminal session. Mutations require --revision; the session is a pair check,
not a claim of authentication. Chat and Buddy provide the same fixed actions
for the current completed response. They require an exact mutation receipt and
fresh status readback before showing success, with one operation in flight.
Retained historical GUI transcripts remain read-only and have no inferred
feedback target. IDs are kept out of Slint labels, clipboard and history text.

The active projection feeds a separate bounded count into the existing
operator-reviewed self-dev proposal path. The legacy G-03/0xBB follow-up tone
heuristic remains independent, and no proposal is automatically accepted.

## Acceptance boundaries

Focused regression requirements cover fresh-home setup and redirected storage,
CAS and concurrent mutation, replacement/removal, capacity, Incognito zero I/O,
terminal issuance order, failed writer completion, strict closed transports,
exact daemon-to-CLI/GUI forwarding, and real Chat/Buddy callbacks with receipt
and readback. The FIFO flush must leave the daemon writer usable and propagate
closed/sync failures. The macOS custom callback catalog gains one W164 fixture.

Working evidence is retained in work/gold-20260906/wave164-response-feedback.
A source review is not compilation or executed behavior evidence. Native tests,
rendered layout and accessibility require their own Hosted acceptance. No Road
checkbox closes from this document or the existence of test source.

## Integrated source admission

The integrated source set contains 24 implementation/fixture paths and 35
regression entries. Independent scoped reviews cover core persistence,
producer/CLI, writer/daemon transport, GUI/bridge/callbacks and the top-level
feedback navigation mapping. Three CRLF-to-LF changes are recorded separately;
historical review hashes remain unchanged. The admission adds the profile cron
consumer and parity mapping to the earlier 22-path owner inventory.

The canonical verification manifest now admits 367 source inputs: 378 universal
native test identities, three Windows-only and four Unix-only native identities,
71 universal GUI identities, 15 Linux/macOS component callbacks, and the existing
seven optional-adapter cases. The macOS custom harness catalog contains 20 names.
The public GUI integration test uses its existing exact JUnit class mapping.

The remaining W165 repairs preserve authenticated reasoning controls and exact
terminal identity. GUI fixtures release the runtime before waiting for its last
WAL writer, and the MCP retained-deny fixture permits the initial real tool call
before asserting no additional denied call. Native reruns must confirm these
repairs. A FIFO sync acknowledgement does not close W141's physical deadline.