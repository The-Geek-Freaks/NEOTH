# Conversational voice backend

The conversational backend retains one authenticated voice conversation in
the daemon. The implementation is feature-gated and has no public CLI command
or GUI entry point in this batch. The implementation and validation state are
recorded in `docs/verification/gold-wave2274-2282-conversation-backend.json`.

## Local authenticated lifecycle

The public safe `ConversationBridge` uses the existing local authenticated
audit-RPC transport. It projects bounded request, subscription, availability,
progress, event, and error values; it does not expose audio, transcript text,
credentials, sealed provider authority, WAL handles, microphone capability, or
the retained session. Provider consent exposes safe provider route names and
endpoint origins so the caller can present an informed decision.

1. `availability` reports feature state, microphone permission state, busy
   state, and the last actual microphone-open result. Before an actual open it
   does not infer a device verdict.
2. `preflight` establishes the request-bound lifecycle and may return a local
   microphone confirmation prompt. It does not open capture or pre-authorize
   STT, provider, or TTS egress.
3. `decide_microphone` accepts `AllowOnce`, `AllowAlways`, or `Deny` for the
   matching pending microphone request. `start` consumes the admitted local
   capability: durable microphone-open intent, the one audio permit, capture,
   observed readiness, then the opened or failed durable result.
4. A qualified nonempty STT result can cause a separate provider confirmation.
   `decide_provider` takes the provider request ID and decision. A denial ends
   that recognized provider turn and leaves microphone capture available for a
   later turn.
5. `attach` replays bounded ordered progress after a requested sequence; a
   stale cursor is a typed replay-gap outcome. `stop` requests owned
   cancellation and settlement. `revoke_microphone` revokes the matching local
   microphone admission and drives the same retained lifecycle to a terminal
   state.

Every request carries the schema version, expected daemon boot ID, and caller
request ID. Follow-up operations also bind subscription ID, session ID, Buddy
origin, and expected generation. Responses and stream frames echo the boot
binding, subscription, generation, and sequence. These checks prevent an old
client, another session, or a prior generation from controlling a replacement
conversation.

## Ownership and settlement

`ConversationRegistry` owns the active lifecycle and bounded replay history.
`ConversationOwner` owns opening, cancellation, and cleanup. The direct
crate-private `conversation_gui_bridge` adapts retained conversation work to
the existing GUI-chat runtime without routing the daemon through self-RPC.
The public bridge remains a projection boundary.

Stopping, disconnecting a post-write start, and failure paths remain
cancellation-coupled: retained work is settled and joined before its slot can
be reused. The stream supervisor settles an authorized turn before cleanup;
functional stages, supervisor work, and cleanup work are drained in order.
An abort, closed channel, or lost reply is not treated as a successful
settlement.

## Feature and evidence boundary

Without `live-audio`, the backend reports typed unavailability; it does not
fabricate a successful runtime. The live-audio build contains the CPAL capture,
VAD/STT, ordered audio ownership, TTS/playback, and session facade. The frozen
assembly includes source-only test identities: 50 portable and 33
audio identities. They are registrations, not evidence that tests, hosted
validation, local runtime, microphone/speaker devices, UI, or release flows
have run.

No GUI entry is included. Hosted compilation, tests and device qualification remain
separate acceptance gates.
