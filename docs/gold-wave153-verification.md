# W153 - operator-controlled transient reasoning

Road item `GOLD-LF-P1-10` remains open. This record describes the implementation
boundary being prepared for hosted validation, not completed acceptance.

The operator chooses reasoning display for one turn. Direct CLI uses
`--show-reasoning`; Main and Buddy capture a default-off selection in their
private launch envelope or authenticated daemon preflight. The consent digest
binds that selection, so later UI changes cannot alter an admitted turn.

Providers carry a separate event stream while preserving full visible
`CompletionChunk` values, including terminal text and all usage fields.
Reasoning never enters the visible response accumulator, ordinary provider
WAL payload, journal, chat history, memory, preview, Buddy recents or clipboard.
Its buffer is bounded and zeroizing; Debug representations redact raw text.
The closed terminal states are `unsupported`, `hidden`, `redacted`, `complete`
and `cancelled`. Provider output suppression also suppresses reasoning.

The CLI has a separate canary buffer and emits authenticated protocol-v3
reasoning controls with an independent contiguous sequence. Wire counters
describe delivered reasoning deltas; the metadata-only extended WAL receipt
may separately count observed provider deltas. An unavailable authenticated
leaf identity is recorded as `Unobserved`, never replaced by an invented
provider/model. Every owned success, error and cancellation path requires
an awaited terminal finalizer.

The child-process and daemon GUI routes both project reasoning into a
request-owned transient view. Terminal, cancellation, history/session switch,
stale work and handoff clear it. Daemon replay retains only a distinct
`ReasoningCheckpoint` carrying cursor/counters; all five `ReasoningState`
values remain terminal. Raw text belongs to a single live turn subscription.

The provider review findings were repaired and independently reviewed before
the provider/audit subsystem was published. Claude CLI parsing now handles
native assistant/result envelopes and retains zeroizing owners for raw bytes
and parsed string values. The separate hosted compiler repair preserves those
owners while borrowing UTF-8 views and propagates async-stream validation
failures through the stream error path.

CLI source review includes actual `dispatch_provider` tests with a recording
sink and WAL for stream-item failure and cancellation during stream opening
or a pending next item. Daemon source review includes an actual duplex attach
exchange proving that a Main-to-Buddy handoff revokes the earlier raw-text
lease while preserving text-free checkpoint continuity. Overflow admission
validates candidate counters before changing state and emits one bounded
redacted terminal after clearing retained raw text.

The remaining GUI child fixture uses the same private callback installer as
the production Main/Buddy child transport. Its final source review is approved; hosted execution remains pending. The
fixture drives Main/Buddy success, captured default-off, forged frames and
a blocked child cancelled before its success barrier is released. It asserts
one launch despite repeated dispatch, synchronous clearing, cancelled
settlement and no visible success reply on the cancellation path.

Required hosted evidence includes actual Claude-envelope parser regressions,
provider authorization/accounting preservation, dispatch-level recording-sink
and WAL regressions, actual daemon attach/cancel/overflow behavior, strict GUI
control parsing and both real Main/Buddy callback paths. The exact identities
and source hashes are bound in the canonical verification matrix. The source
manifest contains 327 inputs; this integration adds 16 native, 10 universal GUI
and two Linux/macOS callback requirements. A newly generated CLI reference is
also required for the new flag.

No local compiler, formatter, parser probe, test, fixture or product execution
is permitted under the workstation stability restriction. Source review alone
does not establish native, visual, provider or release acceptance.

Independent review receipts: CLI F3E9001C4D3641EE39F5BAE8B932EE2F155561A1BB2AE914062780389D9BB560;
daemon 978D68B5C62DB7B948A838DEC4E6FE3E2A42594B45B087BFB54B04BAEA3C2D23;
GUI child 73CC74E44531F4DF3E8E4B37AF09BB9B8A06FE5D3A89FCEE28DDF19E5B70705B.
The complete reports remain in `work/gold-20260906/wave153-next-batch/`.

**W153 hosted repair (2026-09-21):** integration 7a0cd863 passed Code Quality
35612427039. Preflight 35612427933 supplied 86 exact Rustfmt hunks in seven
files; all were imported. Core/reference build 35612427120 found one E0308:
the unobserved-identity WAL append returned its offset rather than unit.
The repair awaits the same append, discards only that success offset and
preserves error propagation and audit ordering. The 327-input manifest and
required-test hashes bind the corrected source. Fresh hosted compilation,
native/GUI execution and generated reference remain required; no Road box closes.
