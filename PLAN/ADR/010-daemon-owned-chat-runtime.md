# ADR-010 — Daemon-owned chat runtime

- **Status:** Accepted (2026-07-29)
- **Relates to:** ADR-007, `GOLD-R4-05`, `GOLD-R4-06`, `GOLD-R4-08`,
  macOS GUI chat release blocker

## Context

Main GUI chat and Buddy currently start a fresh `neoth chat` subprocess for
each turn. Both surfaces independently own launch tokens, stdout protocol
parsing, cancellation, process containment, and teardown. Direct CLI chat owns
a third execution path.

That model has four release-blocking properties:

- Main and Buddy duplicate lifecycle and rendering logic.
- A UI window owns paid/provider work, so disconnect and explicit cancellation
  cannot be distinguished reliably.
- Every turn creates another provider/WAL/process-containment lifetime.
- macOS correctly fails closed because the GUI cannot prove complete descendant
  containment for an arbitrary chat subprocess.

Adding a `launchd`, `kqueue`, process-group, second daemon, second socket, or
localhost-TCP workaround would retain the wrong owner and add another authority
boundary. In particular, hard-aborting a provider future is not a general
cancellation contract: some adapters can leave an already-started subprocess
alive after their async stream is dropped.

NEOTH already has the stronger primitives needed for one local authority
boundary: a sole daemon WAL writer, an accepted config snapshot, a shared
provider runtime, and an authenticated local audit-RPC endpoint with private
discovery, PID/nonce binding, same-user peer attestation, and no TCP fallback.

## Decision

`neoth serve` is the sole owner of a long-lived `ChatRuntime`. Main GUI, Buddy,
and daemon-aware CLI are authenticated clients of that runtime. They start,
attach to, reconnect to, inspect, or cancel a turn by stable request ID. They
never own the provider process or the turn task.

The implementation is delivered in six bounded slices.

### 1. Transport-independent turn pipeline

Extract the existing per-turn operation into
`neothd/src/cli/chat_turn_pipeline.rs`, retaining ADR-007's named phases:

1. `build_prompt_bundle`
2. `enforce_preflight`
3. `dispatch_provider`
4. `run_post_reply_pipelines`

The pipeline:

- accepts typed request, accepted-snapshot context, cancellation state, and an
  event sink;
- emits typed events and a typed terminal outcome;
- never prints protocol frames or writes directly to stdout;
- borrows/clones a WAL writer handle but never drains or joins the writer;
- retains `ProviderCallAuthorizer` at the final resolved provider leaf;
- returns durable transcript, hindsight, and background-job identifiers when
  those effects exist.

Direct CLI remains an adapter around this pipeline. It owns and drains its
standalone writer exactly once and renders typed events to the current human or
protocol-v2 stdout formats.

### 2. Daemon-owned runtime

Add one `ChatRuntime` to the existing daemon:

- one stable per-boot daemon ID;
- bounded active-turn semaphore;
- a registry keyed by client-generated UUIDv7 request ID;
- canonical request hash and same-boot idempotency;
- strictly increasing per-request sequence numbers;
- a compact durable request ledger with a unique `(boot_id, request_id)` key;
- bounded delta replay plus separately retained terminal receipts;
- one daemon-owned task per admitted turn;
- cooperative cancellation and ordered shutdown drain;
- the existing sole daemon WAL writer and accepted reload snapshot.

Repeating a request ID with the same canonical request hash returns the original
start receipt. Reusing it with different intent is a conflict. A daemon restart
returns `BootChanged`; NEOTH does not claim cross-boot exactly-once execution
and never silently repeats a potentially paid call.

Replay payloads may be evicted, but the compact request row, canonical hash,
admission receipt and terminal state may not be evicted while that daemon boot
can still be addressed. The durable unique row is the idempotency authority;
an in-memory cache is only an accelerator. Losing or corrupting that authority
is fail-closed and cannot turn a retry into another provider call.

Client disconnect only detaches a subscription. It does not cancel a turn.

### 3. Existing authenticated local endpoint

Chat uses the existing authenticated audit-RPC endpoint. No second socket or
TCP listener is permitted.

Add strict, `deny_unknown_fields` routes:

- `POST /chat/v1/consent/preflight`
- `POST /chat/v1/consent/decide`
- `POST /chat/v1/start`
- `POST /chat/v1/attach`
- `POST /chat/v1/cancel`
- `POST /chat/v1/status`
- `POST /chat/v1/active`

Every connection repeats endpoint ownership, daemon PID, endpoint nonce, peer
identity, and per-boot bearer validation. Bearer and consent secrets never
appear in stream frames or lifecycle WAL payloads.

The current short RPC timeout remains on bounded ingress. A held chat
attachment has its own semaphore and bounded per-frame write timeout; a slow
subscriber is detached without canceling the turn. Held streams may not starve
health, audit, cancel, or shutdown RPCs.

The held attachment wire contract is fixed, not implementation-defined:

- every start, attach, status and cancel request carries the `expected_boot_id`
  obtained from the freshly attested endpoint sidecar/PID/nonce;
- an expected boot mismatch returns `BootChanged` before request lookup,
  consent consumption, or effect admission;
- attach returns `HTTP/1.1 200`, `Content-Type: application/x-ndjson` and
  `Connection: close`, with neither `Content-Length` nor chunked encoding;
- each line is one strict UTF-8 JSON envelope terminated by `\n`, bounded by a
  named `MAX_CHAT_FRAME_BYTES`; accumulated response/replay remains subject to
  the existing 32 MiB response ceiling;
- the new chat client uses a bounded incremental line parser and accepts
  fragmented reads without buffering an unbounded response;
- every frame has a bounded write deadline;
- a terminal envelope is flushed and followed by orderly connection close;
- EOF before terminal, oversized lines, invalid UTF-8, malformed JSON, unknown
  fields, sequence gaps, and a changed sidecar/PID/nonce are visible typed
  failures and may never synthesize success.

One-shot chat RPC responses retain explicit bounded `Content-Length`. This
long-lived close-delimited parser is chat-specific; it does not weaken or
silently change the existing audit client, which rejects chunked responses and
expects a bounded content length.

### 4. Typed lifecycle and receipts

The stream uses authenticated typed envelopes containing:

- protocol and daemon boot ID;
- request and session IDs;
- a strictly increasing sequence number;
- one of `Accepted`, `PhaseChanged`, `Delta`, `Notice`, `ProviderDone`,
  `BackgroundAccepted`, `CancelRequested`, or `Terminal`.

Start and terminal receipts bind the canonical request hash, request/session
IDs, final sequence, response hash, provider/model, token usage, relevant
durable row/job IDs, and WAL receipt. Replay-to-live handoff must be gap-free
and duplicate-free. A lagged client receives a canonical snapshot/replay-limit
error, never silent data loss.

The daemon writes one content-free `ChatTurnLifecycle` extended WAL subtype for
`accepted`, `cancel_requested`, and `terminal`. Provider intent/result auditing
continues at the provider boundary. Raw prompts, bearer tokens, and consent
secrets are forbidden in lifecycle records.

### 5. Cancellation semantics

Cancel is idempotent and returns `Accepted`, `AlreadyRequested`,
`AlreadyTerminal`, `UnknownRequest`, or `BootChanged`.

`Accepted` means the cancel intent is durable and the runtime starts no new
external effects. It does not claim that an in-flight effect has stopped.

Every external-effect leaf consumes a request-bound effect-admission permit.
Permit admission and cancellation linearize through one per-turn gate:

1. an effect acquires the gate, revalidates request/config/authority generation,
   durably writes its intent and reserves a `Preparing` slot without starting
   the external effect;
2. immediately before the adapter's bounded start handshake, it reacquires the
   gate. A still-open gate performs that handshake while holding admission and
   atomically classifies the slot `Started`; a closed gate classifies it
   `Aborted` without the effect;
3. cancel acquires the same gate after any in-progress bounded start handshake,
   closes future admission, aborts every remaining `Preparing` slot, durably
   writes `cancel_requested`, and only then returns `Accepted`;
4. an effect classified `Started` before that linearization may drain to its
   safe boundary, while no effect can physically start afterward.

The adapter start handshake has a strict deadline and owns the exact moment an
HTTP request is committed, a provider transport is invoked, or an OS child is
spawned. Slow response/drain work happens after the gate is released. A failure
to persist the effect intent aborts that preparation. A failure to persist
`cancel_requested` leaves admission permanently closed and moves the turn to a
fatal audit-unavailable state; it never reopens admission and never returns
`Accepted`.

A start-handshake timeout is `Aborted` only when the adapter proves no external
commit occurred. If commitment is possible or unknowable, classify the slot
`Started`/`Indeterminate`, keep later admission closed, and reconcile or drain
that exact effect. Timeout may never be used to pretend the effect did not
start.

An atomic flag checked outside this gate is insufficient because it permits a
check-then-cancel-then-effect race.

- Before provider dispatch, cancellation prevents the call.
- During a provider/tool effect, stop publishing new user-visible deltas and
  drain that effect to an adapter-proven safe boundary.
- Start no fallback, MCP/tool, naming, post-reply, or other external effect
  after cancellation.
- An already accepted durable background job keeps its own lifecycle and job
  ID; canceling the chat does not forge cancellation of that job.
- Emit terminal `Cancelled` only after the current effect reaches a safe
  boundary.

Adapter-native process termination is a separate, per-adapter contract. A
generic `JoinHandle::abort`, stream drop, or UI-process kill is not accepted as
proof of cancellation.

### 6. Surface migration and shutdown

Main GUI and Buddy use one shared `DaemonChatBridge`. The bridge owns local RPC
connections and reconnect state, not the turn. Both surfaces may attach to the
same request without creating another provider call.

- Send performs start-or-attach.
- Stop sends explicit cancel.
- Window close detaches and zeroizes local sensitive UI state, but neither
  cancels a turn nor shuts down the daemon.
- Reopening a surface can attach after the last observed sequence.

Once both GUI paths use the bridge, delete the GUI-owned chat subprocess
supervisor, duplicated parsers, worker barriers, launch envelopes, and
control-token-derived request ownership.

CLI uses daemon RPC when the exact selected home has a valid live daemon. It
uses direct mode only when daemon absence is proven. A live daemon with failed
endpoint/PID/nonce/bearer validation is a fail-closed error, not permission to
open a competing provider runtime or WAL writer.

The absence decision is atomic with runtime ownership. Direct CLI and daemon
startup share one owner-private, home-scoped OS file lease:

1. daemon startup acquires the runtime lease before its PID lock, WAL writer or
   provider and holds it for the daemon lifetime;
2. a CLI that initially sees no daemon makes a bounded nonblocking attempt to
   acquire the same exclusive lease;
3. if the lease is busy, CLI waits boundedly for the owner's endpoint Ready
   publication, then fully attests and attaches to that exact daemon; if no
   valid endpoint appears, it returns typed `RuntimeBusy`/Repair and never
   enters direct mode;
4. only after CLI actually acquires the lease does it repeat the absence and
   stale-metadata checks under exclusion; a second proven absence may enter
   direct mode;
5. direct mode holds the lease through terminal receipt and standalone WAL
   writer join;
6. platform-unit activation honors the lease and may wait/report Busy, but may
   not start a daemon beside a direct owner.

All paths acquire the runtime lease before the PID lock; no inverse ordering is
permitted. An unavailable/corrupt lease is fail-closed. OS process death
releases the kernel lock, while the next owner validates and recovers any stale
metadata before use.

The packaged product must also own daemon bootstrap. A GUI-only clean install
cannot assume that the operator already ran `neoth serve`. Native packages
install the platform user-session launcher (Windows Task Scheduler/startup
registration, macOS LaunchAgent, Linux systemd-user unit). The product launcher
starts or activates that registered unit through a single-instance,
request/receipt-bound command and waits for authenticated PID/nonce/peer/bearer
readiness before opening chat. GUI and Buddy may request activation, but they
do not own the daemon process lifetime. A missing, stale, or failed unit is a
typed Repair state; spawning an untracked raw `neoth serve` child is forbidden.
Install, upgrade, rollback, repair, and uninstall must transact this unit with
the exact CLI/GUI version set and preserve operator data.

The unit is bound to the absolute installed `neoth` binary and the authoritative
`NEOTH_HOME`; it never inherits an ambient working directory or a second home.
Activation follows one state machine:

1. a valid PID lock plus freshly attested endpoint reuses the exact daemon;
2. proven absence activates the registered user unit once;
3. concurrent launchers wait for the same PID-lock/Ready receipt rather than
   starting another process;
4. a lock without a valid matching endpoint, a wrong-home daemon, version
   mismatch, timeout, crash loop, or failed authenticated health check enters a
   typed Repair state and cannot fall back to a competing raw child;
5. the platform manager owns bounded crash restart, while the PID lock remains
   the single-instance authority;
6. upgrade/rollback replaces the unit and binaries transactionally, then proves
   the restarted daemon's exact version/home/boot receipt before success;
7. uninstall disables/removes the unit and waits for a clean daemon shutdown
   without deleting operator data.

Rejecting `launchd` above means rejecting it as a per-turn containment hack.
Using a LaunchAgent as the long-lived macOS user-daemon supervisor is the
selected zero-friction lifecycle.

Daemon shutdown order is:

1. close new chat admission;
2. stop accepting new attachments;
3. mark active turns cancel-requested;
4. drain every admitted effect to a safe boundary;
5. emit each turn's terminal receipt and join every turn task;
6. release provider roots;
7. drain/drop the sole WAL writer last.

Normal shutdown cannot return after merely reaching a safe effect boundary;
the turn must terminalize and its owner task must be joined while provider and
WAL roots still exist. If an adapter cannot reach a safe boundary, shutdown
remains visibly `Cancelling`/`Draining`. A forced OS termination is crash
recovery, not a successful shutdown receipt.

## Required acceptance evidence

The feature is not complete until tests prove:

- direct CLI human and protocol-v2 output compatibility;
- accepted config/provider-route and one-time consent binding;
- same-request idempotency and conflicting-intent rejection;
- after more completions than replay/LRU capacity, retrying the oldest request
  launches zero additional provider calls and conflicting-intent rejection
  still holds;
- new-boot non-replay;
- same-user/PID/nonce/bearer checks on every reconnect;
- no bearer or consent secret in frames/WAL;
- sequence, replay/live handoff, response-hash, and terminal-receipt integrity;
- fragmented NDJSON reads, oversized/malformed/truncated frames, EOF before
  terminal, old boot IDs and sidecar rotation all fail visibly;
- a stream may outlive the old short RPC timeout;
- slow attachments cannot starve one-shot RPC;
- Main and Buddy observe one turn and cause one provider call;
- a barrier pauses direct CLI after its first absence observation while GUI
  activation races it; the shared runtime lease proves exactly one runtime/WAL
  owner and one provider call, with the loser attaching or failing closed;
- the daemon-start winner holds the lease before endpoint publication while CLI
  observes absence; CLI waits for Ready and attaches without waiting for daemon
  termination or acquiring its lifetime lease;
- close detaches, Stop cancels, and reopen reattaches;
- cancellation starts no new effect and does not orphan an unsafe-to-abort
  provider subprocess;
- cancel/effect barrier tests prove the durable cancel linearization wins every
  check-then-effect race at provider, fallback, MCP/tool, naming, post-reply and
  background-launch boundaries, including pauses before and during the bounded
  start handshake plus cancel-WAL failure;
- a child-backed provider fixture captures its PID, cancels during streaming,
  admits no later effect, drains the child, waits/reaps it, and only then emits
  terminal `Cancelled`;
- accepted background jobs remain durable and discoverable;
- shutdown terminalizes and joins chat before provider/WAL teardown;
- a clean packaged GUI launch activates and authenticates the platform-owned
  daemon without a prior manual `neoth serve`;
- the platform-unit matrix covers default and custom homes, two concurrent
  launchers producing one daemon, stale lock/wrong home/crash loop entering
  Repair with no raw-child fallback, bounded crash restart producing a new boot
  and `BootChanged`, exact binary/home/version proof across upgrade and
  rollback, and standard-user uninstall preserving operator data;
- macOS GUI and Buddy chat work without invoking subprocess containment;
- source invariants find no GUI `OwnedChatChild::spawn`, no GUI construction of
  `neoth chat`, and no duplicated Main/Buddy chat parser.

The final macOS clean-machine release journey must exercise daemon
install/activation/readiness plus real GUI send, stream, explicit cancel,
close/detach, reopen/reattach, Buddy handoff, repair and uninstall using the
packaged app. Equivalent Windows and Linux journeys prove their platform-owned
user-session launchers. The macOS journey also starts a deliberately long
durable background job, closes the last window, reopens, and retrieves the same
job ID and final result.

## Consequences

Positive:

- removes the macOS chat blocker instead of weakening containment;
- gives GUI, Buddy, and CLI one execution, consent, audit, and cancellation
  contract;
- makes reconnect/resume and background work durable across UI lifetimes;
- removes duplicate provider/WAL/process ownership.

Negative:

- requires a staged extraction of the large current chat path;
- held-stream RPC needs separate capacity and timeout handling;
- generic cancellation may remain visibly `Cancelling` while an adapter drains
  an effect that cannot yet be terminated safely.

Operator-facing:

- closing a window no longer means Stop;
- explicit Stop is durable and truthful;
- an active turn can be resumed from another NEOTH surface;
- no additional service, port, verifier, or manually installed dependency is
  introduced.

## Alternatives considered

- **Add macOS process containment to the GUI child path.** Rejected: it retains
  UI-owned work and does not solve reconnect, duplicate paths, or generic
  subprocess cancellation.
- **Start another chat daemon/socket.** Rejected: duplicates authentication,
  provider, WAL, configuration, and shutdown authorities.
- **Use unauthenticated localhost HTTP/WebSocket.** Rejected: weakens the
  existing same-user, PID/nonce, private-discovery, and no-TCP boundary.
- **Hard-abort all provider tasks on Stop.** Rejected: dropping an adapter
  future is not proof that its OS child or remote effect stopped.
- **Keep separate Main and Buddy clients.** Rejected: surface parity requires
  one bridge and one typed event projection.

## References

- `PLAN/ADR/007-chat-turn-pipeline-module-boundary.md`
- `SRC/neothd/src/cli/chat.rs`
- `SRC/neothd/src/cli/consent_challenge.rs`
- `SRC/neothd/src/daemon/audit_rpc/`
- `SRC/neothd/src/daemon/serve.rs`
- `SRC/neothd/src/cli/serve_tasks.rs`
- `SRC/neothd-gui/src/chat_child_supervisor.rs`
- `SRC/neothd-gui/src/main.rs`
- `PLAN/ROAD_TO_1_0_GOLD.md`
