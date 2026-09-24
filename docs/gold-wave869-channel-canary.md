# Channel conversation canary

## Scope and purpose

The channel pipeline carries one opaque canary through a provider-backed,
already admitted conversation. It is a narrow generated-output quarantine
control: if generated text reproduces the token, the affected result is held
before it can become a preview, archive record, transcript/result artifact,
tool input, teacher correction, or channel delivery.

This guide describes the current source contract. It does not establish a
complete security boundary, prove every provider/channel combination, or mark a
release accepted. Under the current BSOD hold, local builds, formatters,
parsers, fixtures, tests, product runtimes, and GUI checks are not run; hosted
validation remains required for any integration or release conclusion.

## Canonical conversation scope

The handler-local registry keys a canary to the same canonical admitted
conversation identity used for the channel WAL session. The identity is a
versioned, length-delimited combination of:

- bound channel id;
- bound account id;
- chat id;
- optional thread id; and
- sender id.

It deliberately excludes the message body, message id, timestamp, and every
provider-owned value. A continuing accepted conversation therefore reuses its
token across turns and retries, while a distinct bound account/conversation
gets a distinct token.

The registry is process-local RAM only. It holds at most 1,024 recently used
identity/token pairs and evicts the least recently used pair at capacity. The
identity and token are not written to WAL, archives, diagnostics, provider
metadata, or persisted request state. Token creation happens only after normal
inbound admission and route selection; failure to acquire or insert it blocks
provider dispatch and returns a content-free local setup notice.

## Prompt budget effect

The token is rendered as a provider instruction in the typed prompt bundle as
Required-retention Block A. It is inserted after any existing trusted Block A
items and before the user-message boundary. If an MCP catalogue insertion slot
exists, that slot is shifted with the insertion.

Required retention means the final A–E budget must account for the canary. The
normal budgeter may reduce degradable material, but it must not silently remove
this item. A final-budget failure prevents the provider dispatch rather than
sending a request without the conversation canary. Maintainers changing prompt
assembly must preserve the shared `insert_chat_canary` ordering and use its
returned MCP slot.

## Quarantine order

Every channel provider leaf crosses a concrete completion boundary tied to the
conversation token. The channel path covers the direct provider, authorized
retry/fallback paths, loop and MCP orchestration, council, abliterated refusal
recovery, and teacher escalation. Recovery and teacher leaves receive the
optional session token and check their raw completion immediately after it is
returned, before classifying it, persisting it, or composing it into another
provider request. A teacher correction skill write happens only after that
check.

Streaming output receives an additional pre-egress guard. It holds the
unresolved suffix of a possible token match in a bounded in-memory buffer,
releases only bytes that cannot complete the token, and rechecks the held
suffix on a clean terminal chunk. A matching token, a stream error, or a
bounded-buffer failure does not release the unresolved raw suffix to live
preview collection or later content sinks.

After hooks, refusal recovery, fallback, teacher correction, and
operator-refusal presentation have settled the reply, the pipeline checks the
final text before session archival, profile/post-reply processing,
prepared-result handling, or channel egress. The shared release tail repeats
the check after `PreEgress` hooks, because a hook may replace the body; only a
clean post-hook reply may reach the live final edit, egress audit, and
transport.

## Failure behavior and maintenance constraints

When a check detects the token, it returns a content-free quarantine error. Log
records use typed phase, token digest, and output length rather than raw token
or generated text. After a token exists, provider and orchestration failures
also use the opaque post-mint failure path: callers receive a phase-labelled
quarantine error and logs retain an error digest. Quota handling preserves only
the provider name and retry delay needed for retry state; its provider body is
discarded.

Do not bypass these checks by unwrapping the underlying provider, forwarding a
raw stream to preview/collector code, or adding a new recovery/teacher/tool
leaf that consumes a completion before the optional-canary guard. A new reply
transform must be followed by a final-text guard before its first durable,
archival, tool, or transport consumer. A non-provider local notice intentionally
has no canary and remains on its established compatibility path.

## Source of truth

- `SRC/neothd/src/cli/serve_pipeline.rs` defines the canonical identity,
  bounded LRU registry, channel prompt insertion, final checks, and shared
  release tail.
- `SRC/neothd/src/cli/chat.rs` owns Required-A insertion, complete-provider
  and streaming guards, plus content-free post-mint error handling.
- `SRC/neothd/src/security/refusal_abliterated.rs` guards the local shadow and
  cloud-continuation recovery completions before they are consumed.
- `SRC/neothd/src/skills/teacher.rs` guards the teacher completion before
  refusal classification or inactive correction-skill persistence.

## Behavioral regression selection

The hosted C1a selection contains 24 named cases shared by the native matrix,
the 1,381-case lifecycle group, and the 139-case Windows regression lane.
It covers typed prompt/budget retention, per-conversation token reuse and LRU
eviction, bounded streaming/Unicode handling, sanitized provider and Council
errors, MCP/loop/Council leaves, local-shadow and teacher boundaries, and the
actual channel handler.

The handler regression builds a real small code-map snapshot and confirms the
provider sees the canary in its finalized system request. A whitespace-split
echo must stop before archive, prepared receipt, WAL content, and egress. A
second clean turn must reuse the same token and create exactly one prepared
receipt and one egress frame. JSON WAL strings are decoded and checked with
whitespace normalization, including escaped newline storage.

W877 independently reviewed the frozen implementation and these assertions.
That is static review evidence; executable acceptance is pending on GitHub.
