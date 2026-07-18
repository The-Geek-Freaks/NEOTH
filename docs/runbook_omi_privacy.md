# Runbook — OMI conversation and native media ingest

OMI is NEOTH's most sensitive ingest surface: it can contain everyday speech,
images, and video-call frames. The complete pipeline is therefore opt-in,
authenticated, bounded, sanitizer-gated, auditable, and covered by an explicit
retention policy. `omi.enabled` defaults to `false`.

## Runtime modes

| `omi.mode` | Input | Network policy | Credential |
|---|---|---|---|
| `developer_api` | Official OMI conversation list/detail API | Local endpoint by default; public HTTPS only with `allow_cloud_api: true` | `omi_developer_api_key` (`omi_dev_*`) |
| `native_ingest` | NEOTH's authenticated live call API | Listener must be loopback or private; wildcard/public binds are rejected | `omi_ingest_token` (at least 32 bytes) |
| `both` | Developer API plus native live calls | Both policies apply; completed native calls are exported through the official OMI transcript-segment API | Both credentials |
| `legacy_memories` | Historical local `GET /v1/memories` feed | Local/private endpoint only | None |

The old local feed is compatibility-only. New integrations should use the
official Developer API, the native live-call API, or both. NEOTH does not pretend
that OMI's `/v4/listen` WebSocket is an ingest receiver: that endpoint is an OMI
client-to-server audio protocol and is not used here.

Both-mode export uses a stable `client_session_id`, so transport retries are
idempotent upstream. An upstream `discarded: true` response is also terminal:
NEOTH records a metadata-only lifecycle frame, completes the local projection,
and clears the pending effect. It does not retry the same deterministic discard
forever or lose the locally consented conversation.

## Minimal configuration

Developer API import:

```yaml
# ~/.neoth/freedom.yaml
omi:
  enabled: true
  mode: developer_api
  endpoint: https://api.omi.me
  allow_cloud_api: true
  poll_interval_secs: 30
  max_conversations_per_poll: 100
  retain_transcripts: false
  retention_days: 30
```

```yaml
# ~/.neoth/credentials.yaml (owner-only permissions)
omi_developer_api_key: omi_dev_REPLACE_ME
```

Native live ingest:

```yaml
# ~/.neoth/freedom.yaml
omi:
  enabled: true
  mode: native_ingest
  listen_addr: 127.0.0.1:8003
  audio_enabled: true
  visual_enabled: false
  video_enabled: false
  retain_transcripts: false
  summary_enabled: true
  allow_cloud_summary: false
  create_actions: true
  seed_groundtruth: true
  retention_days: 30
  max_audio_bytes_per_stream: 67108864
  max_image_bytes: 16777216
  max_connections: 4
  max_active_calls: 64
  idle_timeout_secs: 120
  allowed_uids: []
```

```yaml
# ~/.neoth/credentials.yaml
omi_ingest_token: REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES
```

The credentials can instead live in the configured keychain backend. They are
loaded through the same effective file/keychain path during startup, reload,
doctor, status, and worker restart. Secrets are reported as present/missing and
are never printed.

## Native live-call API

Every request is `POST /v1/native/calls/<call-id>/<event>` and requires:

- `Authorization: Bearer <omi_ingest_token>`
- a unique, retry-stable `x-omi-event-id`
- `x-omi-uid` when `allowed_uids` is non-empty; the UID cannot change within a call

Supported events are `start`, `audio`, `caption`, `image`, `video-frame`,
`finish`, `cancel`, and `fail`. An event ID is bound to its exact body and
semantic media headers: an exact replay is a no-op, while reuse for another
kind or payload is rejected. Active calls, tracks, events, segments, media, and
transcript bytes have hard caps. Terminal calls leave memory immediately and
their full recovery journal is replaced by a minimal idempotency receipt. Raw
audio/image bytes are never written to the journal or `views.db`. Journal and
receipt replacements are atomically created as mode `0600` on Unix; on Windows
they inherit the ACL of the private NEOTH-home parent directory.

`audio` accepts mono `audio/x-pcm-f32le` and requires `x-omi-track-id`,
`x-omi-sample-rate-hz`, and `x-omi-start-ms`. Optional speaker headers preserve
alignment. The stream byte limit is enforced before decode, end-of-stream
flushes the STT hangover buffer, and a completed call cannot be mutated.

`image` and `video-frame` accept bounded PNG, JPEG, WebP, or GIF image bytes and
require `x-omi-at-ms`; `x-omi-media-id` is optional. `video-frame` represents a
sampled frame from a video call rather than an unbounded video container. Image
and video processing are independently gated by `visual_enabled` and
`video_enabled`.

`start`, `caption`, and terminal events use bounded JSON. `finish` can supply a
title, summary, and action items; NEOTH also supports local deterministic
summarization. `cancel` and `fail` retain only the consented bounded incident
record; caller-supplied partial summaries/actions are never promoted to a
summary, task, or ground-truth row. Cloud summarization requires all of:

- `summary_enabled: true`
- `allow_cloud_summary: true`
- native or both mode
- a configured cloud provider and NEOTH's global cloud consent
- a writable audit sink for intent and result

Without that complete contract the cloud call is refused. Transcript content is
passed as quoted data, not as provider instructions.

## Sanitizer and fail-closed recovery

All external OMI text — Developer API fields, native captions, STT output,
titles, summaries, action items, speaker/source/language fields, and extracted
vision metadata — passes SC-18 before it is journaled and again before any
summary, official export, ground-truth promotion, or task creation.

A quarantine is a durable halt, not a dropped warning. NEOTH records the finding
classes and `sanitizer_halted`, performs no downstream effect for the quarantined
revision, and refuses further OMI processing until an operator reviews it:

```bash
neoth omi status
neoth omi resume --review-note "reviewed finding set and source device"
```

The review note and the prior finding set remain as durable evidence when the
halt is cleared. Restarting or reloading the daemon does not bypass the halt.

## What NEOTH stores

`views.db` contains a transactional OMI reconciliation ledger:

- conversation revision, timestamps, status, source, content hashes, and consent snapshot
- timestamp/speaker-aligned segment metadata and SHA-256 text hashes
- transcript text only when `retain_transcripts: true`
- bounded media metadata and content hashes, never raw media bytes
- mappings to OMI-derived ground-truth and kanban tasks
- sanitizer, polling, retention, and anti-reimport state

Each conversation revision and all derived projections commit atomically.
Identical revisions are strict no-ops. Updates reconcile superseded summaries,
ground-truth candidates, and tasks instead of duplicating them. Audit frames are
metadata-only and use SHA-256 digests; they do not turn the WAL into a second
transcript store.

`retain_transcripts: false` is the default. This does not mean no text-derived
memory exists: an explicitly enabled summary, ground-truth candidate, or action
task contains the sanitized derived text needed for that feature. Disable
`summary_enabled`, `seed_groundtruth`, or `create_actions` independently when
those projections are not wanted.

Those opt-outs are immediate on startup/reload, including a reload that disables
OMI or moves away from native mode. Before a candidate runtime can start, NEOTH
transactionally removes retained segment text and disabled media metadata,
summary text, every historical OMI ground-truth row, and the OMI-owned kanban
sessions/tasks. Native recovery journals are scrubbed under the same policy.
Affected projection hashes are invalidated so a later authoritative poll can
rebuild only what remains enabled. Repeating the scrub is a strict no-op.

## Retention, deletion, and anti-resurrection

The retention worker runs in every active mode and remains alive when ingest is
disabled, so disabling capture cannot freeze already accepted records past
their deadline. At `retention_days`, a conversation, its segments/media
metadata, derived tasks, and ground-truth row are deleted in one transaction.
Native idempotency receipts are then durably removed; a cleanup failure is
surfaced as a retention error. A tombstone prevents the next remote poll from
silently restoring deleted data.

Operator controls:

```bash
neoth omi status
neoth omi purge <conversation-id> --yes
neoth omi enforce-retention
neoth omi allow-reimport <conversation-id> --yes
```

`purge` is the precise OMI deletion path. Purging a native call requires the
daemon to be stopped so no private active-call state can remain in memory; its
journal/receipt is removed with the database derivatives. `allow-reimport` is
deliberately separate and confirmed because it removes the anti-resurrection
tombstone. For native sources it also requires a stopped daemon and idempotently
removes any stale journal/receipt plus Developer/native reconciliation state
before clearing the tombstone.

Every mutating `neoth omi` command writes intent/result metadata to its own
`wal/omi-operator-*.wal` segment. Conversation ids and review notes appear only
as SHA-256 hashes. `resume` and `allow-reimport` are safety-boundary reductions:
their intent frame must be durable before mutation. `purge` and
`enforce-retention` use the explicit `privacy_deletion_wins` contract: deletion
is not postponed when audit storage fails, but the command returns a loud
"committed with incomplete audit" error instead of claiming full success.
Lifecycle, summary, retention, recovery, and operator frames use the semantic
`extended/omi_lifecycle_audit` subtype. The historical top-level `0x9C
omi_action_promoted` decoder remains available for old WAL segments but is no
longer overloaded with unrelated lifecycle events.

## Reload, health, and incident handling

OMI workers remain reload-aware. A native candidate acknowledges readiness only
after journal reconciliation and a successful socket bind; a poller candidate
preflights its Developer client before it can be marked ready. The supervisor
persists `starting`, `healthy`, `disabled`, `degraded`, `failed`, or `stopped`
with its PID and bounded detail. If a valid candidate cannot start, the
supervisor attempts to restore the last known-good config and credentials. A
failed rollback is durable and visible rather than a tracing-only task exit.
Invalid changes that cross neither a privacy nor authentication boundary are
rejected before teardown and preserve the last valid runtime. A changed/removed
credential generation, a monotonic privacy reduction, or a candidate that fails
after crossing either boundary is deliberately different: the prior surface
stays stopped rather than restoring stale authority or capture, and status
exposes the failed candidate.

Privacy reductions are the exception to last-known-good rollback. A shorter
retention window, disabled transcript/summary/action/ground-truth/media/cloud
control, disabled poll/listen surface, or tighter UID allowlist is applied as a
monotonic pre-start step. If later endpoint/provider/listener readiness fails,
the scrubbed state remains scrubbed and the weaker prior runtime stays stopped;
status records the failed candidate instead of silently re-enabling revoked
capture or retention.

Use:

```bash
neoth doctor
neoth omi status --output json
neoth omi probe
neoth reload
```

`doctor` opens an existing ledger read-only. `omi status` is also read-only and
does not create `views.db`; it reports an uninitialized ledger until the daemon
or migration path creates it. Both expose config validity, credential presence,
pending projection-audit reconciliation,
worker errors, sanitizer halt state, retention errors, and ledger counts without
revealing secrets or transcript content.

The Settings → Privacy OMI card exposes the same mode, endpoint/listener,
retention, independent audio/image/video/transcript/summary/action/ground-truth
and cloud consents, credential-presence state, runtime health, pending intents,
probe, resume, retention, purge, and re-import controls. Existing secrets are
never read back into widgets. Saving the card sends one strict, at-most-32-KiB
JSON request to `neoth omi configure`: the complete surfaced settings snapshot
and any newly entered credential replacements travel together through bounded
child stdin, never through process arguments. Omitted credential fields preserve
their existing values. The desktop zeroes its private submission buffer after
the write attempt and clears the write-only credential drafts while the request
is in flight.

`omi configure` uses the shared owner-private, checksummed recovery-journal
protocol while preserving unrelated and advanced fields. The first pair
publication makes the public settings and file credential image crash-safe. For
the keychain backend, values are staged as authoritative file overrides; after
the OS-keychain writes, a second credential-only pair transaction clears those
overrides. A failure therefore reports the real finalization state: failure
before a complete keychain generation was staged, prior values restored after a
pre-publication rollback, the updated generation retained because the file
target may already be committed, or rollback failure reported explicitly. A
non-zero exit alone is not proof that every write was undone; inspect the
complete error and run `neoth omi status --output json` before retrying.

A success receipt is secret-free and binds the exact submitted settings, config
path and SHA-256 generation, credential backend/updated field names/presence,
and reload request. The desktop verifies that receipt against the file on disk
and then requires a strict `omi status` readback before replacing the last
verified UI state. Secret drafts stay cleared on failure, the non-secret draft
remains visible, and the last verified runtime status is preserved. Reload is
requested only after persisted readback and validation; if the reload request
itself fails after commit, run `neoth reload` and refresh status. A success
receipt does not claim that asynchronous worker activation has already finished.

Both the desktop custom onboarding wizard and the terminal `neoth init` flow
expose the same opt-in and consent choices. Terminal automation supplies secrets
only through `NEOTH_OMI_DEVELOPER_API_KEY` and `NEOTH_OMI_INGEST_TOKEN`; they are
omitted from argv, `freedom.yaml`, and wizard crash-resume checkpoints. Init
commits credentials before the public enabled configuration and merges only
wizard-owned YAML fields, preserving unknown and advanced operator configuration
during `--force` reconfiguration. The credential-only `omi set-credentials`
command remains available for existing automation and is still used by desktop
onboarding; it is not the Settings-card save path.

## Pre-flight checklist

- [ ] Pick one explicit mode; do not use legacy mode for a new integration.
- [ ] Put dedicated OMI credentials in `credentials.yaml` or the keychain.
- [ ] Keep native binding loopback/private and use a random 32+ byte token.
- [ ] Enable audio, images, video frames, transcript retention, actions,
      ground-truth, cloud API, and cloud summary independently.
- [ ] Confirm the retention period and test `neoth omi purge` before production use.
- [ ] Run `neoth doctor` and `neoth omi status` after startup and after reload.
- [ ] Treat any SC-18 halt as an incident requiring documented review.
