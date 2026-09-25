# n8n localhost HTTP API

NEOTH exposes a loopback-only HTTP API so n8n (or any local workflow
tool that can hit `http://127.0.0.1:9744`) can drive NEOTH without
any cloud round-trip. Default OFF — the operator opts in explicitly.

Spec: [`PLAN/SPEC_n8n_localhost_api_2026-05-23.md`](../PLAN/SPEC_n8n_localhost_api_2026-05-23.md).
Companion: [cron-vs-n8n.md](cron-vs-n8n.md) for the "which scheduling
surface should I use" decision.

---

## Enable + token

```yaml
# ~/.neoth/freedom.yaml
n8n_api:
  enabled: true
  port: 9744            # default; only change if 9744 collides locally
  token_path: null      # null = ~/.neoth/n8n_api_token (mode-0600)
```

On first daemon boot with `enabled: true`, NEOTH mints a 32-byte
random secret + writes the 43-char base64url-NOPAD encoding to
`~/.neoth/n8n_api_token`. Subsequent boots reuse the existing token
(restart-stable so n8n workflows don't need re-rotation per restart).

Read the token once + paste it into your n8n credentials:

```bash
cat ~/.neoth/n8n_api_token
# example: ZmF rR2x...43 chars total
```

---

## Auth + safety

Every request needs a bearer header:

```
Authorization: Bearer <token-from-~/.neoth/n8n_api_token>
```

Enforcement layers (all active by default):

| Layer | Behaviour |
| :-- | :-- |
| **Bind** | `127.0.0.1:9744` only — never `0.0.0.0`. |
| **Accept-time** | Non-loopback peer IP refused before any handler runs. |
| **Audit-before-auth** | Every attempt — refused OR successful — lands as a 0x39 WAL frame BEFORE the bearer check. Replay-safe. |
| **Constant-time compare** | Token check uses `constant_time_token_eq` so leakage via timing-side-channel is bounded. |
| **5-strike cooldown** | 5 failed bearer attempts from one source-IP triggers a 60-second silence window for that source. |
| **256 KiB body cap** | Body buffer rejects oversize payloads before JSON parse touches the bytes. |

---

## Endpoints

| Path | Method | Body | Returns |
| :-- | :--: | :-- | :-- |
| `/api/health` | GET | — | `{version, uptime_secs, status}` |
| `/api/recall` | POST | `{query, limit?}` | `{hits: [...], total}` (routes through `memory::ctx::search`) |
| `/api/stats` | GET | — | `{events_total, provider_requests, channel_inbound, channel_outbound}` |
| `/api/memory/drift` | POST | `{limit?}` | `{drifting: [...], imminent_count, at_risk_count, stable_count}` |
| `/api/proactive/proposals/pending` | POST | `{limit?, min_age_secs?}` | `{pending: [...], total}` (pending proposal metadata only) |
| `/api/calendar/agenda` | POST | `{timezone, day, limit?}` | Supported local-day events, conflicts and explicit truncation |
| `/api/paperless/findings/recent` | POST | `{since_unix, limit?}` | `{coverage, since_unix, findings: [...], total, truncated}` |
| `/api/memory/save` | POST | `{kind, body, tags?}` | `{stored, bytes}` (writes a RAW_TEXT WAL frame) |
| `/api/provider/call` | POST | `{prompt, system?, model?, incognito?}` | `{completion, model}` (authenticated operator communication profile + authorized provider leaf) |
| `/api/channel/send` | POST | `{channel, recipient, text}` | `{queued}` (writes a CHANNEL_EGRESS WAL frame; adapter dispatch via the broker) |

`/api/memory/drift` reads the existing `views.db` projection with a read-only
SQLite connection. `limit` defaults to 20 and is capped at 100; zero returns
only aggregate counts. Wrong JSON types are `BadRequest`. Rows include memory
text, so a scoped token needs `recall:read`; `stats:read` alone is insufficient.
The handler does not create or migrate a database. A missing projection returns
`StoreUnavailable` (503). The usual HTTP request audit still applies.

The inactive `memory_decay_report` starter uses this route. Starters whose
adapters remain unavailable disclose that limitation; their presence
in the thirteen-workflow catalog does not prove those routes work. Use an n8n
HTTP Header Auth credential containing the appropriate bearer token.

`/api/proactive/proposals/pending` requires the separate `proposals:read`
scope. It reads the existing proposal files without creating a missing store,
which returns an empty list. Recognised corrupt records return `UpstreamError`.
Only Pending proposals are returned, sorted by their existing ID order. The
default limit is 20, capped at 100; `total` counts matches before truncation.
`min_age_secs` defaults to zero and uses an inclusive minimum age.

Each summary contains `id`, `kind`, `title`, `generated_ts_unix`, and `status`.
Draft configuration, rationale and operator notes stay out of this API. The
inactive `proposal_review_reminder` starter selects proposals at least 24 hours
old. Reading a reminder does not approve or apply a proposal. Tokens for recall
or statistics do not grant access to this endpoint.

`/api/calendar/agenda` requires `calendar:read` and a separate account-bound
CalDAV read grant, managed with `neoth calendar read-access grant`, `status`
and `revoke`. The grant binds the configured collection, username and password;
changing any of those values requires a new grant. This route reads the API
instance's credentials without environment fallback. Revocation denies later
read admissions; a bounded read already admitted may finish.

Supply an IANA timezone such as `Europe/Berlin`, a day such as `2026-09-25`,
and an optional limit from 1 to 100 (default 20). Supported UTC/offset and
all-day events are projected onto that local day. Recurring, floating and TZID
events fail explicitly instead of producing an incomplete agenda. The inactive
`calendar_morning_agenda` starter includes an editable `calendarTimezone`.

`/api/paperless/findings/recent` requires `paperless:findings:read` and reads
only the current API instance's recorded threat quarantines. `since_unix` is
an inclusive Unix timestamp in seconds. `limit` defaults to 20 and must be
between 1 and 100. Results are newest first with deterministic tie ordering;
`total` counts all matches before truncation. Unknown request fields, including
a supplied `home`, are rejected.

Records contain `occurred_unix`, `document_id`, `ocr_source`, `raw_input_hash`
and fixed `finding_kinds`. OCR text and sanitizer marker patterns are omitted.
Only `prompt_injection_marker` and `persona_override_attempt` are retained.
The coverage value is always `recorded_quarantines_only`: this is not a scan
of historical documents or an inventory of every sanitizer diagnostic.

The CLI and webhook record these findings before returning a threat quarantine.
A storage failure prevents a vault write; the webhook returns a fixed 500
diagnostic. The private store has a hard cap of 1,000 records and 1 MiB, with
no automatic eviction. A missing store reads as empty without creation;
corrupt existing evidence returns `StoreUnavailable` (503). Reaching capacity
requires local operator attention and is not silently treated as successful
recording.

The inactive `paperless_threat_alert` starter reads the last 15 minutes with
a limit of 20. Its name does not imply alert delivery: it only reads metadata.
It has no delivery cursor or replay guarantee; missed runs and truncated
responses require operator review.

---

## Envelope

Every response uses the same envelope:

```json
{
  "ok": true,
  "data": { /* endpoint-specific */ },
  "request_id": "01950e2c-..."   // UUID v7, time-ordered for WAL replay
}
```

Errors:

```json
{
  "ok": false,
  "error": {
    "code": "Unauthorized | PermissionDenied | NotFound | BadRequest | UpstreamError | NonLoopback",
    "message": "human-readable cause",
    "hint": "operator-actionable next step"
  },
  "request_id": "01950e2c-..."
}
```

HTTP status mapping: `Unauthorized=401`, `PermissionDenied=403`,
`NotFound=404`, `BadRequest=400`, `UpstreamError=502`,
`NonLoopback=403`.

---

## Example: /api/health

```bash
TOKEN=$(cat ~/.neoth/n8n_api_token)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9744/api/health
```

```json
{
  "ok": true,
  "data": { "version": "1.0.0", "uptime_secs": 312, "status": "ok" },
  "request_id": "01950e2c-..."
}
```

## Example: /api/recall

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "the build failure from Tuesday", "limit": 5}' \
  http://127.0.0.1:9744/api/recall
```

## Example: /api/memory/save

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"kind": "fact", "body": "Prefer terse replies", "tags": ["tone","preference"]}' \
  http://127.0.0.1:9744/api/memory/save
```

## Example: /api/provider/call

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"prompt":"Summarize the deployment status","system":"Return valid Markdown","incognito":false}' \
  http://127.0.0.1:9744/api/provider/call
```

After bearer authentication, this endpoint is bound to the local `operator`
communication subject; request JSON cannot select or spoof another subject.
NEOTH compiles the same typed presentation-only layer used by chat, then adds
the caller's explicit `system` layer through the canonical prompt composer. The
resulting final system prompt is part of the concrete provider request and its
cost/consent authorization binding.

Automation prompts may be machine-generated, so this endpoint never records
them as communication-profile evidence. Existing request bodies remain valid:
`incognito` defaults to `false`. Set it to `true` when the workflow must perform
zero communication-profile reads; even corrupt profile state is not opened in
that mode. The provider lifecycle stays content-free/auditable and is marked
`incognito: true`.

---

## Bootstrap workflows

NEOTH ships 3 example n8n workflows under `SRC/neothd/assets/n8n_workflows/`:

| File | Schedule | What it does |
| :-- | :-- | :-- |
| `daily_summary.json` | 21:00 every day | Today's activity → 5-bullet summary via `/api/recall` + `/api/channel/send` |
| `morning_brief.json` | 07:30 weekdays | Open threads → motivating brief |
| `weekly_stats.json` | Sunday 18:00 | Snapshot of cumulative `/api/stats` counters → markdown archive → channel summary |

All ship inactive. Before enabling a workflow, configure its **Operator
Configuration** node and bind an **HTTP Header Auth** credential on each NEOTH
HTTP node. The credential header is `Authorization`, with value `Bearer <NEOTH
n8n API token>`. This is the token described above; an n8n instance's own API
key authorizes a different API. Tokens are not embedded in the workflow JSON.

Set `neothBaseUrl`, `channel`, and the channel's `recipient`. The templates use
ordinary Set-node fields, so they do not require n8n's licensed Variables
feature or access to process environment variables. HTTP requests use typed
JSON bodies and read NEOTH's `data.hits` and `data.completion` envelopes.
Automated provider calls use `incognito: true` to avoid communication-profile
reads.

The base URL must reach NEOTH from the n8n process. For a native n8n process on
the same host, it is normally `http://127.0.0.1:9744`. A bridged container has
its own loopback interface; the managed Docker installation's connection to
this host API still needs deployment acceptance. Keep the workflow inactive
until that route and its credential work. The NEOTH listener and its loopback
peer check remain private.

The weekly workflow writes a real text-to-binary conversion through n8n's
Read/Write Files node before queueing its channel message. `archiveDirectory`
defaults to `/home/node/.n8n-files`, n8n's permitted file directory. Container
deployments must mount separate persistent storage there; the current managed
installer does not yet provision that archive mount. Do not use n8n's `.n8n`
configuration directory, which contains its database and credentials. The
message reads the original provider completion after the successful write.

The four stats fields are cumulative event/provider/channel counts. The
weekly schedule takes a snapshot of them; it does not turn them into a
seven-day cost, skill-usage, or consent-denial report.

The pinned-image import check proves that inactive graphs can be stored and
read back. Workflow execution, channel delivery, persistent archive storage,
and managed host connectivity require their respective runtime checks.

---

The optional hosted execution check has also run two in-memory Daily/Morning
copies through the real pinned n8n CLI with dummy credentials and an internal
mock API. It verifies the six ordered recall/provider/send requests and their
data flow. That check does not contact a real NEOTH instance or deliver a
channel message; those deployment checks remain required.
## Optional starter catalog

The CLI also lists ten generated starter intents, for a total of thirteen
workflows. Their historical Paperless, email, calendar, proposal, Obsidian,
audit and memory-report routes are not implemented by this six-route API.
Their descriptions and request nodes identify the missing adapters. They
remain inactive even after choosing an origin and HTTP Header Auth credential;
configuration alone cannot make an unavailable route work. The generated
request methods describe the intended future adapter and do not authorize or
implement its effects.

---
## When NOT to use the n8n API

| Use this surface instead | When |
| :-- | :-- |
| Built-in `freedom.yaml::cron` | One CLI command, no logic, operator-readable in one line. See [cron-vs-n8n.md](cron-vs-n8n.md). |
| Direct CLI (`neoth chat ...`) | One-off operator-typed queries. |
| Slash commands (`/recall`, `/status`) | Channel-side operator commands the slash registry already handles. |
| Provider SDK directly | Code outside NEOTH that needs multi-turn streaming or tool-use — the API surface is intentionally single-round-trip. |

---

## Audit + observability

Every request writes one 0x39 `EVENT_TYPE_N8N_REQUEST` WAL frame
with `{endpoint, source_ip, request_id, ts_unix}`. Recall the audit
trail via:

```bash
neoth wal show --type n8n_request --last 24h
```

The frame writes **before** the bearer check, so a flood of bad-
token attempts is fully observable + the 5-strike cooldown engages
deterministically.
