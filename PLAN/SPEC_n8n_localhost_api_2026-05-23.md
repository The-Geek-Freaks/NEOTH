# N-3 — NEOTH localhost HTTP API for n8n integration

**Status:** spec + scaffolding shipped 2026-05-23 Session 21.
**Closes:** the last open N-* backlog item.

## What this is

n8n is the optional workflow engine NEOTH ships via N-1 (installer
primitive) + N-2 (3 bootstrap workflows). Those workflows POST to
`http://127.0.0.1:9744/api/...` endpoints — this spec defines the
exact endpoint surface, auth model, and integration with the rest
of NEOTH (autonomy + consent + WAL audit).

## Operator scope

- **Single operator**, **localhost-only** binding. The HTTP server
  refuses to bind any non-loopback address. No `0.0.0.0` accepted
  even if the operator hand-edits `freedom.yaml`.
- **Bearer token** in `freedom.yaml::n8n.api_token`. Generated at
  wizard step (`secret::SecretString` round-trip, 32-byte CSPRNG
  base64url-encoded → 43-char token). Operator copies it into n8n's
  environment as `NEOTH_API_TOKEN`.
- **Default port 9744**. Configurable via `freedom.yaml::n8n.api_port`.

## Endpoint surface (v1)

All endpoints return JSON. All require `Authorization: Bearer <token>`.
All fall through to the existing autonomy + consent layers — n8n cannot
bypass any guard that a CLI invocation honours.

| Endpoint                       | Verb | Purpose                                                      |
| ------------------------------ | ---- | ------------------------------------------------------------ |
| `/api/health`                  | GET  | Probe — returns `{"status":"ok","version":"<v>"}`. No auth. |
| `/api/recall`                  | POST | Query hot+warm+cold+groundtruth tiers. Body `{query, tier?, limit?}`. |
| `/api/provider/call`           | POST | One-shot provider call. Body `{prompt, provider?, model?}`. Honours autonomy gate. |
| `/api/channel/send`            | POST | Send via a configured channel. Body `{channel, text, peer?}`. Honours consent gate. |
| `/api/stats`                   | GET  | Aggregate stats over `?window=7d` (or `24h` / `30d` / `all`). |
| `/api/memory/save`             | POST | Persist a memory the operator (via n8n) wants kept. Body `{kind, text, importance?}`. |

v2 endpoints (deferred until v1 has operator usage data):
- `/api/skill/run` — fire a skill by slug
- `/api/cluster/peers` — read cluster peer roster
- `/api/profile/preset/apply` — apply a profile preset

## Auth model

- Bearer token in `Authorization: Bearer <token>` header.
- Token shape: 43-char base64url (32-byte CSPRNG entropy = 256 bits).
- Stored in `freedom.yaml::n8n.api_token` as `SecretString` (mlocked
  per K-Sec-2 / DPAPI-wrapped on Windows per K-Sec-4).
- **Token rotation** via `neoth n8n rotate-token` CLI — generates a
  fresh token, writes to `freedom.yaml`, prints the new value once
  (operator must update n8n env immediately). Old token revoked
  immediately (no grace window — n8n's HTTP nodes will 401 until
  operator updates env, which is the desired "force operator to act"
  shape).
- 5 consecutive 401s from one source IP → 60s cooldown (defence
  against accidental config drift / mistyped env).

## Autonomy + consent integration

- The HTTP server runs in `cli::serve::run_serve` alongside the rest
  of the daemon. It shares the same `Daemon` handle so every endpoint
  has access to the autonomy gate + consent layer + WAL writer.
- `/api/provider/call` consults `permissions::evaluate(action, level)`
  exactly as the CLI chat path does. A request that lands at autonomy
  level `strict` and tries to hit a cloud provider gets the same
  consent prompt UX — except n8n can't prompt, so the request fails
  with `403 PermissionDenied + reason`. Operator sees the failure in
  n8n's execution log + can either bump autonomy or pick a different
  provider.
- `/api/channel/send` consults the per-channel consent registry.
  Same fail-closed contract.

## WAL audit envelope

Every n8n-driven endpoint call emits a new WAL frame:
- `EVENT_TYPE_N8N_REQUEST` (0x39, reserved in the 0x30..=0x3F channel
  band) with payload `{endpoint, source_ip, request_id, ts_unix}`.
- The matching downstream event (PROVIDER_REQUEST / CHANNEL_EGRESS /
  RECALL_HIT) carries the `request_id` so WAL replay shows the n8n
  trigger chain end-to-end.
- 401/403 responses emit `PERMISSION_DENIED` with `source: "n8n_api"`.

## Localhost-only enforcement (defence in depth)

Three layers:
1. **Bind-time**: `TcpListener::bind("127.0.0.1:9744")` — kernel
   refuses non-loopback peer connects to a loopback-bound socket.
2. **Middleware**: every request checks `peer_addr().is_loopback()`
   before routing. Belt-and-braces for kernel quirks + proxy edge
   cases.
3. **Doctor**: `neoth doctor n8n-api` surfaces the bound address +
   warns if the operator hand-edited `freedom.yaml` to a non-loopback
   address (which the bind-time check would reject anyway, but the
   doctor surfaces the misconfig before the daemon refuses to start).

## Wire format

All bodies are JSON. All responses are envelope-shaped:

```json
{
  "ok": true,
  "data": { ... },
  "request_id": "abc-123"
}
```

or on error:

```json
{
  "ok": false,
  "error": {
    "code": "PermissionDenied",
    "message": "operator autonomy level `strict` refuses cloud providers; n8n cannot prompt for confirmation",
    "hint": "either bump autonomy via `neoth autonomy set elevated` or use the local Qwen provider in the n8n workflow"
  },
  "request_id": "abc-123"
}
```

`request_id` is generated server-side per request (UUID v7) and
appears in the WAL events for cross-reference.

## Multi-day implementation order

1. **N-3.a** (~1 day) — `cli/serve.rs::start_n8n_api_server` spawns a
   tokio task hosting hyper + a tiny router (no axum needed — hyper
   handles the 6 endpoints directly). `freedom.yaml::n8n.{enabled,
   api_port, api_token}` config block.
2. **N-3.b** (~1 day) — `/api/health` + `/api/recall` + bearer auth
   middleware + WAL `EVENT_TYPE_N8N_REQUEST` (0x39 — reserve in
   `wal/events.rs` first). 5-strike 401 cooldown.
3. **N-3.c** (~1-2 days) — `/api/provider/call` + autonomy gate
   integration + `/api/channel/send` + consent gate integration.
4. **N-3.d** (~0.5 day) — `/api/stats` + `/api/memory/save`. Token
   rotation CLI subcommand.
5. **N-3.e** (~0.5 day) — `neoth doctor n8n-api` diagnostic. Wizard
   step exposing the token to the operator with copy-to-clipboard.

Total: ~3.5-4 days focused work. Spec ships now (Session 21);
implementation lands in a focused N-3 session.

## What's already shipped that this builds on

- N-1 installer primitive (`installers/n8n.rs`) — operator-side
  install path picker.
- N-2 bootstrap workflows (`assets/n8n_workflows/*.json`) — all 3
  already point at `http://127.0.0.1:9744/api/...` with bearer auth.
  The wire shape this spec defines IS what the workflows expect, so
  implementation must match exactly.
- N-4 cron-vs-n8n decision flow (`docs/cron-vs-n8n.md`).
- `cli/serve.rs` daemon task infrastructure — n8n API server slots
  in alongside the existing WAL writer / cron scheduler / tmux
  sweeper / decay task / channel gateways.
- Autonomy + consent + WAL audit primitives — all already in tree,
  the HTTP layer just calls them.

## What's NOT in scope

- HTTPS / TLS termination — operator's reverse proxy handles that
  if they want to expose the API beyond localhost (which they
  shouldn't, but adding TLS is one nginx config block away).
- Multi-tenant / per-token scopes — single-operator NEOTH; one token
  with full surface access.
- Per-endpoint rate limiting beyond the 5-strike auth cooldown.
  Operator runs n8n on the same host; abuse vector is the operator
  themselves.
- WebSocket / SSE streaming — v1 is request/response only. Streaming
  defers to v2 once an operator workflow actually needs it.

## Why this spec ships now even though impl is deferred

The N-2 bootstrap workflows already declare the endpoint shape they
expect (URL paths + bearer header + JSON body keys). Without this
spec on file, those workflows + their tests are aspirational. With
the spec, the implementation in a focused session has a non-debatable
contract to hit + the workflow tests stay green from day one.
