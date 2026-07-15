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
| `/api/memory/save` | POST | `{kind, body, tags?}` | `{stored, bytes}` (writes a RAW_TEXT WAL frame) |
| `/api/provider/call` | POST | `{prompt, system?, model?}` | `{completion, model}` (runs `providers::from_config(...).complete()`) |
| `/api/channel/send` | POST | `{channel, recipient, text}` | `{queued}` (writes a CHANNEL_EGRESS WAL frame; adapter dispatch via the broker) |

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

---

## Bootstrap workflows

NEOTH ships 3 example n8n workflows under `SRC/neothd/assets/n8n_workflows/`:

| File | Schedule | What it does |
| :-- | :-- | :-- |
| `daily_summary.json` | 21:00 every day | Today's activity → 5-bullet summary via `/api/recall` + `/api/channel/send` |
| `morning_brief.json` | 07:30 weekdays | Open threads → motivating brief |
| `weekly_stats.json` | Sunday 18:00 | Week stats via `/api/stats` → markdown archive + channel summary |

All ship INACTIVE — operator must enable them in the n8n UI per the
hard rule "no destructive auto-action without operator GO".

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
