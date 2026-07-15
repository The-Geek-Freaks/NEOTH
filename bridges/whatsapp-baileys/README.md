# NEOTH WhatsApp Baileys bridge

This operator-owned sidecar links a personal WhatsApp account through
`baileys@7.0.0-rc13` and exposes NEOTH's authenticated bridge protocol on
loopback. It is optional and separate from the official Meta Cloud API adapter.

The exact pin matches upstream's official `latest` dist-tag checked on
2026-07-13. Upstream still tags `6.7.23` as `legacy`; this bridge deliberately
uses v7 because current WhatsApp LID/key-store behavior and transaction-aware
Signal state live on that line. The RC is therefore not an accidental range or
a stale copied pin: upgrades require a lockfile diff plus the bridge tests.

Requirements: Node.js 22.16+ and pnpm 10.32.1. WhatsApp Web/Baileys is an
unofficial client path; use a dedicated account and accept the platform-policy
risk before enabling it.

## Install and pair

From a NEOTH GitHub release, download and verify the signed
`neoth-whatsapp-baileys-vX.Y.Z.tar.gz` asset, then install its fixed directory:

```bash
install -d -m 700 "$HOME/.local/share/neoth"
tar -xzf neoth-whatsapp-baileys-vX.Y.Z.tar.gz -C "$HOME/.local/share/neoth"
cd "$HOME/.local/share/neoth/whatsapp-baileys"
pnpm install --frozen-lockfile
```

The same directory exists at `bridges/whatsapp-baileys` in a source checkout.

```bash
install -d -m 700 "$HOME/.config/neoth"
printf 'NEOTH_WA_BRIDGE_TOKEN=%s\n' "$(openssl rand -hex 32)" > "$HOME/.config/neoth/whatsapp-baileys.env"
chmod 600 "$HOME/.config/neoth/whatsapp-baileys.env"
set -a; . "$HOME/.config/neoth/whatsapp-baileys.env"; set +a
pnpm start
```

Scan the printed QR in WhatsApp -> Linked devices. The repo-owned auth store is
a process-locked, atomic, fsynced snapshot of credentials and Signal keys; it
does not use upstream's demo-oriented `useMultiFileAuthState`. Auth state, the
inbound event journal, restart cursor history, and outbound idempotency live in
`~/.neoth/whatsapp-baileys-bridge/` with owner-only permissions. Do not copy the
auth directory to another operator.

Configure NEOTH with the same token. The sender allowlist is mandatory; groups
are denied unless their exact `@g.us` JID is also listed.

```bash
neoth channel add whatsapp_baileys \
  --url http://127.0.0.1:9120 \
  --token "$NEOTH_WA_BRIDGE_TOKEN" \
  --allowed-sender '+491701234567' \
  --allowed-rooms-csv '120363000000000000@g.us'
neoth channel test whatsapp_baileys
```

`--allowed-sender` and `--allowed-rooms-csv` accept comma-separated exact IDs.
Direct chats accept E.164 or WhatsApp JIDs. Group messages require both an
allowed sender and an allowed group.

## Run as a user service

The bundled unit expects the release layout above. Pre-create the private state
directory; the unit refuses a missing env file, a symlink, a non-owner file, a
mode other than 0600, or a malformed token before Node starts:

```bash
install -d -m 700 "$HOME/.neoth/whatsapp-baileys-bridge"
mkdir -p "$HOME/.config/systemd/user"
cp neoth-whatsapp-baileys.service "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now neoth-whatsapp-baileys.service
systemctl --user status neoth-whatsapp-baileys.service
systemctl --user stop neoth-whatsapp-baileys.service
```

The HTTP server refuses non-loopback binds. For a bridge on another host, keep
the sidecar on loopback and put an authenticated TLS reverse proxy or a
Tailscale Serve endpoint in front; configure NEOTH with that `https://` URL.

## Contract and recovery

- Every request requires `Authorization: Bearer <token>`.
- `GET /v1/health` reports pairing/connection state, capabilities, identity,
  and latest cursor.
- `GET /v1/messages?cursor=N&timeout_ms=25000` long-polls the durable inbound
  journal. A cursor older than retained history returns HTTP 409; it never
  silently skips messages.
- `POST /v1/messages` sends text or base64 media and requires an idempotency
  key. A pending intent is persisted before the network send and the result is
  persisted before it is reported to NEOTH. If the bridge crashes in between,
  that key returns HTTP 409 instead of risking a duplicate send.
- Unknown-outcome (`pending`) tombstones are never TTL- or size-pruned. After
  checking WhatsApp, stop the service and resolve one explicitly with
  `pnpm reconcile -- '<key>' sent '<whatsapp-message-id>'` or
  `pnpm reconcile -- '<key>' not-sent`; then restart the service. `not-sent`
  permits a retry, so use it only after proving no message was delivered.
- Inbound media and outbound media are capped at 10 MiB. The journal is capped
  at 5,000 events or 128 MiB, with a separate 20,000-ID restart dedup set.
- Baileys reconnects with capped exponential backoff. Logged-out sessions stop
  instead of spinning. To re-pair, stop both services, back up then remove only
  `~/.neoth/whatsapp-baileys-bridge/auth/`, and restart the bridge.
- Any auth-key, credential, or inbound-journal persistence failure puts health
  in `fatal` and closes the WhatsApp socket. Later events cannot overtake the
  failed event; repair storage and restart instead of continuing with gaps.

NEOTH claims an inbound ID durably before invoking the provider/pipeline. This
is intentionally at-most-once: a daemon crash after the claim can lose the
reply, but it cannot replay the same inbound into a second paid/tool-bearing
agent turn. The sidecar's pending-send tombstone closes the equivalent outbound
duplicate window.

## Tests

```bash
pnpm test
```

Tests cover authenticated API access, atomic auth/key restart, durable cursor
replay and crash-tail repair, cursor-expiry fail-closed behavior, inbound
restart dedup and persistence fail-stop, concurrent-send serialization, and
outbound sent/pending idempotency plus manual reconciliation across restart.
