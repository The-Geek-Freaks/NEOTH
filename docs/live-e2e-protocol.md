# Live end-to-end protocol — provider + council + budget + WAL audit

**For:** operators who want to verify NEOTH's claims against their
own host with real provider keys, no wiremock.
**Time:** ~15 minutes once you have one API key.
**Cost:** ~$0.02–$0.10 depending on which providers you have keys for.

This is the reproducible protocol the project itself runs before
cutting a public release. CI gets the same shape via wiremock; this
doc is the operator-side equivalent so anyone can verify the system
behaves end-to-end without trusting our CI.

---

## What you'll prove

Walking through this end to end demonstrates:

1. A real provider answers a real prompt → WAL records both
   `PROVIDER_REQUEST` (0x20) + `PROVIDER_RESPONSE` (0x21) frames
   linked by `request_id`.
2. `BudgetToken` accounting actually fires — a 2nd call with the
   daily cap exhausted refuses cleanly with `QUOTA_BREACHED` (0xF0).
3. The council triggers + picks a winner — `COUNCIL_SYNTHESIS_ATTEMPTED`
   + `COUNCIL_WINNER_SELECTED` frames + audit-visible dissent line.
4. A 429 rate-limit response triggers the retry classifier from
   `providers/claude_retry.rs` instead of a silent crash.
5. The full chain is operator-auditable from one shell session —
   no fishing in 3 different log files.

---

## 0. Setup (one-time, 3 minutes)

```bash
# 0.1 — current 1.0.0 install from the source tree
git clone https://github.com/The-Geek-Freaks/NEOTH
cd NEOTH/SRC
cargo install --locked --path neothd --features release-server
# After publication: cargo install neoth --locked --features release-server

# 0.2 — initialise into a throwaway directory so this protocol does
#       not pollute your real ~/.neoth/
export NEOTH_HOME=/tmp/neoth-e2e
mkdir -p "$NEOTH_HOME"
neoth init --home "$NEOTH_HOME"
# Wizard asks: operator id (e.g. "you"), provider (pick claude_cli
# OR openai_compat with an api key you have), autonomy (pick
# "standard" — strict refuses cloud + you need cloud for this proto),
# memory tier defaults (keep defaults).

# 0.3 — set the daily budget low so we can exhaust it deliberately.
neoth --home "$NEOTH_HOME" quota set --daily-eur 0.05

# 0.4 — confirm the daemon comes up clean
neoth --home "$NEOTH_HOME" serve --dry-run
# Expects: SegmentHeader written, recovery scan 0 frames, "ready".
```

---

## 1. Single-provider round trip (~30 seconds)

Goal: prove one full request/response with real upstream.

```bash
# 1.1 — start the daemon in one terminal
neoth --home "$NEOTH_HOME" serve &
NEOTH_PID=$!

# 1.2 — fire one chat
neoth --home "$NEOTH_HOME" chat \
  "In one short sentence: what is 2 plus 2?"

# 1.3 — read back the WAL frames that landed
neoth --home "$NEOTH_HOME" wal show --tail 6 --format json | jq '.[] | {type, request_id, ts, cost_eur}'
```

**Pass criteria:**
- Output contains a `PROVIDER_REQUEST` (0x20) frame and a
  `PROVIDER_RESPONSE` (0x21) frame.
- Both frames share the same `request_id`.
- The response frame has a non-zero `cost_eur` (or `0.0` for local).
- The response text contains "4" or "four".

**If it fails:**
- `0 PROVIDER_REQUEST frames` → wizard didn't write a provider; re-run
  `neoth init` and pick a real provider this time.
- `PERMISSION_DENIED` (0xA1) appears → autonomy was set to strict; run
  `neoth autonomy set standard`.
- Upstream timeout → check `neoth doctor providers` for connectivity.

---

## 2. Budget exhaustion (~1 minute)

Goal: prove `BudgetToken` accounting actually refuses calls.

```bash
# 2.1 — current quota state
neoth --home "$NEOTH_HOME" quota status
# Expects: "daily_eur: 0.05 used: <something below 0.05>"

# 2.2 — fire enough chats to exceed 0.05€. The exact count depends
#       on your provider's per-call cost; usually 1–3 cloud calls
#       at 0.05€ cap. Each call streams cost into the quota.
for i in 1 2 3; do
  neoth --home "$NEOTH_HOME" chat "Test message $i — give me a 50-token answer."
done

# 2.3 — fire one more; expect refusal.
neoth --home "$NEOTH_HOME" chat "This one should bounce." || true

# 2.4 — confirm the refusal landed in the WAL as QUOTA_BREACHED.
neoth --home "$NEOTH_HOME" wal show --tail 10 --type quota_breached --format json | jq
```

**Pass criteria:**
- Step 2.3 exits non-zero with operator-readable message
  `daily quota exhausted — refused before contacting provider`.
- Step 2.4 shows at least one `QUOTA_BREACHED` (0xF0) frame.

**If it fails:**
- Budget is too high to exhaust in 3 calls → re-run `quota set
  --daily-eur 0.01` and try again.
- Refusal happened but no WAL frame → grep the daemon log for
  `quota` to see why the writer didn't capture.

---

## 3. Council convening + winner pick (~1 minute)

Goal: prove the council fires on dissent-marker prompts and writes
a winner-pick frame.

```bash
# 3.1 — re-grant some budget for the council calls.
neoth --home "$NEOTH_HOME" quota set --daily-eur 1.00

# 3.2 — fire a council-triggering prompt (CH-14 dissent markers).
#       "should I" + "what's better" both trigger.
neoth --home "$NEOTH_HOME" chat \
  "Should I use Rust or Go for a new microservice — what's better?"

# 3.3 — read the council frames.
neoth --home "$NEOTH_HOME" wal show --tail 20 --format json \
  | jq '.[] | select(.type | startswith("council_"))'
```

**Pass criteria:**
- Output contains `COUNCIL_SYNTHESIS_ATTEMPTED` (0x80) frame.
- Output contains `COUNCIL_WINNER_SELECTED` (0x83) frame with a
  named winning hemisphere (`left` / `right` / `cerebellum`).
- If the council found disagreement, also a
  `COUNCIL_DIVERSITY_WARNING` (0x84) frame.

**If it fails:**
- No council frames at all → `NEOTH_COUNCIL_DISABLE` is set
  somewhere, or the prompt doesn't hit a dissent marker. Try a
  more obvious one: "what do you think — Rust or Go?"
- Winner frame missing despite synthesis → check
  `COUNCIL_PARTIAL_REFUSAL` (0x81); a partial-refusal upstream
  means no clean winner could be picked.

---

## 4. Rate-limit retry classifier (~1 minute)

Goal: prove a real 429 from upstream triggers the
`Transient` retry path with exponential backoff, not a silent crash.

```bash
# 4.1 — fire many quick calls so the upstream rate-limits you.
#       Most operators won't actually trip this on a free key in
#       under 10 calls; the retry classifier path is exercised in
#       wiremock CI. The operator-side proof is:
neoth --home "$NEOTH_HOME" wal show --tail 200 --type provider_error --format json \
  | jq '.[] | {ts, reason, retry_class}'

# If you see entries with retry_class: "transient" — the classifier
# fired. If you don't, the protocol covered budget + council
# instead; run the rate-limit step on a host that already saw a 429.
```

**Pass criteria (when you can trigger one):**
- At least one `PROVIDER_ERROR` (0x22) frame with
  `retry_class: "transient"`.
- Followed by a successful `PROVIDER_RESPONSE` (0x21) on retry
  attempt 2 or 3.

This step is the only one where automated proof is harder than
manual — most operators won't deliberately exhaust their upstream
rate limit. If you've ever seen a 429 in normal NEOTH usage,
search the WAL for it; the classifier path is the same.

---

## 5. Operator audit walkthrough (~3 minutes)

Goal: walk the full chain back through one operator session.

```bash
# 5.1 — find the request id for one chat you remember running.
neoth --home "$NEOTH_HOME" wal show --tail 100 --type provider_request --format json \
  | jq '.[] | {ts, request_id, prompt_preview}'

# 5.2 — pick one request_id + trace every frame that mentions it.
REQ=<copy-paste from step 5.1>
neoth --home "$NEOTH_HOME" wal show --grep "$REQ" --format json | jq '.[] | {ts, type}'
```

**Pass criteria:**
- One `PROVIDER_REQUEST` (0x20) at the start.
- Zero-or-more `PROVIDER_STREAM_CHUNK` (0x23) for streaming.
- Exactly one `PROVIDER_RESPONSE` (0x21) at the end.
- If council was involved, the corresponding `COUNCIL_*` frames
  sandwiched between.
- If budget was checked, a `COST_ESTIMATE_SHOWN` (0xA4) before
  the request.

**This is the audit-trail claim:** every meaningful event during
one chat is tagged with the same `request_id` so an operator can
reconstruct what happened without log archaeology.

---

## 6. Teardown

```bash
kill $NEOTH_PID
rm -rf "$NEOTH_HOME"
```

---

## What this protocol does NOT cover

Out of scope for the v1 release proof:

- **Multi-host cluster routing.** Single-host only — cluster transport uses
  NEOTH's own peeroxide/Hyperswarm protocol; it is not a Keet adapter
  (see [R-A1 research note](../QUELLEN/research/R-A1_hyperswarm.md)
  if you have the operator-local docs).
- **Hysteria QUIC transport.** Sidecar pattern only — the Hysteria
  daemon runs as a separate process today. Verify the sidecar shape
  via `neoth-relay doctor --hysteria-config /path/to/hysteria.yaml`.
- **Plugin sandbox.** WASM plugin host has its own test surface;
  exercise via `neoth skills test`.
- **Auto-update.** Self-update is a separate workflow; see
  `neoth update --check`.

---

## CI parity

The wiremock-driven CI version of this protocol lives in
`SRC/neothd/tests/` and runs against a fake upstream that replays
canned responses. Operator-side parity is the value-add of this
doc: real provider, real upstream, real cost, real WAL — no place
for the system to fake the answer.
