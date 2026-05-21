# R-7 Hyperswarm heartbeat — Chorus verdict (2026-05-21)

Chat ID: `019E4A48975F25C0BD9F8B96BC085C94`
Reviewers: codex-cli, gemini-cli
Verdict: both approve once the listed changes land

## Consensus picks

| Q | Codex | Gemini | NEOTH adopts |
|---|-------|--------|--------------|
| Q1 encoding | CBOR | CBOR | **CBOR via ciborium 0.2** |
| Q2 framing | u32 LE length-prefix + 64 KiB cap | u32 LE length-prefix | **u32 LE + MAX_FRAME_BYTES = 64 KiB** |
| Q3 cadence | 5s ± 20% jitter + on-change push rate-limited 1/sec + unhealthy after 3 missed (~15s) | adaptive 10-30s + debounced push | **Codex's tighter cadence** (5s + jitter for routing freshness; pure-adaptive lags on idle→relevant transition) |
| Q4 versioning | protocol-version handshake on connect | protocol-version handshake on connect | **Hello frame with PROTOCOL_NAME + version; mismatch disconnects** |

## Required additions (both reviewers)

- [x] Monotonic per-connection sequence number for stale-frame detection
- [x] Separate `CapabilityUpdate` frame so heartbeat hot path carries only volatile load metrics
- [x] Cluster name hash in handshake (HyperDHT topic alone insufficient as protocol guard)
- [x] Frame-level limits — `MAX_FRAME_BYTES = 64 KiB`, `MAX_CAPABILITIES = 64`, `MAX_CAPABILITY_STRING_LEN = 64`
- [x] NaN/Inf/negative `tokens_per_sec` rejection at the wire boundary
- [x] Absurd-value sanity cap (>1M tokens/sec rejected)
- [x] Unknown-field tolerance via serde + CBOR (additive evolution)

## Constants pinned

```
PROTOCOL_NAME                       "neoth-r7-heartbeat"
PROTOCOL_VERSION                    1
MAX_FRAME_BYTES                     65_536  (64 KiB)
HEARTBEAT_INTERVAL_MS               5_000
HEARTBEAT_JITTER_PCT                20
UNHEALTHY_AFTER_MS                  15_000  (3 missed intervals)
ONCHANGE_PUSH_MIN_INTERVAL_MS       1_000
MAX_CAPABILITIES                    64
MAX_CAPABILITY_STRING_LEN           64
```

## What lands next

- Wire `cluster::heartbeat::{read_framed,write_framed}` into
  `cluster::hyperswarm::spawn_discovery` so each accepted
  peer connection runs:
    1. write Hello → read Hello → `validate_hello`
    2. spawn heartbeat-sender task (5s ± 20% jitter ticker)
    3. spawn heartbeat-reader task (loop `read_framed` →
       `validate_heartbeat` → `registry.lock().record_heartbeat`)
    4. on connection drop → mark peer unhealthy in registry
- Capability-change detection: heartbeat sender re-computes
  `hash_capabilities` per tick + pushes a CapabilityUpdate
  frame (rate-limited) when the hash changes.

## Implementation

Module: `SRC/neothd/src/cluster/heartbeat.rs` (this commit).
16 unit tests pin every invariant the reviewers flagged.
