# SPEC — Multi-Node Clock (Hybrid Logical Clock) — NEOTH v1.1

> Status: BUILD-READY. Fixes: S9 from ADVERSARIAL review (panic → Result), S2 audit note.
> WAL v1.1 wire format: hlc replaces ts_ns. EventHeader offsets updated per SPEC_wire_header_v2_slim.md §4.
> wal_format_version = 0x02 (initial v1.1 wire format; v0.7 ts_ns format was never shipped).

---

## 1. Motivation

v0.7 replay-window ±300s used NTP-trusted wall clock. Safe for single-node ingress.
With Veronica (100.86.138.18) as second node and WAL gossip-sync in Phase 3:
- Two nodes may have up to 60s NTP drift
- A message processed on Veronica and replicated to debian could arrive
  with `ts_ns` in the past by up to 60s → replay-window rejects as stale
- Causal ordering of cross-node events undefined with wall clocks only

**Solution:** Hybrid Logical Clocks (HLC, Kulkarni et al. 2014) for WAL inter-node ordering.
Wall-clock replay-window (±300s) retained for channel ingress only (Telegram/WhatsApp/Slack webhook freshness).

**v1.1 vs v0.8 fixes:**
- **S9**: `.expect("HLC logical overflow")` replaced with `Result<(), HlcError>` propagation. Single-packet remote DoS via `peer.logical = u32::MAX` eliminated. New event type `0x2F CLOCK_LOGICAL_OVERFLOW` emitted instead of panic.
- **S2** (re-audit): the v0.8 `hlc_tick_receive` branches were re-verified against Kulkarni 2014 paper. The implementation matches the paper's rules — initial adversarial-agent flag was a misreading. The branch order is preserved. **No causality-violation bug exists in branch 2.** Detailed audit in §3.5.

---

## 2. HLC Data Structure

```rust
/// Hybrid Logical Clock — 12 bytes on wire.
/// physical_ns: NTP wall-clock nanoseconds at last update
/// logical:     monotone counter within same physical_ns
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hlc {
    physical_ns: u64,  // u64 LE
    logical:     u32,  // u32 LE
}

impl Hlc {
    pub const EPOCH: Hlc = Hlc { physical_ns: 0, logical: 0 };

    /// Construct with validation. Reject `physical_ns == 0 && logical != 0`
    /// as an invalid "post-epoch logical without physical" state.
    pub fn new(physical_ns: u64, logical: u32) -> Result<Self, HlcError> {
        if physical_ns == 0 && logical != 0 {
            return Err(HlcError::PostEpochLogicalWithoutPhysical);
        }
        Ok(Hlc { physical_ns, logical })
    }

    pub fn physical_ns(&self) -> u64 { self.physical_ns }
    pub fn logical(&self) -> u32 { self.logical }
}

/// Total ordering per HLC paper: physical_ns dominates, logical is tiebreaker.
impl Ord for Hlc {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.physical_ns.cmp(&other.physical_ns)
            .then(self.logical.cmp(&other.logical))
    }
}

impl PartialOrd for Hlc {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
```

Wire encoding: `physical_ns` as u64 LE, `logical` as u32 LE. Total = 12 bytes at WAL header offset [33..45) per `SPEC_wire_header_v2_slim.md §4`.

---

## 3. HLC Update Rules (S9 fix: Result, not panic)

### 3.1 Errors

```rust
#[derive(thiserror::Error, Debug)]
pub enum HlcError {
    #[error("post-epoch logical without physical (physical_ns=0, logical={0})")]
    PostEpochLogicalWithoutPhysical(u32),

    /// Logical counter overflow: u32 wraps after 4.29B increments at same physical_ns.
    /// In practice unreachable on a healthy node, but can be triggered by a malicious peer
    /// gossiping HLC with `logical = u32::MAX - N`.
    #[error("HLC logical counter overflow (peer={peer_node_id:?})")]
    LogicalOverflow { peer_node_id: Option<NodeId> },
}
```

### 3.2 On local event generation

```rust
/// Call before writing a new WAL event originating on this node.
/// Returns Err on logical-counter overflow (does NOT panic — S9 fix).
/// Caller should emit `0x2F CLOCK_LOGICAL_OVERFLOW` event and abort the offending operation.
pub fn hlc_tick_local(current: &mut Hlc, now_ns: u64) -> Result<(), HlcError> {
    if now_ns > current.physical_ns {
        current.physical_ns = now_ns;
        current.logical = 0;
        Ok(())
    } else {
        // Clock did not advance; increment logical to preserve monotonicity.
        match current.logical.checked_add(1) {
            Some(new_logical) => {
                current.logical = new_logical;
                Ok(())
            }
            None => Err(HlcError::LogicalOverflow { peer_node_id: None }),
        }
    }
}
```

### 3.3 On receiving event from peer node (S9 fix: no panic)

```rust
/// Call when a WAL event arrives from a peer node. peer_hlc comes from gossip message header.
/// Returns Err on logical-counter overflow — caller must reject the peer message and
/// emit `0x2F CLOCK_LOGICAL_OVERFLOW` event WITHOUT propagating peer's frame.
/// Per Kulkarni 2014 HLC paper algorithm.
pub fn hlc_tick_receive(
    current: &mut Hlc,
    now_ns: u64,
    peer_hlc: Hlc,
    peer_node_id: NodeId,
) -> Result<(), HlcError> {
    let max_physical = now_ns.max(peer_hlc.physical_ns).max(current.physical_ns);

    // Branch 1: now_ns dominates strictly (both local and peer behind wall clock)
    if max_physical > current.physical_ns && max_physical > peer_hlc.physical_ns {
        current.physical_ns = max_physical;
        current.logical = 0;
        return Ok(());
    }

    // Branch 2: local and peer are at same physical (both equal to max_physical)
    if max_physical == current.physical_ns && max_physical == peer_hlc.physical_ns {
        let merged = current.logical.max(peer_hlc.logical);
        current.logical = merged.checked_add(1)
            .ok_or(HlcError::LogicalOverflow { peer_node_id: Some(peer_node_id) })?;
        return Ok(());
    }

    // Branch 3: local leads (peer.physical < current.physical, equal to or below now_ns)
    if max_physical == current.physical_ns {
        current.logical = current.logical.checked_add(1)
            .ok_or(HlcError::LogicalOverflow { peer_node_id: None })?;
        return Ok(());
    }

    // Branch 4: peer leads (peer.physical > current.physical, equal to max which equals or exceeds now_ns)
    // max_physical == peer_hlc.physical_ns (and > current.physical_ns)
    current.physical_ns = peer_hlc.physical_ns;
    current.logical = peer_hlc.logical.checked_add(1)
        .ok_or(HlcError::LogicalOverflow { peer_node_id: Some(peer_node_id) })?;
    Ok(())
}
```

### 3.4 HLC Comparison (causal ordering)

```rust
// Derived from Ord impl in §2.
// e1.hlc < e2.hlc  iff
//   e1.physical_ns < e2.physical_ns
//   OR (e1.physical_ns == e2.physical_ns AND e1.logical < e2.logical)
```

`e1.happened_before(e2)` ⟺ `e1.hlc < e2.hlc`.

### 3.5 S2 Re-Audit — branch correctness per Kulkarni 2014

The original ADVERSARIAL/04 review claimed branch 2 (now §3.3 Branch 3) was wrong, asserting it should use `max(current.logical, peer.logical) + 1`. **This was a misreading.**

Per Kulkarni et al. 2014 ("Logical Physical Clocks", USENIX ATC), HLC merge rule on receive:

```
let l_new = max(l_old, l_msg, pt)
if l_new == l_old == l_msg:
    c_new = max(c_old, c_msg) + 1     // BOTH-EQUAL CASE
elif l_new == l_old:
    c_new = c_old + 1                  // LOCAL-LEADS CASE (no peer.logical interaction)
elif l_new == l_msg:
    c_new = c_msg + 1                  // PEER-LEADS CASE
else:
    c_new = 0                          // WALL-CLOCK-LEADS CASE
```

In the LOCAL-LEADS case (`l_new == l_old > l_msg`), peer's physical is strictly older.
Peer's logical was set at that older physical time; it has no causal meaning at the current physical time.
Setting `c_new = c_old + 1` (not `max(c_old, c_msg) + 1`) is correct per Kulkarni.

NEOTH v1.1 implementation matches Kulkarni paper exactly. No causality violation.

The adversarial-agent confusion likely came from conflating the "both-equal" case (where merging logical IS correct) with the "local-leads" case.

---

## 4. WAL EventHeader Integration (v1.1 wire format)

Per `SPEC_wire_header_v2_slim.md §4`:
- HLC at frame offset `[33..45)` (12 bytes within the 96-byte header body)
- `hlc.physical_ns`: bytes 33-40 (u64 LE)
- `hlc.logical`: bytes 41-44 (u32 LE)

No backward-compat from v0.7 — v0.7 was never shipped. Reader rejecting `wal_format_version != 0x02`.

Byte cost vs hypothetical v0.7 (ts_ns only): +4 bytes per event. 10M events: +40 MB. Acceptable.

---

## 5. Replay-Window Policy

### 5.1 Channel Ingress (Telegram/WhatsApp/Slack)

Policy: wall-clock ±300s freshness check. UNCHANGED from v0.7.
Rule: `message.date` (Unix seconds) within `[now_wall - 300, now_wall + 300]`.
Outside window: HTTP 200 (suppress retry storm), no WAL emit.

### 5.2 WAL Inter-Node Replication

Policy: HLC-only ordering. No wall-clock replay check.
Rationale: nodes may have up to 60s NTP drift; wall-clock check would reject legitimate events.
Rule: accept event from peer if HLC is monotonically greater than last-seen HLC from that node.
Out-of-order delivery: buffer up to 1024 events per node, reorder by HLC before WAL append.
Duplicate detection: `(content_hash, node_id, hlc)` triple must be unique in `idx_inbound_dedup`.

### 5.3 Migration Events (Phase 3 Days 63-65)

`hlc.physical_ns = source_mtime_ns` (original creation time from Jarvis store).
`hlc.logical = 0` (no concurrent events at exact ns during migration).
Preserves temporal ordering of migrated content relative to new live events.

---

## 6. Clock-Skew Detection

```
Condition: abs(now_wall_ns - hlc.physical_ns) > 60_000_000_000 (60 seconds in ns)
Action:    emit WAL event 0x2E CLOCK_SKEW_DETECTED
Inspect:   neoth wal tail --event-types 0x2E
```

```rust
pub struct ClockSkewDetected {
    pub node_id:          [u8; 16],
    pub local_wall_ns:    u64,
    pub hlc_physical_ns:  u64,
    pub skew_ns:          i64,  // negative = local behind HLC; positive = local ahead
    pub detected_at_hlc:  Hlc,
}
```

Clock skew does NOT abort processing — diagnostic event only.
Skew threshold 60s matches NTP worst-case drift in healthy cluster.

---

## 7. Logical-Overflow Event (NEW v1.1, S9 fix)

```rust
/// 0x2F CLOCK_LOGICAL_OVERFLOW — emitted when hlc_tick_local or hlc_tick_receive
/// returns HlcError::LogicalOverflow. Caller MUST emit this event and abort the
/// triggering operation. Never panic.
pub struct ClockLogicalOverflow {
    pub local_node_id:    [u8; 16],
    pub peer_node_id:     Option<[u8; 16]>,  // None if originated locally
    pub last_hlc:         Hlc,                // HLC state at point of overflow
    pub now_ns:           u64,
    pub triggering_event: Option<u64>,        // event_id being processed, if any
}
```

Recovery: operator manually advances local node's physical_ns via `neoth wal hlc-advance --ns N`
or waits for wall clock to advance past `last_hlc.physical_ns + 1ns`. Logical resets to 0
on next physical advance via `hlc_tick_local`.

---

## 8. Causal Ordering Guarantee

For any two WAL events e1, e2 across all nodes:
- If e1 happened-before e2 (`e1.hlc < e2.hlc`), recall queries return them in order.

Events with equal HLC are concurrent (neither happened-before the other).
Tie-break: `node_id` lexicographic ascending.

Recall query sort order:
1. Primary: `hlc.physical_ns` descending (most recent first)
2. Secondary: `hlc.logical` descending (within same nanosecond)
3. Tertiary: `node_id` ascending (stable tie-break)

Guarantee holds even for out-of-order network delivery, gated by HLC reorder buffer.

---

## 9. Test Plan

### Test 1 — Single-Node Monotonicity
Generate 1000 events. Verify all HLCs strictly increasing.
Simulate 100 events within same nanosecond: logical increments, physical_ns constant.

### Test 2 — Two-Node Gossip with 60s Clock Skew
Node A at wall T. Node B at wall T+60s.
A generates E_A1. B receives E_A1, generates E_B1.
- Assert: `E_B1.hlc > E_A1.hlc` (B is causally after A).
- Assert: all 4 events in WAL with unique HLCs. No events lost.

### Test 3 — Clock-Skew Detection Fires
Inject peer HLC with `physical_ns = now_wall_ns + 65_000_000_000` (65s ahead).
- Assert: `0x2E CLOCK_SKEW_DETECTED` emitted with `skew_ns ≈ +65s`.

### Test 4 — S9: Logical-Overflow Does NOT Panic (NEW)
Inject peer HLC with `physical_ns = current.physical_ns` AND `logical = u32::MAX`.
- Assert: `hlc_tick_receive` returns `Err(HlcError::LogicalOverflow)`.
- Assert: NO panic.
- Assert: `0x2F CLOCK_LOGICAL_OVERFLOW` event emitted to WAL.
- Assert: triggering peer event REJECTED, not appended.

### Test 5 — Recall Ordering with Concurrent Events
Insert 10 events with equal `hlc.physical_ns`. Vary `hlc.logical` 0-9, node_id between 2 values.
Run recall query.
- Assert: events in `hlc.logical` desc order, then `node_id` asc.
- Run 1000 random recall queries.
- Assert: no ordering violations.

### Test 6 — Kulkarni 2014 Conformance (S2 audit re-verify)
For each of the 4 algorithm branches, run a unit test with explicit `(now_ns, current_hlc, peer_hlc)`
inputs and assert the resulting state matches the paper's formula.

```rust
// Branch 1: wall clock dominates strictly
hlc_tick_receive(&mut Hlc{1000, 5}, 2000, Hlc{500, 10}, peer);
assert_eq!(current, Hlc{2000, 0});

// Branch 2: local and peer both at same physical
hlc_tick_receive(&mut Hlc{1000, 5}, 999, Hlc{1000, 8}, peer);
assert_eq!(current, Hlc{1000, 9}); // max(5, 8) + 1 = 9

// Branch 3: local leads (peer behind, wall behind)
hlc_tick_receive(&mut Hlc{1000, 5}, 800, Hlc{600, 100}, peer);
assert_eq!(current, Hlc{1000, 6}); // current.logical + 1 (peer.logical IGNORED per Kulkarni)

// Branch 4: peer leads
hlc_tick_receive(&mut Hlc{1000, 5}, 800, Hlc{1500, 3}, peer);
assert_eq!(current, Hlc{1500, 4}); // peer.logical + 1
```

---

## 10. Gossip Protocol Integration

Multi-node WAL gossip (debian ↔ Veronica, mTLS, Phase 3 Day 85+):

**On send (debian → Veronica):**
1. Serialize WAL event with hlc field
2. Include sender `current_hlc` in gossip message header
3. Veronica calls `hlc_tick_receive(now_ns, sender.current_hlc, sender.node_id)`
4. On `Err(HlcError::LogicalOverflow)`: REJECT this message. Emit 0x2F event. Notify operator.
5. On `Ok`: Veronica appends event to local WAL with updated HLC

**On receive (Veronica from debian):**
1. Buffer event in per-node reorder buffer (max 1024 events per node)
2. Sort buffer by HLC
3. Flush to WAL when head is unambiguously ordered

mTLS: node_id as client certificate subject — prevents node_id spoofing.

---

## 11. Reference

Kulkarni, S. et al. (2014). *Logical Physical Clocks and Consistent Snapshots in Globally Distributed Databases.* USENIX ATC 2014.

---

## 12. Status

**v1.1 multi-node clock BUILD-READY.** S9 fixed (Result instead of panic). S2 audited and confirmed correct against Kulkarni paper (initial adversarial flag was a misreading).
