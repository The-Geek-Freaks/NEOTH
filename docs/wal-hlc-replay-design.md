# P1-04 EventHeaderV2 HLC replay design

## Wire and reader compatibility

`EventHeaderV2` already contains the complete wire representation needed for
inter-node ordering: the 12-byte HLC and 16-byte node identifier are fixed
fields in the existing 96-byte header. P1-04 does not change their offsets,
the `0x02` event-header version, the schema version, or any event registry
code.

There is no shipped EventHeaderV1 to decode. `PLAN/SPEC_multinode_clock.md`
section 4 records that the older `ts_ns` header was never shipped and that a
reader must reject an event header whose format is not `0x02`. This is distinct
from the segment envelope: existing segment readers continue to accept v1,
v2, and v3 segment headers, and all three carry the current V2 event frame
body. The compatibility regression therefore covers a v1 segment containing a
V2 HLC event header; it does not invent a hypothetical V1 event-header parser.

## Replay order

Decoded frames use this ascending canonical key:

1. `hlc.physical_ns`
2. `hlc.logical`
3. `node_id` bytes
4. `event_id`
5. the remaining immutable header fields, ending with declared lengths

The HLC fields order ordinary causal time. Node identity gives concurrent
events with equal HLCs a deterministic cross-node order. The remaining header
fields make corrupted-but-decodable distinct metadata deterministic without
looking into payload bytes. Exact same headers remain equal and retain their
already-authenticated source order.

`neoth wal show` sorts its complete decoded result with this key before the
newest-first view. `neoth wal export` sorts its proof-frame collection in the
same ascending replay order before sealing its canonical proof bundle. Neither
path applies a peer wall-clock freshness window to an EventHeaderV2 HLC.

## Authenticated receive merge

The only production receive merge runs in the single foreign-persist writer.
That writer first calls the authorized durable receive state machine. It calls
`hlc_tick_receive` only after that call has returned a canonical
`Committed` or fully bound `Duplicate` outcome, and before the transport gets
its result for ACK construction. `Gap`, dropped frames, persistence failures,
and legacy `DuplicateUnbound` receipts never merge a header HLC.

The SQLite transaction is already committed before the global HLC mutex is
acquired. The merge helper takes no database or membership lock, so it adds no
inverse lock ordering. It first applies the receive transition to a copied HLC
and commits that copy to the global state only on success. A merge error remains
an ACK-withholding error without a partial clock update.

## Fixture matrix

- HLC skew: physical HLC order wins even when node/event tie-break fields
  reverse it.
- Equal HLC: node bytes, then event identity, order concurrent frames.
- Legacy segment compatibility: a v1 segment reader decodes a current V2 HLC
  event header unchanged.
- Live inspector: an append-order-inverted frame set is presented in canonical
  HLC/node order.
