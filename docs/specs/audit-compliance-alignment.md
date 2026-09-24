# Permission audit field alignment

ADOPT31-C9 is a documentation and naming crosswalk. NEOTH retains its existing
persisted WAL header, permission payload and reader projection. This document
does not claim an implemented Agent Governance Toolkit exporter.

The authority is [AUDIT-COMPLIANCE-1.0 section 4.1](https://github.com/microsoft/agent-governance-toolkit/blob/98a777328af9ad4dc76bc76803071cf5a615811b/docs/specs/AUDIT-COMPLIANCE-1.0.md#41-agent-os-audit-entry-pure-specification),
verified on 2026-09-24 at commit `98a777328af9ad4dc76bc76803071cf5a615811b`,
Git blob `721447991f46ab69567f33776a72cc61883f307b`, 94,424 bytes,
SHA-256 `033ec682630d71b93b971baf1686cd0d1262e911d4e2896e182e92842e887bf7`.

| Upstream field | NEOTH permission audit representation | Alignment |
| --- | --- | --- |
| `timestamp` | Payload `ts_ns`; header also carries HLC time | Integer Unix nanoseconds require explicit UTC ISO-8601 conversion. HLC logical ordering must not be mistaken for timestamp text. |
| `event_type` | Numeric WAL header code (`0xA0` / `0xA1`) | An exporter must define a string category; a numeric-code rename is insufficient. |
| `agent_id` | No equivalent field | Header `node_id` identifies a node; payload `subject` identifies the decision subject. Neither establishes the triggering agent identity. |
| `action` | Payload and reader `action` | Same field name and action role. |
| `decision` | Payload and reader `decision` | Same field name. Native decision tags need a defined conversion; they are not automatically the upstream allow/deny/escalate/warn vocabulary. |
| `reason` | Optional payload and reader `reason` | Same optional field name and explanation role. |
| `latency_ms` | Not recorded in this payload | No measured latency may be inferred from event timestamps. |
| `metadata` | Additional native payload/header fields | There is no existing dictionary alias. Any exporter must choose and document which fields it includes. |

The separate Agent Mesh schema in section 4.3 has `previous_hash` and
`entry_hash`; section 4.4 defines its canonical entry hash. NEOTH's
`payload_hash` hashes payload bytes, so neither chain field can be aliased to it.
The July adoption note's `seq` and `hash` list is not the verified section 4.1
schema and must not be used as a serialization contract.

The source anchors are `permissions::gate::audit` (actual JSON emitter),
`wal::events::EVENT_TYPE_PERMISSION_GRANTED` and `EVENT_TYPE_PERMISSION_DENIED`
(shared payload documentation), `wal::header` (binary frame), and
`permissions::audit::AuditEntry` (diagnostic reader projection). The upstream
specification does not change any of these boundaries.
