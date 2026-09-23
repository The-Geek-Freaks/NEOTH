# Gold wave 388 — Research terminal effect state

Group780 run `35857339883` reached the real successful Research lifecycle after
the W368 fixture budget correction. The run was durably `Completed`, emitted
both lifecycle WAL receipts, made its two provider calls, and carried an
audit `effect_started` event. It failed only because the fixture treated
`effect_started` as a terminal-history bit.

`research_runs::complete` intentionally clears `effect_started` after settling
wall time and clearing the attempt token. The field denotes an active,
in-flight effect window; the durable audit records its historical crossing.
The fixture now asserts terminal `effect_started == false` and explicitly
requires the `effect_started` audit event, while preserving completed audit,
real provider-call, WAL start/completion, and terminal no-replay checks.

No production transition changed. No local Cargo, compiler, parser, formatter,
test, or runtime command ran under the BSOD hold. Hosted rerun evidence remains
required.