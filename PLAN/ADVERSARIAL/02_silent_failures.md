# ADVERSARIAL -- Silent Failure Analysis v1.0
# NEOTH v1.0 Design: What Fails Without Anyone Noticing

Status: adversarial analysis -- not a spec, not build guidance.
Target specs: 00_DESIGN_v1.0_FINAL, SPEC_wal_lifecycle, SPEC_proactive_learning,
              SPEC_multinode_clock, SPEC_channels, SPEC_skill_plugin_system,
              SPEC_wire_header_v2_slim, SPEC_recall_parity_methodology,
              RUNBOOK_phase3_cutover, tool_framework_v4_1, SPEC_mirror_refusal

---

## ROUND 1 -- Silent Failure Inventory

### SF-01: Profile Confidence Drops Below 0.6 With No WAL Event
Severity: CRITICAL | Detection-Gap Depth: 5/5 (architectural blind-spot)

Spec location: SPEC_proactive_learning.md ss 4, 6

Mechanism: Decay is lazy/on-read.
  confidence = confidence * decay_rate.powi(d as i32)
When a field like identity.employer crosses the 0.6 injection threshold going DOWN,
no WAL event is emitted. WAL events for profile: 0x30 PROFILE_DELTA (extraction/mutation)
and 0x31 PROFILE_REINFORCE (reinforcement). NO 0x3X event for threshold crossing.

Auto-drop event exists only at 0.1: confidence < 0.1 removes from idx_profile active view.
The range [0.1, 0.6) is a WAL dead zone.

Silent outcome: identity.employer was injected into Block-B last week at confidence=0.72.
Today it decayed to 0.58. Block-B no longer contains employer. The assistant stops using
that context. Alex notices the assistant asks where he works.
No event, no log, no alert. Time-to-notice: weeks or never.

Fix: Emit WAL 0x37 PROFILE_THRESHOLD_CROSS on crossing 0.6 in either direction.
Add crossing_direction: Up | Down, old_confidence, new_confidence to payload.
SPEC_proactive_learning.md needs this event type added to the event catalog.
---

### SF-02: HLC Frozen-Wall-Clock Logical Counter Silent Corruption
Severity: CRITICAL | Detection-Gap Depth: 4/5

Spec location: SPEC_multinode_clock.md ss 3.1, 6

Mechanism: hlc_tick_local increments logical when now_ns <= current.physical_ns.
Clock-skew detection fires when abs(now_wall_ns - hlc.physical_ns) > 60s.
If now_wall_ns is FROZEN (NTP daemon dead, clock stuck):
  hlc.physical_ns advances with the first tick and stops.
  Every subsequent call: now_ns == hlc.physical_ns exactly.
  Skew = abs(frozen - frozen) = 0. Alert threshold 60s. NO ALERT FIRES.
  logical increments on every event: 0, 1, 2, ..., 4294967295.
  At overflow: checked_add(1).expect panics.
  Before panic: WAL ordering valid but physical_ns is wrong for days.

Silent outcome: recall temporal queries return systematically wrong results.
No error, no warning. Panic only after days of silent corruption.

Fix: Emit 0x2F HLC_STALL_DETECTED when logical > LOGICAL_WARN_THRESHOLD (e.g. 1000).
SPEC_multinode_clock.md needs this guard in addition to 0x2E CLOCK_SKEW_DETECTED.

---

### SF-03: emit_inbound Fires for Blocked Messages (False-Positive CHANNEL_INBOUND)
Severity: HIGH | Detection-Gap Depth: 3/5

Spec location: SPEC_channels.md channel_ingest.yaml pipeline

Mechanism: channel_ingest.yaml step order:
  normalize -> allowlist_gate -> mention_gate (cond: allowlist.allowed)
  -> command_gate (cond: mention.should_process)
  -> resolve_identity (cond: command.should_process)
  -> emit_inbound (NO CONDITION GUARD)
  -> dispatch_agent (cond: command.should_process)

emit_inbound has no condition guard. A message that fails allowlist_gate (allowed=false)
still triggers emit_inbound and emits WAL 0x24 CHANNEL_INBOUND.
No corresponding 0x25 CHANNEL_OUTBOUND ever follows. No CHANNEL_GATE_REJECTED event exists.

Silent outcome: WAL accumulates 0x24 events for every non-allowlisted sender.
Metrics show inbound volume 10x higher than actual processed volume.
Phase-3 migration imports all ghost events. Shadow-run flags false parity failures.

Fix: Add condition guard to emit_inbound: cond: allowlist.allowed.
Add WAL event 0x28 CHANNEL_GATE_REJECTED for audit of dropped messages.
SPEC_channels.md needs both the yaml fix and the new event type.

**RESOLVED 2026-05-30 Session 29 (F-03 vollausbau, verify-first).** The
PRIMARY concern — false-positive `CHANNEL_INGRESS` for blocked senders —
is MOOT against the real code: the spec-era `emit_inbound`-with-no-guard
never shipped. The Telegram adapter gates the allowlist in
`channels/telegram.rs` ("Allowlist check FIRST — before we read the text,
before we touch the WAL") and `return Ok(())`s the drop BEFORE the
pipeline handler (which is where `0x32 CHANNEL_INGRESS` is emitted, in
`serve.rs`). So a blocked sender already produces NO ingress frame —
nothing to guard. The genuinely-open half — AUDIT of the drop — shipped:
new `EVENT_TYPE_CHANNEL_GATE_REJECTED = 0x3B` (channels band; the spec's
`0x28` was already taken). `TelegramChannel::with_gate_writer` threads the
daemon's single WAL writer into the adapter (cheap handle clone — no
second-writer/single-writer conflict); the allowlist drop now emits a
`0x3B` frame `{channel, sender_id, reason: "not_on_allowlist", ts_unix}`
(numeric id + reason only, NO text since the gate fires pre-text-read) via
the best-effort `emit_gate_rejected` helper on BOTH the new-message AND
edited-message paths. `neoth wal show --type channel_gate_rejected` now
surfaces rejected inbound that was previously `tracing::warn`-only +
invisible at the default log level. Slack/Discord adapters get the same
`with_gate_writer` treatment when an operator wires their allowlist
(Telegram-first per operator pick). 3 telegram tests + SC-01a
`every_event_type_constant_is_wired` guard green (0x3B is emitted, not
defined-dead). clippy `--lib --tests` crate-wide 0 warnings, fmt clean.

---

### SF-04: content_hash Ambiguity Produces Dedup Collisions Across Boundaries
Severity: HIGH | Detection-Gap Depth: 4/5

Spec location: SPEC_wire_header_v2_slim.md s 4 (PayloadPrefixV4), SPEC_wal_lifecycle.md

Mechanism: content_hash = xxh3-128 of raw content bytes. Three plausible implementations:
  A) xxh3-128 of event body after PayloadPrefixV4 (post-prefix bytes)
  B) xxh3-128 of full payload field in EventHeaderV2
  C) xxh3-128 of original source text before WAL structuring

Implementations A and C on two nodes: identical source text -> different content_hash.
Dedup misses true duplicates.

Migration dedup: SHA-256(normalized_text_bytes || scope_le32 || source_origin_ascii).
Live WAL: xxh3-128 of undefined field. Different function + different field definition.
Every migrated event gets reimported on a second migrate run.

Silent outcome: duplicate events in WAL. Recall returns same memory twice.
Profile reinforcement fires twice per extraction. Confidence values inflated.

Fix: Define raw content bytes = UTF-8 bytes of original source text before normalization.
Align migration dedup to use same hash and field definition.
SPEC_wire_header_v2_slim.md needs a normative definition. No ambiguity allowed.

---

### SF-05: Skill Truncation Drops Skills With No Production Event
Severity: HIGH | Detection-Gap Depth: 3/5

Spec location: SPEC_skill_plugin_system.md s 7

Spec text: WAL on skill activation -- No event emitted (Schicht-1 transient state).
0x29 SKILL_INJECT_SKIPPED defined only for eval sessions (SPEC_recall_parity_methodology s9).

Mechanism: Block-B 3000-token hard limit. Under high context load, calendar_access
or tool_router silently excluded from Block-B. No truncation priority order defined.
No production event on truncation.

Silent outcome: tool invocations fail with tool not found or wrong routing.
No log links failure to skill exclusion. Developer sees tool failures, not truncation.

Fix: Emit 0x29 SKILL_INJECT_SKIPPED in production (not just eval).
Payload: skill_id, reason (truncation | disabled | eval_isolation), block_b_tokens_used.
Define truncation priority order. SPEC_skill_plugin_system.md needs production coverage.

---

### SF-06: compaction_epoch Undefined Allows Idempotency Key Collision on Re-Compaction
Severity: HIGH | Detection-Gap Depth: 4/5

Spec location: SPEC_wal_lifecycle.md ss 4, 5

idempotency_key = {segment_seq}_{compaction_epoch}. compaction_epoch is never defined.
Under interpretation where epoch is not persisted: crash mid-rename (.cpt.tmp exists,
.cpt absent). Daemon restarts, re-runs compaction with epoch=1 again.
Same idempotency_key. Dedup skips second compaction as already-done.
Segment remains un-compacted. Tombstoned events never physically removed.

Silent outcome: disk fills slowly. No error until disk-pressure threshold (70-95%).
neoth wal compact reports success. Disk usage does not decrease.

Fix: Define compaction_epoch as u32 stored in SegmentHeader at offset [N],
incremented atomically before .cpt.tmp write, persisted there.
SPEC_wal_lifecycle.md must define field location, initial value, crash-recovery behavior.

---

### SF-07: Migration Hash Mismatch Allows Silent Double-Import
Severity: MEDIUM-HIGH | Detection-Gap Depth: 3/5

Spec location: RUNBOOK_phase3_cutover.md Day 63-65

Migration dedup: SHA-256(normalized_text_bytes || scope_le32 || source_origin_ascii).
Live WAL content_hash: xxh3-128 of raw content bytes (ambiguously defined, see SF-04).
Two different functions over two different input definitions.
Migrated event and live event with identical source text have different content_hash.
Both stored. Both returned in recall.

Second migrate run after compaction: dedup index entries removed by compaction.
Second pass reimports all events. All Jarvis memory exists 2x in WAL.

Silent outcome: profile reinforcement fires on every duplicate. Confidence values inflated.
Fields promoted to Block-B that should not be (boosted by duplicate evidence).
Seems like a feature (high confidence) not a bug (inflated from duplicates).
Time-to-notice: when Alex notices confidence=0.97 on a field he mentioned once.

Fix: Add post-import WAL event count verification to runbook Day 65.
Emit WAL 0x3F MIGRATION_DUPLICATE_DETECTED on second import of same content.
RUNBOOK_phase3_cutover.md needs the verification step and the new event type.
---

## ROUND 2 -- Detection Gap Analysis

### SF-01 Detection Gap
Per-spec detection: WAL 0x30 PROFILE_DELTA on any profile mutation.
Gap: threshold crossing (0.6) is not a mutation. Decay runs lazily on-read
with no write-back to WAL until the next actual mutation.
User experience: assistant responds without employer context. User thinks it has a bug.
No anomaly in neoth profile show unless run on the exact session where decay crossed 0.6.
Time-to-notice: months if employer rarely referenced. Days if daily -- but only
if Alex connects wrong behavior to profile state, which is non-obvious.

### SF-02 Detection Gap
Per-spec detection: 0x2E CLOCK_SKEW_DETECTED when abs(now_wall - hlc.physical) > 60s.
Gap: frozen clock produces skew = 0 by definition. Spec assumes clock drift, not death.
Frozen clock is invisible to the skew detector.
User experience: neoth recall last Tuesday returns results from Monday. No error.
Time-to-notice: until timestamps are noticed wrong in profile inspect output, or until
logical counter overflow panic (potentially days/weeks after corruption starts).

### SF-03 Detection Gap
Per-spec detection: none. No WAL event for gate rejection. 0x24 emitted regardless.
Gap: CHANNEL_INBOUND emitted before evaluating whether message should be processed.
User experience: metrics show high inbound count, no matching outbound events.
Ops investigates provider connectivity. Finds nothing.
Time-to-notice: only when someone reads the pipeline YAML and notices the missing guard.

### SF-04 Detection Gap
Per-spec detection: CRC32c per WAL frame (wire integrity). payload_hash (xxh3-64).
Gap: content_hash is application-level semantic dedup, not wire integrity.
Different implementations produce logically valid WAL events with wrong dedup identity.
CRC passes. payload_hash passes. Dedup fails semantically.
User experience: recall returns duplicate results. Alex thinks it is a recall bug.
Diagnosis requires knowing the implementation divergence.

### SF-05 Detection Gap
Per-spec detection: 0x29 SKILL_INJECT_SKIPPED exists but is eval-only.
Production: no event for skill truncation. No metric for block_b_fill_level.
Gap: spec explicitly chose not to emit skill activation events in production.
Skill availability is invisible in production.
Time-to-notice: only when someone correlates block_b_tokens_used with tool failure rate,
requiring a metric that does not exist in the spec.

### SF-06 Detection Gap
Per-spec detection: idempotency_key uniqueness check should catch duplicate compact runs.
Gap: if compaction_epoch is not persisted, uniqueness check creates a false negative.
Same key = skip, even on crash-recovery. No alert.
User experience: neoth wal compact reports success. Disk usage does not decrease.
Time-to-notice: disk pressure alarm at 70% threshold. By then, tens of GB of tombstones.

### SF-07 Detection Gap
Per-spec detection: neoth migrate parity-check on Day 65.
Gap: parity-check evaluates recall quality, not storage dedup parity.
User experience: parity-check passes. WAL has 2x events. Confidence inflated.
neoth profile show shows high confidence on everything. Seems like a feature.
Time-to-notice: when Alex notices confidence=0.97 on a field he mentioned once.
---

## ROUND 3 -- Orthogonal Silent-Failure Categories

### OA-01: Alert-Fatigue Collapse of Clock-Skew Monitoring
Severity: MEDIUM | Detection-Gap Depth: 3/5

0x2E CLOCK_SKEW_DETECTED is diagnostic-only with no action required.
In multi-node setup (debian + Veronica), minor clock skew is expected, no events.
Real skew issues cluster: NTP daemon restarts produce bursts of 0x2E. After legitimate
bursts, operators normalize the alarm.
When frozen clock occurs (SF-02), ABSENCE of 0x2E is the anomaly. Nobody notices absences.
Spec has no expected-event heartbeat watchdog. Silence is the real alarm here.
No mechanism to detect absence of expected events.

### OA-02: Corrupted Skill Injection Creates Invisible Prompt Contamination
Severity: HIGH | Detection-Gap Depth: 5/5

Block-B sources: lowkey_identity, freedom_scope, jarvis_identity, profile_summary.
prompt_bundle_hash covers full context bundle. content_hash covers source content.
Neither field covers Block-B injection content against a reference hash of expected skill.

If a skill YAML is corrupted on disk (filesystem error, botched editor save), corrupted
content is injected into every Block-B. WAL records event with prompt_bundle_hash of
corrupted bundle. No comparison against reference hash of expected skill content.
No 0x29 SKILL_INJECT_SKIPPED fires in production. No alert.

Worst case: corrupted jarvis_identity skill causes gradual persona drift.
Time-to-notice: only when neoth profile show --injected is read carefully.

### OA-03: Shadow-Run Parity Gap: Kumpel-Voice vs Jarvis-Neutral Both Score On-Tone=5
Severity: MEDIUM | Detection-Gap Depth: 3/5

SPEC_recall_parity_methodology.md rubric Dimension 3 (On-Tone) grades on:
blunt, direct, German if German, no pleasantries, technical substance exact.
NEOTH Kumpel-voice and Jarvis neutral-voice both satisfy this rubric.
The rubric does not distinguish Kumpel-register from technical-neutral-register.

Shadow-run parity check passes. NEOTH ships. Users notice the voice is wrong.
The brand-voice constraint (00_DESIGN_v1.0_FINAL.md s 6) is never evaluated.
Spec defining voice constraint and spec defining measurement are disconnected.

### OA-04: Hebbian Decay Valley -- Confidence Oscillates Around 0.6 Indefinitely
Severity: MEDIUM | Detection-Gap Depth: 4/5

Reinforcement: new_conf = min(1.0, old_conf + 0.1 * (1.0 - old_conf))
Decay: conf = conf * 0.995^d (per day)

At conf=0.6, one reinforcement: 0.6 + 0.1*0.4 = 0.64. Injected into Block-B.
After ~12 days: 0.64 * 0.995^12 = 0.602. Barely injected.
After ~15 days: 0.64 * 0.995^15 = 0.593. Not injected.
One mention -> field oscillates in/out of Block-B over ~2-week cycles.
Each cycle: no WAL event (see SF-01). No observable signal.
User experience: intermittent amnesia every two weeks. Hard to diagnose.

### OA-05: WAL Segment Boundary Event Splitting Undefined
Severity: MEDIUM | Detection-Gap Depth: 3/5

SPEC_wal_lifecycle.md: rotation at 256 MiB or 24h.
No definition of behavior when a single event payload exceeds remaining segment space.

Possible silent behaviors:
  A) Event written crossing boundary. Segment grows past threshold.
  B) Event split (STREAM_PARTIAL flag exists) but reassembly protocol not defined.
     If reconstruction has a bug: event lost silently.
  C) Event dropped silently because it does not fit.

Large council verdict or profile export payload could exceed 1-2 MiB.
Near a segment boundary, silent data loss is possible.
No test in any spec covers this boundary condition.
---

## Ranked Summary: Top-7 by User Impact

| Rank | ID    | Failure                                   | User Impact                              | Depth | Spec Requiring Fix                    |
|------|-------|-------------------------------------------|------------------------------------------|-------|---------------------------------------|
| 1    | SF-02 | Frozen clock, HLC stall                   | Temporal recall permanently wrong        | 4/5   | SPEC_multinode_clock.md               |
| 2    | SF-01 | Profile drops below 0.6, no event         | Assistant forgets facts intermittently   | 5/5   | SPEC_proactive_learning.md            |
| 3    | OA-02 | Corrupted skill injection                 | Persona drift, invisible contamination   | 5/5   | SPEC_skill_plugin_system.md           |
| 4    | SF-04 | content_hash ambiguity, dupe import       | Inflated profile confidence, dupe recall | 4/5   | SPEC_wire_header_v2_slim.md           |
| 5    | SF-03 | emit_inbound no guard, ghost events       | Metrics confounded, ops misled           | 3/5   | SPEC_channels.md                      |
| 6    | SF-06 | compaction_epoch undefined, stuck compact | Disk fills silently                      | 4/5   | SPEC_wal_lifecycle.md                 |
| 7    | OA-04 | Decay valley, 2-week oscillation          | Intermittent amnesia, hard to diagnose   | 4/5   | SPEC_proactive_learning.md            |

---

## Specs Requiring Explicit Detection Mechanism Added

| Spec                           | Missing Detection                                       | Proposed WAL Event / Guard         |
|--------------------------------|---------------------------------------------------------|------------------------------------|
| SPEC_proactive_learning.md     | 0.6 threshold crossing (up and down)                   | 0x37 PROFILE_THRESHOLD_CROSS       |
| SPEC_multinode_clock.md        | Frozen wall clock (logical counter stall)               | 0x2F HLC_STALL_DETECTED            |
| SPEC_channels.md               | Gate rejection audit event                             | 0x28 CHANNEL_GATE_REJECTED         |
| SPEC_wire_header_v2_slim.md    | content_hash definition (raw content bytes = ?)        | normative definition required      |
| SPEC_wal_lifecycle.md          | compaction_epoch persistence + segment overflow policy | SegmentHeader field + split policy |
| SPEC_skill_plugin_system.md    | Production skill truncation event                      | 0x29 SKILL_INJECT_SKIPPED in prod  |
| RUNBOOK_phase3_cutover.md      | Post-import WAL event count verification               | 0x3F MIGRATION_DUPLICATE_DETECTED  |
| SPEC_recall_parity_methodology | Kumpel-voice dimension missing from rubric             | Dimension 6: Brand-Voice           |
