# Type Design Adversarial — NEOTH v1.0

Source: type-design-analyzer agent, 3-round adversarial.

## ROUND 1 — Inventory: Enforce vs Label

| # | Type | Verdict | Hole |
|---|------|---------|------|
| R1-01 | `EventHeaderV2` (96B) | LABEL | All 19 fields `pub`. Caller can write `wal_format_version = 0xFF`, `_reserved = [0xDE;7]`. static_assert(size==96) only catches size not values. |
| R1-02 | `Hlc` | LABEL | Both fields `pub`. `Hlc { physical_ns: 0, logical: 1 }` compiles — invalid. `hlc_tick_local.expect()` panics on overflow. |
| **R1-03** | **`ts_ns` vs `Hlc` byte layout** | **BUILD-STOPPER** | `SPEC_wire_header_v2_slim.md §3`: `ts_ns: u64` at bytes 29-36. `SPEC_multinode_clock.md §4`: "Hlc at offset [37..49) = 12 bytes". **Two normative specs contradict at bit level. static_assert(size==96) fails on Day-1 build.** Fix: shrink `_reserved: [u8;7]` to `[u8;3]`. |
| R1-04 | `RegionTag` / `brain_region: u8` | LABEL | `PayloadPrefixV4` stores raw u8, not enum. v0.8 renamed to `region_tag` — name drift. Deserialization manually validates 0≤v≤6. No `TryFromPrimitive`. |
| R1-05 | `ProfileClaim<T>` | LABEL | `confidence: f32`, comment says "[0..1]" type doesn't. `decay_rate: f32` — no bounds. `confidence=1.5, decay_rate=-0.1` compiles → oscillating confidence → silent data corruption. |
| R1-06 | `RawClaim` | LABEL | `field: String` "supposed to be" dot-path. `field: "../../etc/passwd"` compiles. Path traversal from misbehaving LLM extractor. |
| R1-07 | `ProfileDelta` | LABEL | `extraction_id: [u8; 16]` — all-zeros silently accepted. Same primitive as `session_id`/`node_id` — interchangeable at call site. |
| **R1-08** | **`PermissionToken<T>`** | **PHANTOM TYPE** | Spec claims compile-time enforcement. **Never defined anywhere in any spec file.** Promised, doesn't exist. |
| R1-09 | `HookResult::{Continue,Abort}` | PARTIAL | Abort reason untyped String. "No tool call" is API discipline, not sealed type. Plugin with global state bypasses. |
| R1-10 | `InboundMessage.human_uuid: Uuid` | LABEL | Same primitive as session_id/node_id throughout. `fn process(session: Uuid, human: Uuid)` allows silent arg-swap. |
| R1-11 | `flags: u8` | LABEL | `flags = 0xFF` compiles, sets reserved bits 5-7 silently. bitflags! would fix. |
| R1-12 | `importance: f32` | LABEL | `importance = f32::NAN` compiles. NaN makes compaction sort undefined. |
| R1-13 | `scope`/`category: u32` | UNDERSPECIFIED | No enum of valid values defined. Any u32 valid. |
| R1-14 | `UserProfile.schema_version: u16` | LABEL | Documentation only. v1 reader receiving v2 has no compile-time signal. |
| R1-15 | freedom.yaml PII flags | LABEL at boundary | serde silently drops unknown keys. Typo `heath: true` = privacy failure with no error. |

## ROUND 2 — Rust-Idiomatic Refactors

**R2-01 — EventHeader sealed constants** (~2h): private fields, public constructor enforces invariants. `wal_format_version`, `event_schema_version`, `header_len`, `_reserved` no longer settable from outside.

**R2-02 — Hlc private fields + Result not panic** (~1h):
```rust
pub fn hlc_tick_local(current: &mut Hlc, now_ns: u64) -> Result<(), HlcError> {
    // Returns Err on overflow, not panic
}
```

**R2-03 — Domain newtypes for IDs** (~2h): `EventId(u64)`, `SessionId([u8; 16])`, `NodeId([u8; 16])`, `HumanId(Uuid)`, `ExtractionId([u8; 16])`. Function `fn sign(session: SessionId, human: HumanId)` — caller cannot swap args.

**R2-04 — Confidence + DecayRate bounded newtypes** (~3h):
```rust
pub struct Confidence(f32);  // [0, 1] enforced
pub struct DecayRate(f32);   // (0, 1] enforced
impl Confidence {
    pub fn reinforce(&self) -> Self { Self(f32::min(1.0, self.0 + 0.1*(1.0-self.0))) }
}
```
Negative decay = oscillating confidence — UNREPRESENTABLE.

**R2-05 — Importance NaN-safe + total Ord** (~1h):
```rust
pub struct Importance(f32);  // never NaN, [0, 1]
impl Ord for Importance { /* unwrap safe: NaN excluded */ }
```

**R2-06 — bitflags! for EventFlags** (~30min): reserved bits 5-7 unrepresentable in safe code.

**R2-07 — PermissionToken<T> phantom + sealed trait** (~4h):
```rust
pub struct PermissionToken<Level>(PhantomData<Level>);
mod sealed { pub trait PermissionLevel {} }
impl<L: sealed::PermissionLevel> PermissionToken<L> {
    pub(crate) fn mint() -> Self { /* only permission manager */ }
}
pub fn vault_read(_t: &PermissionToken<Execute>, k: &str) -> Result<Secret, _> { ... }
// vault_read without Execute = compile error
```

**R2-08 — RegionTag with TryFromPrimitive at deserialize boundary** (~1h): rejects 7-255 at decode. After boundary: only valid variants.

## ROUND 3 — Orthogonal Holes

**R3-01 — Schicht-0 purity not type-enforced.** Tool YAML `schicht: 0` is string annotation. Tool could call `tokio::fs::write` with no error.
Fix: sealed `PureTool` trait, distinct from `EffectAdapterTool`.

**R3-02 — `hemisphere: u8` vs `originator: u8` name+meaning drift.** `SPEC_wire_header_v2_slim.md` says `hemisphere` with `4=BOTH`. `00_DESIGN_v0.8 §1` says `originator` with `4=COUNCIL`. Conflicting normative specs. Misrouting risk.
Fix: resolve to one name, one enum.

**R3-03 — `confidence: f32` duplicated** between ProfileClaim (validated) and RawClaim (unvalidated). Same type, different semantics. Validation boundary invisible.
Fix: `UnvalidatedConfidence(f32)` → `Confidence(f32)` newtype conversion.

**R3-04 — `prompt_bundle_hash: [u8; 32]` unbound to schema version.** Same type as `conversation_hash`. Function taking `[u8; 32]` can receive wrong hash.
Fix: `PromptBundleHash([u8; 32])` newtype.

**R3-05 — `event_schema_version: u8` no typestate.** Code decoding PayloadPrefixV4 should only be callable after version-verify.
Fix: `VersionedHeader<const V: u8>` typestate. `parse_header → Result<VersionedHeader<4>, _>`.

**R3-06 — HlcError propagation.** Already covered R2-02.

**R3-07 — freedom.yaml exhaustiveness gap.** 9 PII keys + 9 UserProfile fields connected by convention only.
Fix: `#[serde(deny_unknown_fields)]` + explicit Rust struct. Typo `heath: true` = parse error.

## Top-5 Refactors Ranked

| Rank | Refactor | Bugs prevented | Dev time |
|------|----------|----------------|----------|
| 1 | **R1-03 fix `ts_ns` vs `Hlc` spec contradiction** | Day-1 build fails without this | 30 min |
| 2 | R2-01 + R2-06 EventHeader private + bitflags! | _reserved corruption, flag-bit accidents, frame-sync breaks | 2h |
| 3 | R2-04 Confidence + DecayRate bounded | Negative decay = oscillating profile, NaN = undefined compaction | 3h |
| 4 | R2-07 implement PermissionToken<T> | Vault access without permission, plugin privilege escalation | 4h |
| 5 | R3-07 freedom.yaml deny_unknown_fields | PII flag typos = silent privacy failure | 1h |

**Total: ~10.5 hours to prevent the largest class of "compiles but wrong" bugs.**

**Critical: R1-03 must be fixed BEFORE any code, or static_assert size==96 fails on Day-1 build.**
