# W138 — operator-owned per-skill autonomy caps

Integrated source passed independent review. Hosted compilation,
behavioral tests and GUI acceptance remain required. GOLD-LF-P2-12 stays open;
this report does not change Road counts or claim runtime acceptance.

## Policy and invocation boundary

The canonical operator configuration is
`custom_autonomy.skill_overrides: {skill-id: {level, overrides}}`. It uses the
same validated SkillId as skill creation, rejects unknown fields and malformed
action maps, and limits the map to 128 skills. Skill package manifests cannot
supply autonomy authority. An empty map preserves the legacy trust fingerprint.

Each selected, admitted route retains its own configured cap. For each action,
Deny dominates Confirm, which dominates Allow; Custom is evaluated per action,
not compared as a linear level. CLI and channel pipelines carry the capability
through provider authorization, retry/fallback and MCP dispatch.

A capped route retains its accepted ReloadController and reads current global
autonomy at the effect gate. The accepted provider topology, token budget and
selected route remain fixed for the turn. No-cap routes preserve their existing
snapshot behavior. A cap's own Confirm cannot be resolved by MCP SmartApprove;
the existing explicit confirmation/lease path remains responsible for approval.

## Operator surfaces

`neoth --output json autonomy skill show|set|reset` shares one typed CLI contract
with Settings and Buddy. Set requires an admitted skill. Reset can remove an
orphaned configured entry without reactivating it. Mutations use the existing
prepared config commit, audit binding, reload sentinel and exact readback.
Idempotent operations report no change and no reload request.

Show and Buddy use a separate read-only inventory path. They create no lock,
key or recovery files and do not reconcile journals or remove stage artifacts.
Uncertain installed recovery state remains inert; the independent bundled
layer remains observable. Local persisted readback never claims daemon
application.

The GUI binds receipts to the selected ID and exact requested cap, validates
change/reload consistency, and requires matching fresh readback before repaint.
Generation checks reject obsolete callback completions. Idempotent Set displays
that no reload was requested. Buddy exposes the same read-only cap data.

## Regression source and review corrections

Core fixtures cover the restrictive action intersection, legacy fingerprint,
config-load validation and map limits. Effect fixtures exercise real provider
and confirmation gates, retained reload policy, and no-cap compatibility.
Read-only fixtures preserve recovery-artifact bytes and forbid lock creation.
The native registered GUI callback fixture covers inspect, incorrect receipts,
idempotent Set, conflicting fresh Set/Reset readbacks and inventory refresh.
Its exact identity is included in the eleven-entry macOS harness catalogue.

Review corrected stale per-turn global authorization, SmartApprove bypass of
cap-origin Confirm, read-only inventory reconciliation, GUI idempotency and
unbound readback, plus source-level ownership/Debug issues. The final source
manifest and test matrix must bind the admitted hashes and exact test identities.

No local compiler, formatter, parser, test, fixture, product or GUI was run.
Validation is exclusively GitHub-hosted because of repeated workstation BSODs.

## Final admission boundary

The cumulative manifest binds 315 source inputs. The native matrix requires
166 exact identities, including 24 additional W138 identities; GUI coverage
requires 22 universal identities plus six Linux/macOS callbacks. The eleventh
macOS native harness callback is the registered W138 inspect/set/reset flow.

Controlled channel confirmation accepts a real reload before answering yes;
the action still returns Denied. A separate MCP preflight-to-authorization
reload refuses a real SmartApprove grant. Both decode writer-backed WAL
records and change Standard to Custom so stale audit levels cannot pass.
The no-cap SmartApprove baseline retains its writer-backed Allow evidence.
Audit level and effective decision use one captured snapshot. The existing
TrustEvent does not persist the configuration fingerprint; the fixtures'
fingerprint comparison is in-memory and is not claimed as WAL evidence.

Final review SHA-256:
87104D03EA919FD364F5B685E2B810F1D590DC003F1F1D5CE0E16B5579FB8DEB.
All dynamic outcomes remain pending GitHub-hosted execution. No leaf checkbox
is closed, and W142 self-improve work is excluded from this admission.
