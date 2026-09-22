# Wave 209 sender-confirmed clustering consent

W209 connects the W208 origin/eligibility boundary to an authenticated sender
ceremony. The reserved request, grant and revoke commands are intercepted before
ordinary RAW_TEXT, transcripts, profile learning and provider dispatch. The
challenge must be echoed by the same sender in the same channel account and
conversation. Consent itself covers that sender and channel account; conversation
binding protects the confirmation and does not narrow the W208 consent key.

The challenge lasts ten minutes and persists only a token commitment. Its
issuance records the consent generation. An older challenge cannot adopt a new
generation after a revoke. Command SHA-256, input receipt, conversation, scope,
operation and audit payload bindings are checked before a positive transition.
Fresh explicit consent after a revoke remains possible.

An opaque ingress capability is minted only inside the accepted channel path.
Closed WAL methods derive content-free input/audit descriptors, require marker
authentication, serialize append-once ownership and verify the exact persisted
frame before returning sealed receipts. Generic writer entry points reject all
three ceremony subtypes. Command/token plaintext does not enter those receipts;
replies use the existing policy-controlled channel egress and body-hash audit.

The additive v43 schema stores challenge reservations and terminal audit custody.
A grant becomes eligible only after its bound audit is durable. Revoke first
removes eligibility and quarantines derived state in one transaction. It also
fences a pending re-grant, preserving its terminal custody. Pending revoke audits
cannot disappear through expiry or request replacement. Startup, the existing
daemon drain and shutdown recovery resume exact persisted work using
marker-authenticated input receipts and the closed audit writer.

Core state-machine, migration, writer and real channel-path regressions accompany
the implementation. Their source inventory is bound to this publication; Hosted results remain
required before this slice can be accepted. Independent integrated static review passed after closing the proof-construction,
generation, revoke-race, error-reporting and recovery gaps. Sixteen focused
test identities cover seven core cases, the migration, three writer cases and
five actual channel/recovery cases. All executable validation is pending on
GitHub. No Road checkbox or release gate is
closed by this work. The workstation remains under the absolute local BSOD hold:
no local compiler, Cargo, formatter, code/model parser, tests, product, GUI or
audio execution.
