# W136 — prompt-visible admitted skill registry

SP-H1 explicitly calls for a session-start summary of skill names and
descriptions. Existing authority-bound routing and selected skill-body
injection do not by themselves make that inventory visible to the provider.
This batch adds that missing summary using the already admitted resolver view,
without changing how a skill obtains execution authority.

The summary contains only bounded metadata from one compound skill snapshot:
identities/descriptions and the config/authority epochs plus snapshot digest.
The effective resolver filters and existing enabled, visibility and path gates
apply before serialization. The complete bounded payload is represented as
typed untrusted data; descriptions cannot become an instruction layer. Bodies,
credentials and tool permissions are not part of the inventory.

The shared request composer receives the inventory in a separate Block D
field. CLI and channel ingress build it from the same filtered resolver that
selects the turn's route. Delegated prompt construction carries the retained
typed context. Retry/fallback coverage must use the actual composer/provider
path and prove an in-flight request cannot pick up a later registry summary.

The eight-file source integration is independently reviewed. A shared borrowed
eligibility iterator checks each metadata entry before retention; the complete
serialized JSON has a separate cap for escape expansion. Five new source
regressions cover exact eligibility/metadata, both size limits, snapshot pinning
and composer placement. Three existing real composer/provider regressions are
strengthened for delegation, truthful retry and local-shadow retention. The
recovery assertions compare one complete canonical envelope byte for byte.
Hosted formatting, compilation and behavioral execution remain required. Non-chat
entry points without an admitted snapshot are not certified by an absent
context field. This batch also cannot manufacture dependency-readiness evidence
for dependency concepts not represented by the current runtime schema.
P2-10 remains open until its complete entry-point/readiness/acceptance scope is
proved. No Road checkbox or count is changed by source presence alone.

All validation remains GitHub-hosted. No local compiler, formatter, parser,
test, fixture, product or GUI execution runs under the workstation restriction.

W136 hosted formatting follow-up: Code Quality 35579924103 passed on 6c9955d0.
Preflight 35579924445 supplied eleven Rustfmt hunks in four W136 files; the
complete log was imported against exact published source mirrors so pending
W137/W138 edits are excluded. Fresh static/full CI remains required. No local
formatter, compiler, test or product was executed and Road counts are unchanged.
