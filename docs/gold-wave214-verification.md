# Wave 214 Buddy embedding lifecycle

`neoth buddy embedding --config PATH list|status|select|probe|pull|repair|prune`
now delegates to the existing typed `models embedding` implementation. Both
surfaces use the same action enum and output format. The optional custom config
retains its exact filename and instance home.

The Buddy command has no separate cache, download policy or readiness logic.
Selection keeps the existing locked lossless update and confirmed readback.
Status remains a cheap cache observation; only the explicit selected BGE probe
can report freshly verified readiness. Pull, repair and prune retain their
existing audit, updater policy, owned-cache and pending-attempt safeguards.
Unsupported Qwen lifecycle actions fail before that work starts.

This adds the Buddy CLI entry point. The earlier W211 Buddy completion wording
described GUI operation feedback and remains valid for that separate surface.

## Verification boundary

Three source regressions exercise all seven action names and unknown-action
rejection, actual selection through `run_buddy` against a custom temporary
config with unknown-field preservation, and all four unsupported Qwen actions
with unchanged config and no model cache creation. Hosted execution and the
generated CLI reference update are pending. Independent bounded source review
passed. Inventory: 529 sources / 798 universal native / 92 GUI identities,
with platform extras unchanged. The grouped lane now selects 251 tests.
No local executable validation ran.

The W213 source/SHA-bound formatting receipt from GitHub run `35771681385`
on `889d3df8` is imported alongside this batch. Core/CLI `35771703379` and
Grouped248 `35771699017` are separate W213 runs. W212 Grouped236 remains
admitted at 236/236. These results do not establish W214 behavior or release
acceptance. GOLD-LF-P2-24 and cross-platform/GUI/release gates remain open.
