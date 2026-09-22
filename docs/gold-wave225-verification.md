# W225 — Role-policy denial at the actual Claude effect-start boundary

An admitted retry whose Council role policy changes before its effect starts
must close the existing durable request with an `authorization_denied` receipt.
The Claude effect-start helper now uses the W221 terminal operation, retaining
the original retry class and current attempt without inventing another request.

This batch changes only `begin_effect_start_or_role_terminal`. The separate
warm-pane pre-send role fence remains unchanged and is not accepted by this
batch. No complete tmux, subprocess or external provider-delivery proof is
claimed.

## Regression and evidence boundary

The selected native identity is
`providers::cost_authorization::role_dispatch_tests::w225_effect_start_role_rejection_closes_admitted_retry_with_denial_receipt`.

It must bind the real role authorizer to the same recording effect gate,
prepare the retry effect through the permit, reload the accepted role policy,
then invoke the actual Claude effect-start helper. The role-policy start
authority must abort before a Started lease. After draining the authenticated
home WAL, the fixture requires exactly two request/error pairs and a final
`role_dispatch_policy_changed` terminal with `authorization_denied`, origin
class `transient`, and attempt 2.

An initial test draft manually closed a separate gate; independent review
rejected it because it bypassed the production effect/start-authority binding.
The corrected fixture passed independent source review. Hosted execution is
pending; no local compiler, parser, formatter, tests or runtime ran. Grouped282
will include the new identity alongside all 281 prior selections. No Road
checkbox is closed by source changes alone.

Published `1129c61b23171993fe0c0043da16933ccd28f557`; Grouped282
`35787183572` is running on that source. The exact formatter artifact from
Preflight `35787183568` was imported in `ea700f15` after source/SHA256SUMS,
Git preimage, unchanged working preimage, patch-check and postimage verification.
Only the fixture formatting changed. No local formatter ran.
The first Grouped282 run failed before executing tests: two nested-module enum
imports were missing and `expect_err` required Debug on the intentionally opaque
EffectStartLease. The fixture now imports its enums explicitly and matches the
error result without changing production types. A fresh run remains required.
Preflight also detected a stale machine-readable Road summary after P2-10;
the published marker and top-level workstream count are now reconciled.
## Hosted acceptance 2026-09-22

Corrected Grouped282 `35787943413` on
`5dff0afb5443a708c402a1f7f9d5a92c04169e2f` passed all **282/282** exact
selected tests. Admission verified 58 source-path hashes, matrix and Cargo.lock,
the exact selection/execution count, every case terminal and no failed cases.
The real W225 role-reload effect-start fixture passed. The unmodified warm-pane
path and broader P2-14 release/GUI scope remain separate.