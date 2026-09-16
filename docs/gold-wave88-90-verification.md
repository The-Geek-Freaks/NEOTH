# W88 and W90 - risk-refusal evidence and shared test import

W88 adds the existing `PATCH_APPLY_FAILED` receipt to the early structural-risk
refusal of an immutable admitted patch. The receipt uses stage `risk` and the
pre-apply impact advisory already computed for that patch. Risk scores,
autonomy, override leases, the returned error, and the refusal to apply are
unchanged. The event registry documents the added stage and refusal reason.

The regression fixture creates 200 real multi-author Git commits with one
fast-import stream and synchronizes the temporary checkout before indexing.
History construction needs three Git child processes instead of 400. The test
enters the actual Full-autonomy/no-override gate and verifies each task's exact
error, no applied patch, exactly one failure receipt, and the available, stale,
and missing advisory states. Available evidence binds the root, generations,
impact digest, calibrated test-gap outcome and non-absence semantics; raw patch
and provider text remain absent. This is source-level coverage until remote
execution passes.

W90 repairs the four `ImpactOptions` resolution errors observed in completed
strict Linux, beta and SSH CI jobs at source `5a8540f5`. One explicit import in
the shared controller's nested test module fixes the GUI binary and both core
integration-test inclusion contexts. Production behavior and assertions are
unchanged. After those failures were confirmed, the remaining immutable-source
Windows/macOS builds were cancelled. Their execution steps did not run, so any
uploaded cached JUnit files are not fresh test evidence. The cancellation did
not save a new Cargo cache; the prior compatible macOS cache remains available.

The [source manifest](verification/gold-wave88-90-source-manifest.json) binds
290 inputs. The [test matrix](verification/gold-wave88-90-test-matrix.json)
requires 49 native and 6 GUI test identities. Independent paired review approved
the risk receipt and event documentation; root review approved the one-import
repair. Rustfmt passed on all three changed Rust files and all 11 roadmap
contracts passed. Local validation is limited to those static checks;
all Rust compilation, Clippy, linking and test execution remain GitHub-hosted.
The separate W86 portable preview `35080018852` still builds `c736c376` and must
be accepted against that exact producer snapshot, not represented as this batch.

W89's native macOS GUI main-thread correction remains a separate WORK proposal.
No roadmap checkbox closes here: 1324 total / 1015 checked / 307 open / 2 partial,
raw309 / pre-tag308. Neither full runtime acceptance nor release readiness is
claimed.
