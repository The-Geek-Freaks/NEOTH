# Wave 216 Windows regression repair

The Windows job of full CI `35765595152` on `c4176c54` executed 17,489 cases
and failed 14. This batch repairs those exact boundaries; it does not treat
source review as a passing native run.

## Runtime and fixture corrections

- Local-model refresh previously replaced rows with fresh inventory and erased
  a durable `InterruptedUnknown` operation before restart. It now reapplies the
  exact model/operation receipt; the regression checks refresh and restart.
- The two read-only wizard long-polls are checked concurrently. Both must remain
  pending and both must wake after the accepted mutation; semantic publication
  remains the existing production rule.
- Non-briefing Cron requests intentionally carry the guarded Skill registry.
  The test requires that metadata while excluding briefing instructions and
  untrusted system-prompt/tool-policy fields.
- Aggregate Skill authority overflow uses deterministic prerequisite readiness,
  so host capabilities cannot short-circuit the intended atomic-discard check.
- Local chat checks the authenticated W208 RawTextOrigin between the raw text
  and turn journal. Channel ingress derives its real binding-scoped sender hash.

## Terminal mirror contract

Four older prepared-turn tests assumed truthful retry/local shadow after a
refusal. The published W206 terminal mirror deliberately prevents those calls.
The tests now state that contract explicitly: one initial request, no retry or
shadow, original admitted registry A retained, and a genuinely fresh session
seeing accepted registry B. A WAL scan decodes the exact REFUSAL_MIRRORED event
and requires it before the final reply receipt. Final hash and byte length bind
the visible mirror response, and caller terminal release follows final custody.
The finalization-error case retains the earlier audits but emits no successful
final receipt, stream done, or terminal completion. This does not establish
registry propagation through the now-unreachable old refusal-recovery branch;
GOLD-LF-P2-10 remains open for its full multi-path contract.

## Inventory and source gates

The parity ledger accounts for all new BGE-M3, selected-embedding and Buddy
leaves, including cluster-feature leaves. Concrete typed GUI operations remain
Verified only where their callbacks/receipts/readback are present; status-only
and missing exact operations remain Partial or Unwired. The MCP hot-path gate
uses the actual post-reply handoff and preserves route/order/assembly checks.
The outbound-network gate allows only the exact reviewed n8n adapter file,
whose endpoint, proxy, redirect, timeout and body bounds are explicit. The GUI
wizard test binds the actual session/frozen-loss/acknowledgement contract.

W215's admission fixture also authorizes both installed Skills while enabled,
then writes accepted custom config disabling one before registry capture.
Production authority correctly rejected its previous attempt to activate a
Skill that was already disabled.

## Evidence and remaining execution

Grouped255 `35774216773` on `71c0436aeebaf54563837fbfa86db716ee853c80` is
source-bound at 253/255: 54 source paths, exact test identities, matrix and lock
were verified. Both W215 runtime propagation/overflow tests and the W213 actual
start role-revocation test passed. Failures were the known raw-call scanner and
W215 admission fixture. Core test-target type-check and public CLI build passed
in `35774220917`. Preflight on `eefe379d` passed in `35775055262`.

Ten exact core cases join the grouped lane, bringing it to 266; the existing
wizard case remains selected once. Integration and GUI cases stay required in
native CI. Inventory: 530 sources, 809 universal native identities, 92 GUI,
unchanged platform extras. Current source bindings are updated from staged Git
blobs. Independent bounded source review passed before publication; fresh
Hosted compile, behavior and native GUI execution remain required afterward.
The old macOS full-CI run is preserved until its outcome; a new ci.yml dispatch
would cancel it. No Road checkbox or release gate is closed by this batch.
No local compiler, formatter, parser, test or product runtime was invoked.
