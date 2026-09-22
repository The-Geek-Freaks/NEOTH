# Wave 218 Buddy Config embedding lifecycle

Buddy Config now exposes the existing selected-embedding lifecycle under its
own operator surface. It sends `buddy embedding --config <instance>/freedom.yaml`
commands; core still delegates to the canonical models lifecycle. No model,
cache, download or policy implementation is duplicated.

## Behavior and source contracts

The view shows the confirmed selection and model rows, a Qwen/BGE selector,
and BGE Verify/Pull/Repair/Prune controls. Core determines supported actions.
Qwen remains visible/selectable but cannot start BGE lifecycle operations.
The helper parameterizes only the CLI prefix: Resources uses `models embedding`,
Buddy uses `buddy embedding`, both with the same explicit resolved instance.

Both surfaces share the existing action-active flag and publication revision.
A mutation disables both surfaces until its bounded worker completes. Status
and action publications check the captured revision; an older result cannot
repaint a newer action. Typed decoding and exact selected-model readback precede
publication. Only an explicit probe whose source, model, readiness and clock
pass the existing freshness verifier can announce a freshly loaded Ready model.
Successful cache actions remain neutral rather than implying inference readiness.

The UI follows the existing Buddy/Theme components and tokens; all new callbacks
and properties traverse the generated MainWindow. Static review checked labels,
in-flight disabling and unavailable-state handling. This is not screenshot,
accessibility or live rendering evidence.

The operation ledger now reflects real W211 main-surface handlers, which W216
had conservatively but incorrectly left Unwired. Buddy and main select/probe/
pull/repair/prune bind actual callbacks, synchronous bounded CLI success and
strict result/readback. That is the ledger's existing typed-evidence definition;
no asynchronous operation-ID receipt is claimed. Standalone list stays Unwired,
and status remains Partial.

## Selected evidence and remaining gates

Independent bounded production and native-fixture source reviews passed.
The new source contract is:
`buddy_wiring_tests::w218_buddy_embedding_callbacks_use_instance_config_and_shared_freshness_fence`.

The actual native callback fixture is:
`w58_gui_callback_runtime_tests::w218_buddy_embedding_callbacks_require_exact_config_singleflight_and_fresh_probe`.
It constructs MainWindow, registers production callbacks, invokes generated
callbacks, pumps the Slint event loop and uses the existing staged CLI fixture.
It checks exact Buddy/default-instance arguments, confirmed selection, mismatched
and malformed readback, shared Resources/Buddy singleflight, Qwen with no child,
and stale versus freshly observed probe results. It is selected for Linux and
macOS; the custom macOS list, dispatcher and packaging discovery verifier now
agree on 25 cases. No new claim of native Windows callback execution is made.

Two core parity checks join the grouped lane: callback/handler/evidence binding
and explicit remaining gaps. The live nested-leaf inventory check was already
selected in W216. Inventory: 531 sources, 814 universal native tests, 93 GUI,
21 Linux/21 macOS GUI extras and unchanged Windows/audio extras. Grouped272 and
fresh full CI must execute the current source. Screenshot/accessibility and
release acceptance remain separate. No Road checkbox closes on this batch.
No local compiler, formatter, parser, test executable or GUI runtime ran.
