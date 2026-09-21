# Gold Wave 151 verification record

## Evidence boundary

This record describes the current source seams and the focused verification
identities for the typed Ouro Q8 GUI path. It is not a release, completion, or
runtime acceptance statement. No compiler, parser, formatter, test, GUI
runtime, model download, cache operation, screenshot, accessibility inspection,
Git, or network operation was run while preparing this record.

The native callback fixture and macOS discovery/dispatch entries are implemented.
Their source presence is a required execution seam, not a runtime result.

## Product result represented in source

The Settings → Hemispheres card offers one cache-only check: it runs the exact
JSON command for `ouro verify-q8` against an already published local cache.
It does not download a model, fetch a cache, repair/promote a generation,
change configured quantization, or claim that an in-flight device load was
cancelled. A typed verified result alone exposes the receipt, device, and
two-forward summary. A typed failed result, malformed result, timeout, or other
observer error is visibly unverified with success identity cleared.

## Current source-only observation

### Typed Q8 boundary

- `SRC/neothd-gui/src/gui_action.rs` registers `ouro_q8` and reexports the
  runner/outcome surface.
- `SRC/neothd-gui/src/gui_action/ouro_q8.rs::run_ouro_q8_verify` owns the
  special nonzero-exit-aware process observation. It captures stdout and stderr
  independently with bounded captures and deadline-based receives rather than
  a blocking `join` or `child.wait`.
- Its strict wire requires outer and inner tested mode `q8`. Configured mode is
  accepted only as a display label (`none` or `q8`). A zero exit must pair with
  a fully verified result; a nonzero exit must pair with the exact typed false
  result. Crossed pairings reject.
- Verified data requires canonical lower-case SHA-256 receipt and forward
  digests, distinct forwards, forward/context claims, `detail: null`, and loop
  steps in `1..=8`. Failed data must carry no success-only identity or forward
  claim and must carry usable bounded detail.
- `OuroQ8VerifyError.process_exit_observed` keeps the distinction between a
  direct child terminal state actually observed and one that remains
  unobserved. Neither case asserts device-loader cancellation.

### Controller, card, and child observation

- `SRC/neothd-gui/src/ouro_gui.rs` registers the callback controller. Its
  singleflight guard and revision prevent duplicate launch and stale result
  publication; dispatch clears prior verified identity before starting work.
- `SRC/neothd-gui/src/main.rs` includes the Q8 action registration and the
  native fixture entrypoint. `ui/main.slint` forwards the paired state and
  callback into `ui/settings.slint`.
- The Settings card names the already-published-cache boundary and the lack of
  a device-load cancellation acknowledgement. It disables while running or
  while a process exit remains unobserved, and it exposes receipt/device/forward
  summary only for a verified projection.
- The current native fixture uses the staged fake `neothd` binary and permits
  only the `ouro-verify-q8` call marker. It covers success, malformed typed
  receipt, typed failure, recovery to success, and a blocked duplicate click.
  It is source present but has not been executed in this record.

## Required focused test identities

The following identities are required evidence for the typed boundary and GUI
controller. They are not results from this record.

| Area | Test identity | Required observation |
| --- | --- | --- |
| Typed verified wire | `gui_action::ouro_q8::tests::accepts_verified_q8_even_when_configured_none` | A configured `none` result may still prove an exact tested Q8 verification. |
| Typed nonzero failure | `gui_action::ouro_q8::tests::accepts_typed_nonzero_failure_without_success_identity` | A structurally clean nonzero false result is typed failed, not success or a generic decode error. |
| Exit/result binding | `gui_action::ouro_q8::tests::rejects_crossed_exit_and_verification_claims` | Zero/false and nonzero/true pairs are protocol errors. |
| Exact wire shape | `gui_action::ouro_q8::tests::rejects_missing_nullable_key_and_unknown_fields` and `gui_action::ouro_q8::tests::rejects_duplicate_wire_keys` | Missing nullable fields, unknown fields, and duplicate fields reject. |
| Q8 evidence rules | `gui_action::ouro_q8::tests::rejects_wrong_loop_mode_and_context_claims` | Wrong mode, bad loop count, identical forwards, and false forward/context claims reject. |
| Failed-result contamination | `gui_action::ouro_q8::tests::rejects_success_data_on_typed_failure_and_normalizes_detail` | A false result cannot carry success identity; operator detail is bounded/normalized. |
| Child observation | `gui_action::ouro_q8::tests::capture_receive_returns_while_the_reader_is_still_held` | Deadline receive returns before a held reader releases; bounded capture behavior remains intact. |
| Native controller fixture | `w58_gui_callback_runtime_tests::w151_ouro_q8_callback_requires_typed_receipt_and_keeps_singleflight` | Generated MainWindow receives typed success/failure projections, clears stale identity, rejects duplicate in-flight click, and dispatches only the cache-only Q8 command. |
| Actual Q8 runtime | W147 `ouro verify-q8` retained-lease/two-forward acceptance on an immutable published cache | The real CLI, cache, device, retained lease, and two forwards must be observed separately from the GUI fixture. |

## GUI source/text evidence and missing evidence

Source/text evidence supports the callback and property forwarding, the
disabled-running/unavailable button state, text that says the card is a local
published-cache check, the no-download/no-settings-change boundary, and the
honest non-cancellation copy. It does not establish Slint compilation,
rendered geometry, focus order, screen-reader accessibility, keyboard behavior,
contrast, responsive overflow, native event-loop execution, or real device and
cache behavior.

The typed capture test is an important child-observation seam, but it is not
evidence that a real descendant retaining a production pipe, a real Ouro
device-load worker, or a real published model cache completed as intended.

Hosted module follow-up: Preflight35600252846 on340252fc exposed two headless
test inclusions that resolved the nested Ouro module beside gui_action.rs.
The explicit gui_action/ouro_q8.rs path now binds all three inclusion contexts.
The runner is unchanged. Fresh hosted formatting and compilation remain required.
