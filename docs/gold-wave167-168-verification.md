# W167/W168 — active daemon recall and throughput presentation

Status: combined source independently approved; fresh GitHub compilation and
native GUI acceptance are pending. These batches repair the active route used
by the installed GUI bridge controller. Earlier CLI control and direct reducer
tests did not establish this route. No local executable validation ran.

## Recall chips

The existing recall producer emits its already-reduced batch as a typed private
output alongside its unchanged authenticated CLI frame. The daemon runtime,
closed protocol, public bridge and installed controller carry the same batch
to the current Main or Buddy surface. They do not repeat the query, parse a raw
control record, infer provenance or expose recalled text or source identifiers.

The transport retains at most five rows and only the closed status, tier,
optional finite warm-hit score and source-state vocabulary. Empty states,
unknown provenance and score eligibility are checked again at consumer
boundaries. ProviderDone freezes the admitted recall snapshot; cancellation,
replacement, failure and detach clear or fence the active projection.

## Live throughput

An explicit daemon-GUI preparation flag activates the existing W162 producer
without requiring a CLI control token. Tokenless direct CLI and plain daemon
responses retain their existing behavior. The typed companion carries the
original measurement basis, state and inner sample sequence through the active
daemon route. The outer GUI frame sequence remains a separate admission check.

The GUI reuses the existing throughput reducer. Rates come only from producer
samples; final usage totals, text length and outer frame counts cannot create a
rate. ProviderDone, cancellation, failed completion, replacement and detach
clear or fence the live meter. The W164 response-feedback projection stays
separate and terminal-bound.

## Regression and publication boundary

Core tests cover closed bounds, direct mapping and separate inner/outer sequence
preservation. GUI tests cover typed reducer validation and cursor/lifecycle
fences. Two new fixtures install a scripted public bridge and invoke the actual
Main and Buddy send callbacks, then observe their projections and terminal
handling. The public API integration test constructs both event variants.

The macOS native callback catalog, dispatcher and discovery contract contain
22 names. The GUI's new async-trait test dependency uses its existing locked
package and adds the corresponding GUI dependency edge to Cargo.lock. The
independent integrated review and separate lock/cadence follow-up are retained
under work/gold-20260906/wave167-recall-callback and wave168-throughput-bridge.

Source approval and scripted callback source do not establish a successful
build, live-daemon rendering, accessibility or release acceptance. Hosted
native tests and platform-specific GUI execution remain required. Road counts
stay at 1324 total / 1015 checked / 307 open / 2 partial.
