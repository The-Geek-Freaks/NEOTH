# W162 - live stream throughput

Status: source-reviewed integration prepared for hosted verification. GOLD-LF-P2-29
remains open until the integrated source passes hosted native/GUI verification.
All executable validation runs on GitHub-hosted runners during the workstation
BSOD hold. No local compiler, formatter, parser probe, test or GUI run is allowed.

## What the display measures

Current providers expose final token usage rather than proven incremental output
token deltas. The working live unit is therefore **stream events per second**:
nonempty visible events accepted by the current request's visible output path.
Reasoning, control records, empty chunks, errors, final usage totals and withheld
output cannot become visible-event samples. Final token totals remain part of
the separate completed-turn accounting path.

A future provider may use **provider tokens per second** only with an explicit,
verified incremental token source. Bytes, chunks and event rates must never be
relabeled as token rates.

## Bounded rolling window and transport

The core keeps 1000 fixed millisecond buckets covering `[now_ms-999, now_ms]`.
It uses a fixed one-second denominator, retains bursts above sixteen events,
expires a bucket at 1000 ms, and rejects backward time without mutating state.
Terminal clearing and reset define distinct request lifetimes. Saturating sums
are reconstructed from live buckets so expired saturation cannot erase newer
events.

Throughput uses the existing authenticated v3 stream-control transport with its
own contiguous sequence, request ID and private control token. State, basis,
unit, reason and rate form a closed bounded schema. GUI parsing rejects unknown
fields, mismatched units, wrong requests/tokens, sequence gaps and late frames.
Provider completion and the final sentinel close the throughput lifetime.

## Presentation and required evidence

Chat and Buddy must show the same explicit unit and distinguish measuring,
paused, unavailable, cancelled and error states. Replacement, cancellation,
settlement, detach and session/history switches clear the transient projection.
It does not enter conversation history, previews, clipboard content or live WAL
samples. Direct CLI response text and terminal TPS accounting remain separate.

Required hosted evidence covers window boundaries and bursts, event eligibility,
wire schema and independent sequencing, forged/stale/post-terminal rejection,
actual Chat/Buddy callbacks and all owning-request cleanup paths. The core, reducer, producer and GUI integration have scoped source reviews.
The producer review found idle-timer starvation under sustained non-visible
events; a persistent Skip interval and actual select-loop regression address
that defect. These reviews do not establish rendered appearance, accessibility
or native runtime behavior.
Retained design, source inventories and scoped reviews are under
`work/gold-20260906/wave162-live-tps`. Final admission must record exact integrated
source hashes and native/GUI test identities in the canonical Gold matrix.

## Source admission

Current integrated manifest: 353 inputs; 325 universal native + 3 Windows-only
+ 2 Unix-only requirements; 61 universal GUI + 13 Linux/macOS callbacks; seven
optional adapter cases. W162 adds 15 exact behavior-test sources. W163 is excluded.

## Hosted compile follow-up

**Current hosted evidence (2026-09-21):** source6003175f passed Core/reference
35634495862, Preflight35634494324 and Code Quality35634493973. Full CI35634988336
continues native compilation, but Linux job106450108773 found two strict-Clippy
style errors in the W162 producer. The exact is_none_or and let-chain repairs
preserve measurement and idle-error behavior. Preview35635024193 remains in
progress. W163 is unpublished and excluded; no roadmap checkbox closes.

The historical W159 core-review file was accidentally overwritten. Its expected
hash remains recorded as unavailable, never reconstructed as original evidence.
A new independent CURRENT-CORE-REVIEW.md approves the current WAL foundation
with exact source hashes; caller/runtime acceptance remains separately required.
W162 GUI-test follow-up:65e27f0c passed Preflight35636083470 and Code Quality
35636082892. The Hosted600 beta job106450108302 exposed 27 missing test-scope
references. Twelve non-Windows imports preserve the complete callback test;
twelve unused startup clones and one unused citation Read import are removed.
The independent frozen-patch review found no code defect; its documentation
scope warning is corrected in the receipt. Native/GUI execution remains
pending. W163 is excluded from this repair admission.
