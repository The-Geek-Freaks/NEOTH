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

W162 source642525f3 passed Code Quality35633810126. Preflight35633811067
requested 33 exact formatting hunks in five files; these are imported.
Core35633811647 reported two E0308 expansions at one interval select: tick()
returns Instant rather than (). The producer and both matching regression
patterns now accept that return value without changing timer ordering. Fresh
hosted compilation and native/GUI behavior remain pending; W163 stays excluded.
