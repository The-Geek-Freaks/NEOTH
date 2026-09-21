# W174 — visual video ingest with observed frame sampling

Road scope: ADOPT31-F1 and ADOPT31-F3. Implementation and focused regression sources passed independent static
review, including the final two-attribute test-only integration delta. Hosted executable acceptance
is required; no Road checkbox closes on source inspection.

`neoth ingest <video> --analyze-video-frames` explicitly requests visual analysis
through the configured Anthropic, OpenAI or Gemini API vision provider. The
ordinary audio/STT ingest path remains selected when this flag is absent. The
visual path supports silent clips and labels its extracted/indexable result
`Visual frame analysis:` rather than presenting it as a transcript.

The actual provider factory checks cloud vision and credentials before media
work. The frame-upload and required-audit policy gates precede snapshot/probe/
decode. A standalone visual WAL writer is drained, and operation and audit
finalization failures remain visible. Existing intent-before-egress and video
synthesis audit records continue to apply. No paid provider was invoked during
this batch's verification.

One supervisor retains a private input snapshot and its worker permit across
ffprobe, scene sampling and frame decoding. Probe output supplies a finite
positive duration, ordered observed frame timestamps and actual keyframe flags.
Codec side data does not replace any required frame field. Scene detection uses
ffmpeg `select='gt(scene,0.20)'` and `showinfo`. Fewer than four keyframes trigger
uniform coverage using observed frame positions; the minimum target is eight
where source frames and provider cap permit it. The new path does not use the
legacy two-second GOP estimate. Existing perceptual dedup runs before synthesis.

Initial review found two substantive issues: caller cancellation could release
the snapshot before detached subprocess completion, and the uniform grid could
seek at the exact end of the clip. The candidate now retains the complete local
operation in a supervisor and selects uniform positions from the observed frame
grid. The initial CSV protocol was also replaced by structured ffprobe output.
The rejected review remains in the W174 work directory.

Acceptance includes pure duration/probe/scene/planner/policy regressions and a
required Linux fixture that creates a real silent video, probes and samples it,
decodes its frames, and dispatches them to a mock vision synthesizer. Missing
ffmpeg or ffprobe is a test failure. The existing Linux CI dependency step now
installs ffmpeg, with the dependency covered by its existing cadence contract.
This fixture exercises local media processing; it is not live provider or
cross-platform product acceptance.

Local compiler, formatter, parser, test, fixture and product execution remain
suspended. All executable validation runs on GitHub-hosted CI. Generated CLI
reference, current native/GUI integration, strict Clippy, formatting and product
acceptance must be checked against the published source before completion.

Independent review 02 SHA-256:
7663DFF920208C2879D4D4DBBAC74595B9608175D05549E8C63BEFF7D35FE4B5.
Final integration-delta review SHA-256:
D3A095664A237CB7B6925DE9AE5826544F8DAA8523788B9DD191219E0EC72759.
Both reports and the earlier HOLD remain in `work/gold-20260906/wave174-next-batch/`.
The final delta scopes the scene-timestamp witness to the Linux test that reads
it; production data and behavior are unchanged by that delta.
