# W186 — live audio capture and Silero VAD

W186 is the source-integration slice for
[GOLD-LF-P1-13](../PLAN/ROAD_TO_1_0_GOLD.md#gold-lf-p1-13--sub-200ms-voice-streaming-capture).
It remains unaccepted: the Road item requires supported-release latency and
runtime evidence that this source-only batch has not produced.

The retained Hosted input run `35694695810` on source `87c18246` verified all
85 artifact checksums, the source revision and the three recorded dependency
inputs. The resulting working source pins `cpal = 0.18.2` and
`tract-onnx = 0.23.8`. The resolver transition is narrowly recorded as
`borsh 1.6.1 -> 1.8.1`, required through the `tract-core` dependency chain.

The imported Silero asset is the `silero_vad_16k_op15.onnx` model from
`snakers4/silero-vad` commit `60b7ffa243625ebdc1070275a29f18c87843786a`.
Its provenance and license are retained alongside the model under
`SRC/neothd/assets/silero-vad/`; model SHA-256 is
`7ED98DDBAD84CCAC4CD0AEB3099049280713DF825C610A8ED34543318F1B2C49`.

The source introduces a bounded live-capture/VAD/STT path. Capture owns its
stream and sends bounded PCM work; terminal events survive PCM wait outcomes.
The CLI holds one audio permit, bounds queued utterances, preserves scope
validation before STT dispatch, drains foreground STT on normal stop, and
reports unavailable live capture before config or device access when the
feature is absent. The live-audio feature is optional and selected by the
desktop release only; default and server builds retain the explicit
unavailable contract.

`docs/verification/gold-wave186-live-audio-tests.json` records 19 shared
Hosted test identities for this slice. The Hosted workflow lane is intended to
compile and run those exact identities under `live-audio`, with platform
specific dependency setup and retained logs. It has not yet established a
native feature pass, microphone input, VAD inference, transcription behavior,
latency, GUI behavior, or a release artifact.

No local compiler, Cargo command, formatter, parser, fixture runner, product,
GUI, microphone, audio or test runtime was used because the workstation BSOD
hold remains in force. All executable validation for W186 is pending on
GitHub-hosted runners.
