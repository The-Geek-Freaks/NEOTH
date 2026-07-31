# Forensic Adoption Report — huggingface/speech-to-speech

**Agent:** A  
**Date:** 2026-07-31  
**Repo:** huggingface/speech-to-speech (Apache-2.0, 9285★)  
**Clone:** `/tmp/adopt2026/speech-to-speech`  
**Total code:** 15,582 lines Python across ~80 source files  

---

## 1. What It Actually Does (from source, not README)

The repo is a self-contained Python library (`src/speech_to_speech/`) implementing a
real-time, full-duplex voice-to-voice pipeline. It is NOT a model; it is an
**orchestration layer** that chains existing models (Silero VAD, Whisper/Parakeet STT,
any HF-compatible LLM, Kokoro/ChatTTS/Facebook-MMS/Qwen3 TTS) into a turn-taking
conversation loop.

**Architecture (source-verified):**

```
MicCapture / SocketReceiver
        │ recv_audio_chunks_queue
        ▼
    VADHandler              ← vad_handler.py (855L), vad_iterator.py (170L)
        │ spoken_prompt_queue
        ▼
    STT Handler             ← base_stt_handler.py, whisper / parakeet / faster-whisper
        │ stt_output_queue
        ▼
    TranscriptionNotifier   ← interstitial: sends partial transcripts to WebSocket
        │ text_prompt_queue
        ▼
    LLM Handler             ← language_model.py (1011L), chat_completions_*.py
        │ lm_response_queue
        ▼
    LMOutputProcessor       ← sentence-batcher → TTS text chunks
        │ lm_processed_queue
        ▼
    TTS Handler             ← kokoro_handler.py (418L), facebookmms_handler.py, qwen3 (903L)
        │ send_audio_chunks_queue
        ▼
    SocketSender / WebSocketStreamer
```

Each stage is a `BaseHandler[InT, OutT]` (`baseHandler.py`, 161L). The base class
provides: `setup()` (model load), `warmup()` (first-pass dummy inference), `process(input)`
(generator yielding output chunks), `should_process_input()` (cancel-scope check),
`before_emit_output()` (VAD dedup), `output_for_queue()` (attaches cancel_generation tag).
ThreadManager (`utils/thread_manager.py`) wraps each handler in a daemon thread.

The queue topology and all handlers are wired in `s2s_pipeline.py:build_pipeline()`
(`initialize_queues_and_events()` → creates `CancelScope`, `should_listen: threading.Event`,
6 typed `Queue` instances → each handler instantiated with its queue pair).

Also present: an OpenAI Realtime API compatibility layer
(`api/openai_realtime/`, 881+520L) that maps the pipeline to the
`/v1/realtime` WebRTC/WebSocket protocol.

---

## 2. Where It Beats NEOTH

### 2a. Barge-In / Cancellation — NEOTH has nothing here

**Verified gap (own grep):**
```
rg -i 'barge|cancel_generation|should_listen|cancel_scope' \
   SRC/neothd/src/media SRC/neothd/src/channels --include='*.rs'
```
Zero hits. The only `full_duplex` hits in channels are `keet_bridge.rs:722`
(`BridgeHealth` test struct). The only `interrupt` hits in media are `ErrorKind::Interrupted`
(IO error handling). NEOTH has no realtime conversation loop, no barge-in, no in-flight
TTS cancellation.

**The mechanism** (source: `pipeline/cancel_scope.py` + `VAD/vad_handler.py` +
`TTS/kokoro_handler.py`):

`CancelScope` is a generation counter + discard flag:
```python
# pipeline/cancel_scope.py — full file (~60L)
class CancelScope:
    def __init__(self) -> None:
        self._gen: int = 0
        self._discarding: bool = False
        self._discarded_generation: int | None = None

    def cancel(self) -> None:
        self._discarded_generation = self._gen
        self._gen = (self._gen + 1) & 0xFFFFFFFF   # wrap at 2^32
        self._discarding = True

    def is_stale(self, gen: int) -> bool:
        return gen != self._gen
```

Each `LLMResponseChunk` and `TTSInput` message carries a `cancel_generation: int | None`
field (`pipeline/messages.py`). When VAD detects new speech while TTS is playing:

1. VAD calls `cancel_scope.cancel()` — increments `_gen`
2. New speech segment enters pipeline normally
3. LLM handler: after each yielded token batch, checks `is_stale(captured_gen)`; breaks
4. TTS handler (kokoro_handler.py:344,396): inside the audio synthesis loop, after each
   chunk synthesis: `if self.cancel_scope.is_stale(gen): logger.info("TTS generation
   cancelled"); break`
5. `should_listen: threading.Event` is cleared by VAD when speech ends (sends it to STT),
   set by TTS when done playing → controls listen/speak toggle

`BaseHandler.should_process_input()` also checks `is_stale()` before even starting
processing, so stale items are drained immediately from queues.

**VAD barge-in gate** (`vad_handler.py:481`):
```python
if self.speculative_turns is not None and not self.speculative_turns.is_latest(
    self._current_turn_id, self._current_turn_revision
):
    return  # drop superseded VAD audio
```

### 2b. Silero Neural VAD — NEOTH has energy-only

NEOTH's `media/vad/smoothed.rs` uses `EnergyBackend` (RMS amplitude threshold, no model
weights). Speech-to-speech uses Silero VAD (PyTorch ONNX, 1.8MB) via
`VAD/vad_iterator.py`. The iterator wraps the Silero model's per-32ms-frame speech
probability, applies a sliding silence window, and emits speech/silence events.

NEOTH's `VadBackend` trait (`smoothed.rs`) is already the right seam to plug in a
Silero backend — trait has `speech_prob(&mut self, frame: &[f32], sample_rate_hz: u32) -> f32`.

### 2c. Speculative Turn Tracker — NEOTH has nothing

`pipeline/speculative_turns.py` (418L): tracks whether a "soft-ended" turn should be
reopened if the user resumes speaking within `speculative_reopen_ms`. Prevents false
barge-ins when a user pauses mid-sentence. States: `uncommitted → committed → done`.
Turn revisions allow the VAD to send amended audio without restarting the STT/LLM chain.

### 2d. Tuned VAD Constants (real production IP)

From `VADHandlerArguments` (vad_handler.py, derived from production use):
```
thresh                    = 0.6    # Silero probability threshold
sample_rate               = 16000  # Hz
min_silence_ms            = 64     # very tight — 64ms gap ends an utterance
min_speech_ms             = 384    # 384ms min to count as real speech
min_speech_continuation_ms= 192    # hysteresis for reopenable turns (184ms lower)
speech_pad_ms             = 500    # 500ms prepended+appended audio around segment
speculative_reopen_ms     = 1000   # turn stays soft for 1s after speech end
unanswered_reopen_ms      = 7000   # extended to 7s if no LLM response yet
_SHORT_SEGMENT_MIN_FRAGMENT_MS = 100  # fragments <100ms never count toward barge-in
```

NEOTH defaults: hangover=750ms (close), smooth_window=100ms (close), but no Silero,
no speech_pad, no speculative reopen, no short-segment guard.

### 2e. Sentence-Batched LLM→TTS Streaming

`LLM/language_model.py:300-411`: uses NLTK `sent_tokenize` to split LLM output; batches
`stream_batch_sentences=3` sentences per TTS chunk. Prevents word-by-word synthesis
latency while keeping first-audio latency low (~3 sentences ≈ 1-2 seconds of speech).

NEOTH's `tts_dispatch.rs` + `tts_provider.rs` have no streaming text chunking.

---

## 3. Steal-List (ranked)

### #1 — CancelScope generation counter
**What:** Port `pipeline/cancel_scope.py` to Rust `AtomicU32` generation counter.  
**NEOTH landing:** New `SRC/neothd/src/media/conversation_scope.rs` (~60L)  
**How:** `struct ConversationScope { gen: AtomicU32, discarding: AtomicBool }`. Methods:
`cancel()` → fetch_add, `is_stale(gen) → bool`, `generation() -> u32`. Inject into
TTS synthesis loop (after each synthesized audio chunk: `if scope.is_stale(captured_gen) { break }`).  
**Consumer:** `media/conversation_loop.rs` (steal #2), and immediately `media/tts_dispatch.rs`  
**Effort:** **S** — pure logic, ~60 lines Rust, zero deps  

### #2 — Conversation loop orchestrator
**What:** The queue topology + thread/task wiring from `s2s_pipeline.py:build_pipeline()`.  
**NEOTH landing:** New `SRC/neothd/src/media/conversation_loop.rs` (~400L)  
**How:** `tokio::sync::mpsc::channel` (unbounded) replaces Python `Queue`. 6 tasks:
mic_capture → vad_task → stt_task → llm_task → tts_task → audio_out_task. Each task
receives `Arc<ConversationScope>`. A `ConversationLoopHandle` exposes `start()`, `stop()`,
`mute()`, emits WAL events at: turn-start, turn-cancel, response-start, response-done.  
**Consumer:** Channel `src/channels/voice_channel.rs` or a new dictation-realtime surface  
**Effort:** **XL** — deep integration, consent gate, WAL, GUI toggle, Windows audio capture  

### #3 — Silero VAD backend
**What:** Replace `EnergyBackend` with Silero ONNX model via `ort` crate.  
**NEOTH landing:** New `SRC/neothd/src/media/vad/silero_backend.rs`  
**How:** `struct SileroBackend { session: ort::Session, state: [f32; 2*1*64] }`. Implements
`VadBackend::speech_prob()`. Model downloaded+version-pinned by `media/model_manager.rs`
(same pattern as Whisper weights). Input: 512-sample window (32ms at 16kHz) as float32
tensor; output: speech probability scalar. `SmoothedVad::new(..., Box::new(SileroBackend))`.  
**Consumer:** Conversation loop #2; upgrades existing `dictation.rs` quality  
**Effort:** **M** — ORT crate already likely present (Whisper), model supervision via
existing `model_manager.rs`; 150-200L new Rust  

### #4 — VAD tuned constants
**What:** The production-tuned constants from `VADHandlerArguments`.  
**NEOTH landing:** `SRC/neothd/src/media/vad/mod.rs` + new `SileroVadConfig` in
`media/conversation_loop.rs`  
**How:** Add `pub struct SileroVadConfig { thresh: f32, min_silence_ms: u32,
min_speech_ms: u32, speech_pad_ms: u32, speculative_reopen_ms: u32 }` with defaults
`{ thresh: 0.6, min_silence_ms: 64, min_speech_ms: 384, speech_pad_ms: 500,
speculative_reopen_ms: 1000 }`. These are `freedom.yaml` tunables.  
**Consumer:** Conversation loop #2; `dictation.rs`  
**Effort:** **S** — struct + constants; ~30L  

### #5 — Sentence-batched LLM→TTS chunking
**What:** NLTK `sent_tokenize` → sentence-batching before TTS.  
**NEOTH landing:** New `SRC/neothd/src/media/lm_output_processor.rs` (~150L)  
**How:** Simple sentence-boundary splitter (`. `, `? `, `! ` with Unicode awareness).
Accumulate N sentences (`stream_batch_sentences: usize = 3`), flush as single TTS input.
Each chunk tagged with `cancel_generation`. Feed from LLM streaming output, forward to
`tts_dispatch::synthesize_streaming`.  
**Consumer:** `media/conversation_loop.rs` (between LLM task and TTS task)  
**Effort:** **M** — ~150L, no new deps, regex-based tokenizer is sufficient  

### #6 — Short-segment false-barge-in guard
**What:** `_SHORT_SEGMENT_MIN_FRAGMENT_MS = 100` — fragments with <100ms active speech
never accumulate toward barge-in threshold.  
**NEOTH landing:** `SRC/neothd/src/media/vad/smoothed.rs`  
**How:** In `process()`, track `active_speech_ms`; if speech ends with
`active_speech_ms < 100` and no prior speech was accumulated, drop the segment instead
of emitting `VadDecision::Speaking`. Add `min_fragment_ms: u32 = 100` to `SmoothedVad`.  
**Consumer:** `dictation.rs` (immediate improvement), `conversation_loop.rs`  
**Effort:** **S** — <30L change to existing file  

### #7 — Speculative turn tracker
**What:** `pipeline/speculative_turns.py` (418L) — soft-end/reopen/committed turn states.  
**NEOTH landing:** New `SRC/neothd/src/media/turn_tracker.rs` (~200L)  
**How:** `struct TurnTracker { state: TurnState, last_end_ms: Instant, turn_id: u64 }`.
States: `Uncommitted(revision) | Committed | Done`. `maybe_reopen(now) -> bool` checks
`elapsed < speculative_reopen_ms`. `begin_reopen_candidate()` → `confirm_reopen()` protocol.
Eliminates false barge-ins when user pauses mid-sentence.  
**Consumer:** `media/conversation_loop.rs` (VAD task)  
**Effort:** **M** — ~200L, no deps beyond std  

---

## 4. Architecture-Fit Check

| Steal-list item | Rules strained | Notes |
|---|---|---|
| CancelScope (#1) | None | Pure value type, no egress, no model |
| Conversation loop (#2) | **Rule 1** (self-contained), **Rule 3** (GUI parity), **Rule 5** (consent+WAL), **Rule 8** (Windows audio) | Mic always-on needs consent gate in `src/permissions/`; WAL ExtendedSubtype events for MicOpen, TurnStart, TurnCancel, TurnDone; GUI: mic mute toggle + VAD threshold slider + barge-in enable toggle; Windows audio capture via `cpal` crate (portaudio/sounddevice are NOT acceptable — Rule 1) |
| Silero VAD (#3) | **Rule 1** (self-contained), **Rule 4** (model-version-agnostic) | Silero ONNX model (~1.8MB) must be downloaded by `model_manager.rs` (same wizard flow as Whisper); model version pinned in catalog (`src/models/catalog.rs`); `ort` crate needed |
| VAD constants (#4) | Rule 2 (default-ON + runtime toggle) | All constants must be `freedom.yaml` tunables, not hardcoded |
| Sentence batcher (#5) | None | Internal pipeline transform, no egress |
| Short-segment guard (#6) | None | Improvement to existing `SmoothedVad` |
| Speculative turns (#7) | None | Internal state machine, no egress |

**Windows audio (Rule 8):** Speech-to-speech uses `sounddevice` (Python portaudio wrapper).
NEOTH must use `cpal` (pure Rust, supports WASAPI on Windows). The conversation loop
mic-capture task wraps `cpal::platform::Stream` — this is the correct Rust-native shape.
`cpal` is likely not yet a NEOTH dependency; add to `Cargo.toml`.

**Consent (Rule 5):** Always-on microphone is the highest-impact consent surface in NEOTH.
Pipeline: user enables `voice_conversation` feature in wizard → `permissions::Tier::Elevated`
gate → explicit `"NEOTH wants to listen continuously for voice input"` prompt → WAL
`ExtendedSubtype::MicConsentGranted`. Each turn-start/cancel emits WAL event for audit.
WAL opcodes must use Extended-Subtype band (top-level opcodes exhausted per Rule 5).

---

## 5. Verdict

**ADOPT-NATIVE** (port logic into Rust):
- Steal items #1, #3, #4, #6 — pure algorithm, zero Python, clean Rust translation
- Steal items #2, #5, #7 — architectural shape, translate to Rust tokio tasks + mpsc channels

**GROUND-TRUTH** (keep as reference data only, do not port code):
- The Python pipeline as a whole (`s2s_pipeline.py` with its Python threading and
  `transformers` model loading) — use as design spec for Rust conversation_loop.rs,
  not as a running sidecar
- The OpenAI Realtime API layer (`api/openai_realtime/`) — reference for future
  `/v1/realtime` compatibility endpoint on `src/oai_serve/`

**SKIP** (do not adopt as-is):
- Python sidecar execution — Rule 1 requires self-contained Rust; no `pip install`
- `sounddevice` / portaudio — not Windows-first; replaced by `cpal`
- NLTK dependency for sentence splitting — simple regex tokenizer is sufficient for
  NEOTH's use case; no need to bundle NLTK data

**License:** Apache-2.0 (SPDX: `Apache-2.0`).  
Attribution obligation: include `LICENSE` and `NOTICE` files in distribution.  
No copyleft, no viral provisions. Free to adopt, translate, or transform.

---

## Appendix — Key Source Locations

| Component | Upstream file:lines | NEOTH equivalent |
|---|---|---|
| Pipeline orchestration | `s2s_pipeline.py:362-465` | MISSING → `media/conversation_loop.rs` |
| CancelScope | `pipeline/cancel_scope.py:1-64` | MISSING → `media/conversation_scope.rs` |
| VAD state machine | `VAD/vad_handler.py:1-855` | `media/vad/smoothed.rs` (partial) |
| VAD iterator (Silero) | `VAD/vad_iterator.py:1-170` | `media/vad/smoothed.rs` (energy only) |
| VAD constants | `VAD/vad_handler.py:VADHandlerArguments` | No equivalent |
| BaseHandler lifecycle | `baseHandler.py:1-161` | `media/stt_dispatch.rs`, `media/tts_dispatch.rs` (separate, not unified) |
| Sentence batcher | `LLM/language_model.py:300-411` | MISSING → `media/lm_output_processor.rs` |
| Speculative turns | `pipeline/speculative_turns.py:1-418` | MISSING → `media/turn_tracker.rs` |
| Short-seg guard | `VAD/vad_handler.py:39,_SHORT_SEGMENT_MIN_FRAGMENT_MS=100` | MISSING → extend `media/vad/smoothed.rs` |
| should_listen toggle | `s2s_pipeline.py:365`, `vad_handler.py:801,850` | MISSING (boolean in conversation_loop.rs) |
