# Providers Codemap — Local Inference Engines

**Last Updated:** 2026-05-15
**Entry Points:** `SRC/neothd/src/providers/clip_engine.rs`, `SRC/neothd/src/providers/whisper.rs`

## Architecture

```
ClipEngine                          WhisperEngine
  |                                   |
  | new(repo?) → ensure_artifacts()   | new(repo?) → ensure_artifacts()
  |              hf_hub download      |              hf_hub download
  |              (first run only)     |              (first run only)
  |                                   |
  | embed_image(rgb, w, h)            | transcribe(samples, WhisperOptions)
  |   spawn_blocking                  |   spawn_blocking
  |   → preprocess_image (224×224)    |   → chunked(30s) loop
  |   → ClipModel.get_image_features  |     → per-chunk language detect (opt)
  |   → l2_normalise                  |     → temperature fallback loop
  |   → Vec<f32> len=512              |     → compression_ratio check
  |                                   |   → concatenated transcript: String
  | embed_text(prompt)                |
  |   spawn_blocking                  |
  |   → tokenize_prompt (77 ids)      |
  |   → ClipModel.get_text_features   |
  |   → l2_normalise                  |
  |   → Vec<f32> len=512              |
```

## Key Modules

| Module | Purpose | Key Exports |
|--------|---------|-------------|
| `clip_engine.rs` | CLIP ViT-B/32 image + text embeddings | `ClipEngine`, `DEFAULT_CLIP_REPO`, `EMBED_DIM=512`, `default_cache_dir` |
| `whisper.rs` | Whisper large-v3-turbo speech-to-text | `WhisperEngine`, `WhisperOptions`, `DEFAULT_WHISPER_REPO`, `default_cache_dir` |

## Constants

### clip_engine

| Constant | Value | Meaning |
|----------|-------|---------|
| `DEFAULT_CLIP_REPO` | `"openai/clip-vit-base-patch32"` | HF repo pulled by `models pull clip` |
| `IMAGE_SIZE` | `224` | Post-crop side length in pixels |
| `EMBED_DIM` | `512` | Output dimension after `get_image_features` |
| `TEXT_CONTEXT_LEN` | `77` | Full token width including SOT + EOT + padding |
| `SOT_TOKEN_ID` | `49406` | `<\|startoftext\|>` — hardcoded per OpenAI checkpoint |
| `EOT_TOKEN_ID` | `49407` | `<\|endoftext\|>` |
| `CLIP_MEAN` | `[0.48145466, 0.4578275, 0.40821073]` | Per-channel normalisation |
| `CLIP_STD` | `[0.26862954, 0.26130258, 0.27577711]` | Per-channel normalisation |

### whisper

| Constant | Value | Meaning |
|----------|-------|---------|
| `DEFAULT_WHISPER_REPO` | `"openai/whisper-large-v3-turbo"` | HF repo pulled by `models pull whisper` |
| `WhisperOptions::temperatures` | `[0.0, 0.2, 0.4, 0.6, 0.8, 1.0]` | Default fallback schedule |
| `WhisperOptions::compression_ratio_threshold` | `2.4` | Hallucination heuristic (gzip ratio) |
| `WhisperOptions::max_new_tokens` | `480` | Per-chunk decoder limit |

## Data Flow

```
Image bytes (RGB u8 buffer)
  → preprocess_image: shortest-side resize 224, centre-crop 224×224, normalise
  → NCHW (1,3,224,224) f32 tensor
  → ClipModel.get_image_features → (1,512) f32
  → squeeze + l2_normalise
  → Vec<f32> len=512

Text prompt
  → tokenize_prompt: BPE encode, truncate to 75 tokens, wrap SOT/EOT, pad to 77
  → Tensor (1,77) u32
  → ClipModel.get_text_features → (1,512) f32
  → squeeze + l2_normalise
  → Vec<f32> len=512

Audio samples (16 kHz mono f32)
  → chunk into 30s windows (zero-pad last)
  → pcm_to_mel (n_mels × N_FRAMES spectrogram)
  → encoder.forward → audio_features
  → [opt] detect_language_for_chunk (one decoder probe step)
  → temperature fallback loop:
       run_decoder_pass (greedy or softmax-sampled)
       compression_ratio check
  → tokenizer.decode → text chunk
  → join chunks with spaces → final transcript
```

## External Dependencies

- `candle-core` / `candle-nn` / `candle-transformers` 0.8 — CPU tensor ops + CLIP/Whisper model definitions
- `hf_hub` — HuggingFace Hub download API
- `tokenizers` — BPE tokenizer for both CLIP (text tower) and Whisper
- `image` — RGB image decode + resize + crop for CLIP preprocessing
- `flate2` — gzip for Whisper compression-ratio heuristic
- `xxhash-rust` — deterministic decoder seed from prompt + temperature
- `rand` — stochastic sampling at temperature > 0

## Safety Notes

Both engines use `VarBuilder::from_mmaped_safetensors` which requires the mapped file not be
concurrently truncated or replaced. The SAFETY comments in both files document: the file lives
in `~/.neoth/models/` (mode 0600 / DACL-locked); `neoth models pull` is a no-op against an
existing cache; multi-process read (daemon + `neoth ingest`) is permitted; a stable HMAC check
is a Phase 2 hardening item.

## Related Areas

- `memory/embeddings.rs` — where CLIP vectors are persisted
- `cli/models.rs` — operator-facing pull/prune/list commands
- `cli/ingest.rs` — calls both engines through the media extractor chain
- `media/vision.rs` — calls `ClipEngine` when the model is cached
- `media/audio.rs` — calls `WhisperEngine`
