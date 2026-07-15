# Media Codemap — Extraction Pipeline

**Last Updated:** 2026-07-14
**Entry Points:** `SRC/neothd/src/media/mod.rs`

## Architecture

```
Asset { kind: AssetKind, mime: String, payload: Bytes | Path }
  |
  | route_to_first_match(backends, asset)
  |   iterate backends in order:
  |     try backend.extract(asset) if kind matches
  |     first Ok(Extraction) wins; Unsupported skips to next
  |
  +--[PdfExtractor]      kind=Pdf
  +--[DoclingExtractor]  kind=Pdf|Document|Image (opt-in subprocess; falls through)
  +--[DocumentExtractor] kind=Document
  +--[VisionExtractor]   kind=Image
  +--[AudioExtractor]    kind=Audio
  +--[VideoExtractor]    kind=Video
  |
  v
Extraction { text: String, metadata: serde_json::Value }
```

`metadata` is backend-specific. Current built-in extractors include an
`extractor` identifier, but only `VisionExtractor` owns `embed_status`; callers
must not require that field from audio, video, PDF, or document output.

## Key Modules

| Module | Purpose |
|--------|---------|
| `media/vision.rs` | PNG/JPEG/WebP/GIF decode; optional CLIP embedding |
| `media/audio.rs` | Audio decode to 16 kHz mono f32; Whisper transcription |
| `media/video.rs` | ffmpeg audio-track + first-frame extraction; delegates audio to `AudioExtractor` |
| `media/frame_decoder.rs`, `media/video_dispatch.rs`, `media/video_frames.rs` | sampled ffmpeg frame decode, permission/config gate, multimodal synthesis, `0xC9` audit |
| `media/pdf.rs` | PDF text extraction via pure-Rust `pdf-extract` |
| `media/document.rs`, `media/docling.rs` | local office/text formats plus optional Docling subprocess fallback |
| `media/stt_provider.rs`, `media/stt_dispatch.rs` | canonical local-first/cloud-opt-in STT selection, policy, model consent, audit, fallback |
| `media/mod.rs` | `Asset`, `AssetKind`, `Extraction`, `ExtractionError`, `MediaExtractor` trait, `route_to_first_match` |

## VisionExtractor

- Accepts: `AssetKind::Image`
- Decode: `image` crate (PNG / JPEG / WebP / GIF → RGB buffer)
- Max size: 16 MiB (matches Telegram attachment ceiling and WAL MAX_PAYLOAD_BYTES)
- Embedding path:
  - If `~/.neoth/models/openai-clip-vit-base-patch32/{config.json, model.safetensors}` exist:
    construct `ClipEngine`, call `embed_image` → 512-dim Vec<f32> stored in
    `metadata.embedding`; `embed_status = "ok"`
  - Otherwise: `embed_status = "model not cached"`; no embedding in metadata
- Extractor name: `"vision"`

## AudioExtractor

- Accepts: `AssetKind::Audio`
- Decode: pure-Rust `symphonia` for WAV/MP3/FLAC/Ogg/M4A, channel mix-down,
  then the shared band-limited resampler to 16 kHz mono f32. Path inputs are
  capped at 512 MiB.
- Transcription: the single `stt_provider::dispatch_pcm_f32` path selects the
  effective configured backend (Candle Whisper, faster-whisper, or explicitly
  enabled cloud STT), applies model-download/cloud consent, fallback,
  post-processing, and audit.
- Metadata reports actual provider/model, sample counts/rates, duration,
  segments, speaker labels, and `transcription_status`. It does not emit
  `embed_status`.
- Extractor name: `"audio"`

## VideoExtractor

- Accepts: `AssetKind::Video`
- Base extractor: ffmpeg converts the audio track to 16 kHz mono WAV, delegates
  transcription to `AudioExtractor`, and attempts a first-frame JPEG thumbnail.
- Multiframe analysis is separately shipped through `FrameDecoder` +
  `video_dispatch`: timestamp plans are provider-capped, cloud frame upload is
  default-off (`media.video_frame_upload_enabled`), and successful synthesis
  emits metadata-only `0xC9 VIDEO_FRAME_SYNTHESIZED` audit.
- Extractor name: `"video"`

## PdfExtractor

- Accepts: `AssetKind::Pdf`
- Pure-Rust `pdf-extract` text extraction. It does not claim OCR or full visual
  layout support; the opt-in Docling extractor can run earlier in the routing
  chain when configured.
- Extractor metadata name: `"pdf-extract"`

## ExtractionError Variants

| Variant | When |
|---------|------|
| `Unsupported { backend, got }` | Backend does not handle this `AssetKind`; route moves to next |
| `Backend { backend, reason }` | Backend attempted but failed (decode error, model load error, etc.) |
| `TooBig { size, limit }` | Asset exceeds the backend's size ceiling |

## Related Areas

- `providers/clip_engine.rs` — called by VisionExtractor
- `media/stt_provider.rs` — canonical transcription dispatcher used by AudioExtractor
- `cli/ingest.rs` — calls `route_to_first_match` and persists the result
- `cli/serve.rs` — calls the same pipeline for channel-attached media
- `channels/telegram.rs` — downloads attachments then passes to the media pipeline
