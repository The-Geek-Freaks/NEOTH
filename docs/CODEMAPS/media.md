# Media Codemap — Extraction Pipeline

**Last Updated:** 2026-05-15
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
  +--[VisionExtractor]   kind=Image
  +--[AudioExtractor]    kind=Audio
  +--[VideoExtractor]    kind=Video
  |
  v
Extraction { text: String, metadata: serde_json::Value }
```

`metadata` fields vary by extractor but always include `extractor` (backend name string) and
`embed_status` (one of: `"ok"`, `"model not cached"`, `"n/a"`).

## Key Modules

| Module | Purpose |
|--------|---------|
| `media/vision.rs` | PNG/JPEG/WebP/GIF decode; optional CLIP embedding |
| `media/audio.rs` | Audio decode to 16 kHz mono f32; Whisper transcription |
| `media/video.rs` | Audio track extract → AudioExtractor; future: frame sampling |
| `media/pdf.rs` | PDF text extraction via pdfium/lopdf |
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
- Decode: `symphonia` or equivalent crate to 16 kHz mono f32 samples
  (TODO: verify exact decode crate used — audio extractor source not read this session)
- Transcription: `WhisperEngine.transcribe(samples, WhisperOptions::default())`
  - Auto-detect language: on
  - Temperature fallback: `[0.0, 0.2, 0.4, 0.6, 0.8, 1.0]`
  - Compression ratio threshold: 2.4
- Model must be cached at `~/.neoth/models/openai-whisper-large-v3-turbo/`; returns empty
  text + `embed_status = "model not cached"` otherwise
- Extractor name: `"audio"`

## VideoExtractor

- Accepts: `AssetKind::Video`
- Strategy: extract audio track → delegate to `AudioExtractor`; frame sampling deferred
- Extractor name: `"video"`

## PdfExtractor

- Accepts: `AssetKind::Pdf`
- Text extraction; page count in metadata
- Extractor name: `"pdf"`

## ExtractionError Variants

| Variant | When |
|---------|------|
| `Unsupported { backend, got }` | Backend does not handle this `AssetKind`; route moves to next |
| `Backend { backend, reason }` | Backend attempted but failed (decode error, model load error, etc.) |
| `TooBig { size, limit }` | Asset exceeds the backend's size ceiling |

## Related Areas

- `providers/clip_engine.rs` — called by VisionExtractor
- `providers/whisper.rs` — called by AudioExtractor
- `cli/ingest.rs` — calls `route_to_first_match` and persists the result
- `cli/serve.rs` — calls the same pipeline for channel-attached media
- `channels/telegram.rs` — downloads attachments then passes to the media pipeline
