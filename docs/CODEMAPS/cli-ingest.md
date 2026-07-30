# CLI Codemap — Ingest + Models

**Last Updated:** 2026-07-29
**Entry Points:** `SRC/neothd/src/cli/ingest.rs`, `SRC/neothd/src/cli/models.rs`

## cli/ingest.rs

`neoth ingest <path>` — multimodal asset ingest pipeline. Detect kind → extract → persist
embedding → emit WAL audit events → print report.

### Command surface

```
neoth ingest <PATH>
  [--db PATH]           override views.db path
  [--wal-segment PATH]  canonical segment directly under the instance wal/
  [--no-persist]        skip embedding persistence (inspection / tests)
  [--no-audit]          skip WAL audit events (batch reprocessing)
  [--no-index]          skip ctx/recall chunk indexing
  [--output table|json] output format (inherited from global --output)
```

### File kind detection (by extension, case-insensitive)

| Extensions | AssetKind |
|-----------|-----------|
| `.pdf` | Pdf |
| `.png .jpg .jpeg .webp .gif` | Image |
| `.wav .mp3 .flac .ogg .m4a` | Audio |
| `.mp4 .mov .mkv .webm` | Video |

### Pipeline

```
detect_kind(path)
  → Asset::Path { kind, mime, path }
  → route_to_first_match(backends, asset)   [pdf, vision, audio, video]
  → Extraction { text, metadata { embedding?, extractor, embed_status } }

if !no_persist && metadata.embedding present:
  → embeddings::upsert(conn, source_kind, source_ref, model, embedding)

if audio/video:
  → dedicated home-bound STT audit writer
  → local STT may continue when finalization fails
  → cloud STT requires authorization + durable intent/result and fails closed
    when its required audit writer/finalization is unavailable

if !no_audit && live daemon:
  → same-user audit RPC forwards 0x2C/0x2D to the daemon-owned writer
  → an unreachable listener is visible in debug logs; ingest still completes

if !no_audit && no live daemon:
  → collision-resistant home-bound one-shot writer under <home>/wal/
  → append 0x2C INGEST_EXTRACTED
  → append 0x2D EMBED_PERSISTED (only if embedding landed)
  → wait for writer completion before reporting success

print IngestReport { path, kind, text_bytes, preview, embed_status, embed_persisted, metadata }
```

### WAL concurrency contract

`neoth ingest` never opens the daemon's active transport. When `neoth serve`
owns the WAL, ingest forwards the allowlisted `0x2C`/`0x2D` payloads through the
same-user audit RPC. If that listener is unavailable the condition is logged
and the extraction report still prints. Without a live daemon, ingest creates a
collision-resistant, canonical segment directly under the selected instance
home's `wal/`, appends through one home-bound writer, and waits for finalization.
The explicit `--wal-segment` override must satisfy that same canonical
home/`wal/` path contract.

### Source ref

Canonical source_ref is `fs::canonicalize(path)` (absolute, resolved symlinks). Falls back
to the display path on canonicalization error.

## cli/models.rs

`neoth models list|pull|prune` — manage `~/.neoth/models/` cache.

### Command surface

```
neoth models list
neoth models pull <clip|whisper> [--repo HF_REPO]
neoth models prune <clip|whisper>
```

### Known model catalogue

| Name | Description | Default repo | Required files |
|------|-------------|-------------|----------------|
| `clip` | CLIP ViT-B/32 image + text embeddings | `openai/clip-vit-base-patch32` | config.json, model.safetensors, tokenizer.json |
| `whisper` | Whisper large-v3-turbo transcription | `openai/whisper-large-v3-turbo` | config.json, tokenizer.json, model.safetensors |

`qwen` is intentionally absent — local Qwen has its own hardware-sizing onboarding flow in
`cli/init.rs::step5b_inference_topology`.

### pull behaviour

Delegates to `ClipEngine::new(repo)` / `WhisperEngine::new(repo)` which call
`ensure_artifacts()`. If all three required files are already present the HF Hub API is not
called. 15-minute per-file download timeout.

### prune behaviour

`std::fs::remove_dir_all` on the engine's `default_cache_dir`. No-op when the directory is
already absent.

## Related Areas

- `providers/clip_engine.rs` / `providers/whisper.rs` — the engines whose cache `models` manages
- `memory/embeddings.rs` — where extracted embeddings land
- `cli/doctor.rs` — `check_model_caches()` reports cached vs missing for both models
- `wal/events.rs` — `0x2C INGEST_EXTRACTED`, `0x2D EMBED_PERSISTED`
