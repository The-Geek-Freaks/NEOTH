# Providers

How Neoth talks to LLMs — and how it runs inference locally.

---

## Cloud LLM providers

| Provider | Config key | Notes |
|----------|-----------|-------|
| Anthropic Claude | `anthropic_api_key` in `credentials.yaml` | Default. `claude-opus-4-5` unless overridden in `freedom.yaml::model`. |
| OpenAI-compat bridge | `openai_compat_endpoint` + `openai_compat_token` | Covers LM Studio, vLLM, Ollama, the `claude_openai_bridge.py` shim, any `/v1`-compliant server. |
| Google Gemini | `gemini_api_key` | Uses the `gemini_api.rs` adapter. Model defaults to `gemini-2.0-flash`. |
| Claude CLI | `claude_cli_adapter` | Wraps `claude -p` in a tmux pane via `claude_cli.rs`. Token-level streaming over stdout. |

Provider selection: `freedom.yaml::provider` field. The wizard sets it during `neoth init`
based on what credentials you supply. Change it at any time and restart `neothd serve`.

If `neoth init` detects a running OpenAI-compat server on localhost (LM Studio :1234, vLLM
:8000, Ollama :11434, legacy bridge :31338), it proposes that endpoint automatically.

---

## Local inference — CLIP + Whisper

These run entirely on the operator's machine. No API key, no network call at inference time.
Artifacts are downloaded once from HuggingFace and cached under `~/.neoth/models/`.

### CLIP ViT-B/32 (vision embeddings)

- **Purpose**: produce a 512-dim L2-normalised image embedding that lives in `idx_embedding`
  and enables `neoth recall --similar-to <image>` cross-modal search.
- **Checkpoint**: `openai/clip-vit-base-patch32` (~605 MiB on disk).
- **Text tower**: also ships a text encoder (`embed_text`). Dot product between an image
  embedding and a text embedding is the canonical CLIP image↔text similarity score. Used by
  `neoth recall --similar-to-text "sunset over water"`.
- **Preprocessing**: shortest-side resize to 224 px → centre-crop 224×224 → per-channel
  normalise with OpenAI's hardcoded mean/std → NCHW f32 tensor.
- **Tokeniser**: CLIP BPE, 77-position context window. SOT token 49406, EOT token 49407.
  Prompts are truncated to 75 content tokens then zero-padded.
- **Acceleration**: CPU-only in v0.1.x. CUDA/Metal feature flags are reserved for when D14b
  completes the candle accelerator stack.
- **Only supported variant**: ViT-B/32 (`vision_config.hidden_size=768, patch_size=32`). The
  engine validates the cached `config.json` at load time and errors loudly on a mismatch.

### Whisper large-v3-turbo (speech-to-text)

- **Purpose**: transcribe audio attachments (Telegram voice/audio messages, ingested audio
  files, video audio tracks) to text before passing to the LLM.
- **Checkpoint**: `openai/whisper-large-v3-turbo` (~1.6 GiB on disk). Multilingual.
- **Chunking**: audio is split into back-to-back 30-second windows (`N_SAMPLES` at 16 kHz
  mono f32). Short trailing chunks are zero-padded. Outputs concatenated with a space.
- **Language auto-detect**: enabled by default (`auto_detect_language: true`). Runs one extra
  decoder step per chunk (one `<|startoftranscript|>` probe, argmax over language-token
  logits). Falls back to `WhisperOptions::language` (default `"en"`) when detection yields
  no result.
- **Temperature fallback**: default schedule `[0.0, 0.2, 0.4, 0.6, 0.8, 1.0]`. After each
  attempt, gzip-compress the output and check `text_len / compressed_len`. If the ratio
  exceeds `compression_ratio_threshold` (default 2.4 — Whisper's reference hallucination
  heuristic), retry with the next temperature. Schedule exhausted → return last attempt with
  a WARN log.
- **Acceleration**: CPU-only in v0.1.x (same candle constraint as CLIP).
- **Mel filterbank**: computed from scratch at engine init using the Slaney mel-scale
  (`htk=False, norm='slaney'`), sized from `config.json::num_mel_bins` (80 for most
  variants, 128 for v3/turbo). Matches whisper's `mel_filters.npz` to f32 precision.

### `neoth models` — cache management

```
neoth models list              # show clip + whisper: cached / missing, default repo, cache dir
neoth models pull clip         # download CLIP artifacts (~605 MiB) from HuggingFace
neoth models pull whisper      # download Whisper artifacts (~1.6 GiB)
neoth models pull clip --repo openai/clip-vit-base-patch32  # explicit repo override
neoth models prune clip        # remove CLIP cache directory
neoth models prune whisper     # remove Whisper cache directory
```

Pull uses `hf_hub::api::tokio::Api` with a 15-minute per-file timeout. It is safe to
re-run: if all required files (`config.json`, `model.safetensors`, `tokenizer.json`) are
already present the download is skipped.

`neoth doctor` includes a `model caches` check that reports which models are cached and
what total disk space the full set would require.

### Cache layout

```
~/.neoth/models/
  openai-clip-vit-base-patch32/
    config.json
    model.safetensors    ~605 MiB
    tokenizer.json
  openai-whisper-large-v3-turbo/
    config.json
    model.safetensors    ~1.6 GiB
    tokenizer.json
```

Repo name is flattened by replacing `/` with `-`. Both engines look up the same path via
`default_cache_dir(repo)` in their respective modules; `neoth models` calls the same
function pointers so there is no path divergence.

The safetensors files are memory-mapped at first use (lazy load on the first
`transcribe` / `embed_image` call, not at engine construction). Multi-process read (daemon
+ `neoth ingest` running concurrently) is permitted; `neoth models pull` is a no-op
against a complete cache. A stable HMAC check for the weight files is tracked as a Phase 2
hardening item (`neoth doctor` warns when a file disappears between runs).

---

## Provider metering

All cloud-provider calls go through `providers::meter.rs`. Quota is tracked in
`idx_motor` (the Cerebellum region). `neoth doctor` warns when the `~/.neoth/` home
directory is above 5 GiB; the full quota architecture is in `PLAN/`.
