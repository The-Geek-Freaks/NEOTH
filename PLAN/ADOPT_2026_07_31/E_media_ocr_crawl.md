# E — Media / OCR / Crawl Adoption Report
**Agent E · 2026-07-31 · NEOTH adoption batch**

Repos: `claude-video` (bradautomates, MIT), `Unlimited-OCR` (baidu), `MediaCrawler`
(NanmiCoder).

Verified against `SRC/neothd/src` at HEAD on 2026-07-31.

---

## Repo 1 — claude-video

### 1. What it actually does

Python-only Claude Code skill/plugin (no installable library). Entry-point is
`skills/watch/skills/watch.yaml` — a YAML skill descriptor that invokes the
`scripts/` Python layer via `Bash`. There are exactly **4 Python files** plus a
SKILL.md:

| File | Purpose |
|------|---------|
| `scripts/config.py` | Detail presets, API-key discovery, `frame_cap()` |
| `scripts/download.py` | `yt-dlp` wrapper — captions-first, audio/video on demand |
| `scripts/frames.py` | ffmpeg frame extraction, scene detection, perceptual dedup |
| `scripts/transcribe.py` | Whisper API fallback (captions unavailable) |

**Core mechanism — frames.py:**
- Three detail tiers: `efficient` (keyframes only, `-skip_frame nokey`), `balanced` /
  `token-burner` (scene-change frames, falling back to uniform sampler).
- Scene-change detection: `ffmpeg -vf "select='gt(scene,0.20)',showinfo"` — threshold
  constant `SCENE_THRESHOLD = 0.20`. Falls back to uniform sampler when fewer than
  `SCENE_MIN_FRAMES = 8` scene-change frames are detected (static / talking-head video).
- Keyframe mode falls back to uniform when fewer than `KEYFRAME_MIN = 4` keyframes are
  decoded (very short or oddly-encoded clips).
- Frame budget: `efficient` caps at 50; `balanced` caps at 100; `token-burner` uncapped.
  Duration-aware `auto_fps()` targets frames-per-second derived from budget ÷ duration,
  clamped at `MAX_FPS = 2.0`.
- JPEG output, `512px` wide by default, hard-clamped at `MAX_READ_DIMENSION = 1998px`
  tall for Claude Read compatibility.
- **Perceptual dedup:** Every extracted frame is scaled to a `DEDUP_THUMB = 16` × 16
  greyscale thumbnail; mean absolute difference against the previously-kept frame is
  computed pure-stdlib (no image library). Frames are dropped when `MAD ≤ DEDUP_THRESHOLD
  = 2.0`. Conservative by design: this only drops visually identical frames (held slides,
  freeze-frames), not slow-moving content.

**Transcript path:** `yt-dlp --write-auto-subs --write-subs --sub-langs en` first;
Whisper OpenAI API as fallback (requires API key in `~/.config/watch/.env`).

### 2. Where it beats NEOTH

NEOTH's video path (`media/video.rs` 1421 lines, `media/video_frames.rs` 464 lines,
`media/frame_decoder.rs` 203 lines, `media/video_dispatch.rs`) does the following:

- `video.rs`: spawns ffmpeg to extract **audio only** (16 kHz mono WAV) for STT. Does
  not touch the video track at all.
- `video_frames.rs`: defines sampling strategy enum (`EveryNthFrame`, `EveryNMilliseconds`,
  `Keyframes`, `Adaptive { target_count }`) and `Frame` data type. No ffmpeg invocations
  here — purely data/strategy types.
- `frame_decoder.rs`: ffmpeg-backed decoder, decodes frames into raw pixel data.

Ripgrep verification (command run; zero output = confirms absence):

```
rg -n 'scene_change\|scene_detect\|SCENE_THRESHOLD\|scene.detect' SRC/neothd/src/
# → (no output)

rg -n 'ocr\|tesseract\|OCR' SRC/neothd/src/
# → (no output)

rg -n 'scene.detect\|scene_change\|video.edit\|video_edit\|browser_auto\|proxy.pool\|ProxyPool' SRC/neothd/src/
# → (no output)
```

**Gap confirmed:** NEOTH has the frame type and decoder infrastructure but is **missing**:

| Gap | claude-video file:line | NEOTH gap |
|-----|----------------------|-----------|
| Scene-change detection via ffmpeg `select='gt(scene,T)'` filter | `frames.py:SCENE_THRESHOLD=0.20` | No `SceneChange` strategy variant exists |
| SCENE_MIN_FRAMES / KEYFRAME_MIN fallback cascade | `frames.py:SCENE_MIN_FRAMES=8, KEYFRAME_MIN=4` | No fallback logic |
| Perceptual dedup (16×16 MAD) | `frames.py:DEDUP_THUMB=16, DEDUP_THRESHOLD=2.0` | Not present |
| yt-dlp download + caption-first path | `download.py:download()` | No yt-dlp installer or wrapper |
| Transcript-only fast path (no video download) | `download.py`, `frames.py:detail==transcript` | No equivalent |

NEOTH's `video_dispatch.rs` vision path currently requires frames already extracted;
there is no scene-aware extraction feeding into the multimodal council call. This is a
real gap for any `/watch` equivalent slash command.

### 3. Steal-list

| # | What to steal | Source file | Target NEOTH file | How | Real consumer | Effort |
|---|--------------|-------------|-------------------|-----|---------------|--------|
| 1 | Scene-change `SamplingStrategy::SceneChange { threshold, min_frames }` variant + ffmpeg invocation string | `frames.py:SCENE_THRESHOLD=0.20, SCENE_MIN_FRAMES=8` | `src/media/video_frames.rs` (extend enum + impl) | New enum variant; impl generates `-vf "select='gt(scene,{threshold})',showinfo"` ffmpeg cmd; parse `pts_time:` from stderr | `video_dispatch.rs::extract_frames_for_vision()` | M |
| 2 | `KEYFRAME_MIN` fallback to uniform (keyframe-sparse clips) | `frames.py:KEYFRAME_MIN=4` | `src/media/video_frames.rs` | Add fallback branch in `Keyframes` strategy impl | `video_dispatch.rs` | S |
| 3 | Perceptual dedup: 16×16 greyscale MAD per-frame | `frames.py:DEDUP_THUMB, DEDUP_THRESHOLD, _dedupe_by_deltas()` | `src/media/video_dispatch.rs` | Post-extraction pass; compute mean per-pixel delta against last-kept frame; pure-Rust stdlib, no image crate needed | `video_dispatch.rs::dedup_frames()` (new fn) | S |
| 4 | yt-dlp installer + caption-first download wrapper | `download.py:download()`, `download.py:_fetch_captions()` | `src/installers/yt_dlp.rs` (new) + `src/media/video.rs` | Installer: `yt-dlp --update-to stable` via wizard. New `VideoSource::Url(String)` arm in `video.rs` dispatches to yt-dlp subprocess, returns temp file path. Caption-first: `yt-dlp --write-subs --skip-download` before full download | `media/video_dispatch.rs` for URL inputs | M |

**First-slice recommendation:** Steal #1 + #2 + #3 together as the scene-aware extraction
upgrade to the existing `Adaptive` path. This has zero new installer requirements (ffmpeg
is already required) and gives `video_dispatch.rs` real scene coverage. Steal #4 (yt-dlp)
is a separate installer slice that enables URL inputs.

### 4. Architecture-fit check

| Steal | Rules strained |
|-------|----------------|
| #1 Scene-change sampling | R1 ✓ (ffmpeg already required); R5 needs new WAL `ExtendedSubtype` event for `FrameExtractionComplete` if not already present; R8 ✓ (ffmpeg Windows-compatible). R3: GUI panel must expose scene-threshold slider (currently `video_dispatch.rs` would hardcode it). |
| #2 KEYFRAME_MIN fallback | No new rules strained — pure logic change. |
| #3 Perceptual dedup | R5: if dedup count is emitted to WAL, must use ExtendedSubtype; R3: GUI could expose dedup-threshold toggle. Low risk. |
| #4 yt-dlp installer | R1 strained if wizard does not install yt-dlp — must add `src/installers/yt_dlp.rs` analogous to `node.rs`. R5: egress (download from internet) needs a `DownloadConsent` gate through `permissions/`. R6: downloaded video bytes are untrusted input, must be defanged / sandboxed in tempfile (already pattern in `video.rs`). R8: yt-dlp has Windows binaries, ✓. R3: GUI needs URL input field for `/watch` equivalent. |

### 5. Verdict

**ADOPT-NATIVE for steals #1–#3.** Port the ffmpeg filter strings, fallback thresholds,
and dedup algorithm directly into Rust. No Python code needed — the real IP is the tuned
constants and algorithm structure, not the Python wrappers.

**ADOPT-NATIVE for steal #4 (yt-dlp), deferred.** Depends on `src/installers/yt_dlp.rs`
plus a consent gate for URL download. R1 and R5 both require work before shipping.

**Licence:** MIT. No attribution obligation beyond keeping the license header if any file
is copied verbatim (we are porting constants and logic into Rust, so attribution note in
the module header `//! Algorithm adapted from bradautomates/claude-video (MIT)` suffices).

---

## Repo 2 — Unlimited-OCR

### 1. What it actually does

This is a **model release**, not a library. Source code in the repo consists of:

| File | Content |
|------|---------|
| `infer.py` (416 lines) | Concurrent SGLang-server inference script |
| `wheel/sglang-0.0.0.dev11416+g92e8bb79e-py3-none-any.whl` | Custom 80 MB SGLang dev wheel |
| `README.md` | HuggingFace model card with inference recipes |
| `Unlimited-OCR.pdf` | Paper (arXiv 2606.23050) |

**Model:** `baidu/Unlimited-OCR` on HuggingFace. Derived from DeepSeek-OCR / DeepSeek-OCR-2
lineage — a vision transformer (VLM) architecture. The model ID is
`PaddlePaddle/Unlimited-OCR` on ModelScope.

**Inference stack:**
- HuggingFace `transformers.AutoModel` on CUDA 12.9 + PyTorch 2.10.0 + NVIDIA GPU (required, not optional)
- vLLM (Docker image `vllm/vllm-openai:unlimited-ocr`)
- SGLang (custom wheel, not yet upstreamed) — what `infer.py` uses
- Context length: 32,768 tokens. Handles multi-page PDFs by converting each page to PNG at 300 DPI (via PyMuPDF) and submitting concurrently via `ThreadPoolExecutor`.
- Custom logit processor `DeepseekOCRNoRepeatNGramLogitProcessor` reduces output repetition (`NO_REPEAT_NGRAM_SIZE = 35`, `NGRAM_WINDOW = 128`).
- Server launched via `python -m sglang.launch_server --model baidu/Unlimited-OCR --attention-backend fa3 ...` on port 10000.

**Model weights licence:** Repo `LICENSE` file is MIT for the **code**. Model weights
hosted on HuggingFace at `baidu/Unlimited-OCR` carry a **separate licence** — not verified
in the cloned repo (no `model_card.md` included). Based on Baidu's PaddlePaddle lineage,
weights are likely Apache 2.0, but **this must be verified on HuggingFace before any
adoption decision** — model weights licences often carry non-commercial or attribution
clauses independent of the code repo.

### 2. Where it beats NEOTH

NEOTH has no OCR engine. Confirmed:
```
rg -n 'ocr\|tesseract\|paddleocr\|OCR' SRC/neothd/src/
# → (no output)
```

`media/docling.rs` (2623 lines) is a supervised sidecar for Docling — it extracts text
from structured documents (PDFs, DOCX, PPTX). This is **not OCR**: Docling works on
machine-readable PDFs that already have embedded text layers; it does not perform
pixel-level character recognition on scanned pages or arbitrary images.

`media/vision.rs` (390 lines) dispatches images to multimodal LLMs for visual
description — also not dedicated OCR.

**The gap:** NEOTH cannot extract text from scanned PDFs, photos of documents, printed
signs, or screenshots with non-selectable text. Unlimited-OCR addresses exactly this.

### 3. Steal-list

No code-level steal is viable. The reasons are architectural (see §4). However:

| # | What to adapt | How | Effort |
|---|--------------|-----|--------|
| — | Document the `infer.py` API contract (SGLang HTTP endpoint at `:10000`, JSON request format, `document parsing.` prompt, ngram dedup logit processor) as a future sidecar spec | GROUND-TRUTH reference only | S |

### 4. Architecture-fit check

Every attempt to adopt Unlimited-OCR hits hard blockers:

**Rule 1 (Self-contained):** The model weights are `~7–14 B` parameters (not stated
explicitly but implied by VRAM requirements and DeepSeek-OCR lineage). Weights are
downloaded from HuggingFace at runtime — the wizard cannot bundle them. The custom
SGLang wheel is 80 MB and not yet upstreamed. A sidecar following `docling.rs` pattern
would install Python + SGLang + model weights on first use, requiring 20–30 GB disk
and 16 GB+ VRAM. This is technically feasible but the wizard step is non-trivial.

**Rule 8 (Cross-platform / Win11 filter):** CUDA 12.9 is required. Most consumer Win11
laptops lack a CUDA-capable GPU. There is no CPU-inference path, no ONNX export, and no
DirectML or ROCm path mentioned. The `infer.py` immediately dies without `cuda` device.
This alone is a **hard block** for the Win11 "Alex's mom" filter.

**ONNX path:** The `ort` crate could run an ONNX-exported version. However, this model
uses a custom architecture (DeepSeek-OCR VLM with custom logit processor) that is not
straightforwardly ONNX-exportable with current tooling. No ONNX export is offered.

**Docling sidecar analogy:** Docling runs on CPU, works on Win11, and handles machine-
readable PDFs — that is why the sidecar was viable. Unlimited-OCR needs CUDA; the analogy
breaks.

### 5. Verdict

**SKIP.** Rule 8 (cross-platform) is an unconditional hard block — CUDA-only inference
has no Win11 CPU fallback. Rule 1 (self-contained) adds a second blocker (model weights
cannot be bundled). Until Unlimited-OCR ships an ONNX or DirectML inference path, there
is no adoption route.

The correct OCR play for NEOTH is either: (a) routing images through the existing
multimodal LLM path in `media/vision.rs` for photo-OCR tasks (works today, no VRAM
requirement), or (b) an explicit ONNX-based OCR model (e.g., TrOCR via `ort`) when that
need becomes a tracked consumer.

**Licence note:** Repo code = MIT. Model weights = unknown (HuggingFace `baidu/Unlimited-OCR`
card not verified — check before any future adoption).

---

## Repo 3 — MediaCrawler

### 1. What it actually does

205-file Python async crawler for Chinese social platforms. Architecture:
- `main.py` → `CrawlerFactory` dispatches to `XiaoHongShuCrawler`, `DouYinCrawler`,
  `KuaishouCrawler`, `BilibiliCrawler`, `WeiboCrawler`, `TieBaCrawler`, `ZhihuCrawler`
- `base/base_crawler.py` (127 lines): Abstract `AbstractCrawler` + `AbstractApiClient`;
  initialises `ProxyIpPool`, launches `BrowserContext` via Playwright, injects
  `libs/stealth.min.js` to defeat bot detection.
- `proxy/proxy_ip_pool.py`: Pluggable proxy pool — validates IPs via echo URL, random
  selection with removal, tenacity retry, expiry-based refresh (`get_or_refresh_proxy`).
  Providers: `new_kuai_daili_proxy`, `new_wandou_http_proxy` (commercial Chinese proxy
  services).
- `cache/local_cache.py`: TTL-based local KV cache to skip already-crawled content IDs.
- Platform-specific `client.py` + `core.py` + `help.py` + `login.py` per platform.
- `media_platform/douyin/help.py`: `get_a_bogus(params, post_data, user_agent, page)` —
  calls `window.bdms.init._v[2].p[42].apply(...)` via execjs + compiled Douyin JS
  (`libs/douyin.js`), implementing Douyin's reverse-engineered request signing scheme.
- `media_platform/xhs/core.py`: Playwright BrowserContext + stealth injection + cookie
  extraction; random sleep (`asyncio.sleep(config.CRAWLER_MAX_SLEEP_SEC)`) between
  requests; proxy pool auto-refresh.
- Storage backends: MySQL, MongoDB, CSV, JSON, Excel (multiple store adapters).
- REST API layer in `api/` (FastAPI + WebSocket) for external control.

### 2. Licence — this is the disqualifying question

**The licence is NOT MIT, NOT Apache, NOT any OSI-approved licence.**

It is a custom "NON-COMMERCIAL LEARNING LICENSE 1.1" (`relakkes@gmail.com`, 2024) with
the following explicit restrictions (full text read verbatim from `/tmp/adopt2026/MediaCrawler/LICENSE`):

- Scope: "free, non-exclusive, non-transferable right to use, copy, modify, and merge the
  Software for **non-commercial learning purposes only**."
- Condition 2: "**limited to learning and research purposes only, and may not be used for
  large-scale crawling or activities that disrupt platform operations.**"
- Condition 3: "may not be used for any **commercial purposes** or to cause improper
  influence on third parties."
- Dispute resolution: "people's court where the **copyright owner is located**" (China
  jurisdiction, PRC law).

Incorporating any MediaCrawler code into NEOTH — a product that may be used commercially
or redistributed publicly — is **prohibited by the licence**. This is not a grey area.

### 3. Platform ToS exposure

Every platform MediaCrawler targets (XiaoHongShu, Douyin, Kuaishou, Bilibili, Weibo,
Tieba, Zhihu) prohibits automated collection in its ToS. The implementation:
- Uses logged-in browser sessions to authenticate as a real user
- Injects `libs/stealth.min.js` — the puppeteer-extra stealth plugin — specifically to
  **defeat platform bot detection**
- Implements Douyin's proprietary `a_bogus` request signing via a decompiled/reverse-
  engineered copy of Douyin's JS SDK (`libs/douyin.js`)
- Provides commercial proxy pool integration (kuai-daili, wandou HTTP) to rotate IPs

The reverse-engineered signing JS (`libs/douyin.js`) may additionally violate the CFAA
(US), the EU's Computer Misuse Directive, or equivalent national law depending on
jurisdiction. This is a reputational and legal liability that would follow any code
lineage into NEOTH's public release.

### 4. Where it beats NEOTH (platform-neutral engineering assessment)

Setting aside the licence, NEOTH's `web_fetch.rs` (1895 lines) covers: SSRF-hardened HTTP
GET, HTML-to-text extraction, goal-based LLM extraction, CSS-selector extraction
(`web_extract.rs`), caching (`web_doc_cache.rs`). It explicitly does **not** have:
- JS-rendered page support (Playwright, deferred to Phase 2 per inline comment)
- Proxy pool with IP rotation and health validation
- Browser stealth injection
- Incremental crawl checkpointing (skip-already-seen IDs)
- Rate-limit backoff (random sleep, configurable)

Ripgrep verified:
```
rg -n 'proxy\|ProxyPool\|browser_context\|playwright\|rate_limit\|backoff\|incremental_crawl' SRC/neothd/src/tools/
# → (no output)
```

The **proxy pool validation pattern** (validate-on-load, random selection, expiry-aware
refresh, tenacity retry) and the **incremental crawl checkpoint** (cache already-seen IDs,
skip on re-run) are genuinely useful patterns. But they can be implemented independently
from MediaCrawler — these are standard techniques documented in any web-scraping
engineering guide, not novel inventions.

### 5. Steal-list

**None.** The licence prohibits any adaptation, and platform-specific signing code is
legally toxic. The platform-neutral patterns (proxy pool rotation, incremental cache) are
well-known and implementable without copying this codebase.

### 6. Verdict

**SKIP — hard legal block.** NON-COMMERCIAL LEARNING LICENSE 1.1 prohibits incorporation
into a commercially-usable product. Platform-ToS exposure (stealth automation, RE'd
signing JS) compounds the liability. Adopting any MediaCrawler code would compromise
NEOTH's public release. The proxy-pool and incremental-crawl patterns are worth
implementing independently when a real consumer exists (Rule 9).

---

## Summary Steal-List (Ranked)

| # | Item | Source | Target NEOTH file | Effort | Real consumer |
|---|------|---------|-------------------|--------|---------------|
| 1 | Scene-change `SamplingStrategy::SceneChange { threshold: 0.20, min_frames: 8 }` — ffmpeg `select='gt(scene,T)'` + showinfo pts_time parsing | `claude-video/frames.py:SCENE_THRESHOLD` | `src/media/video_frames.rs` (new enum variant + impl) | M | `media/video_dispatch.rs::extract_frames_for_vision()` |
| 2 | Perceptual dedup: 16×16 greyscale MAD ≤ 2.0 — pure-stdlib, no image crate | `claude-video/frames.py:_dedupe_by_deltas()` | `src/media/video_dispatch.rs` (new fn `dedup_frames`) | S | `video_dispatch.rs` post-extraction step |
| 3 | KEYFRAME_MIN=4 fallback to uniform when keyframe count is sparse | `claude-video/frames.py:KEYFRAME_MIN=4` | `src/media/video_frames.rs` | S | `video_dispatch.rs` Keyframes strategy arm |
| 4 | yt-dlp installer + caption-first URL download wrapper | `claude-video/download.py:download()` | `src/installers/yt_dlp.rs` (new) + `src/media/video.rs` | M | `media/video_dispatch.rs` for `VideoSource::Url` inputs |

## Build Order — Staged Slices

**Slice E-1 (no new deps, no installer):** Steals #1 + #2 + #3. Extend
`video_frames.rs` with `SceneChange` variant; add `dedup_frames()` to
`video_dispatch.rs`; add `KEYFRAME_MIN` fallback. All ffmpeg flags, no new
subprocess. Wire through `video_dispatch.rs`. Add GUI toggle for threshold
in video settings panel (Rule 3). WAL: new `ExtendedSubtype::VideoFrameExtracted`
event if not already present.

**Slice E-2 (installer slice):** Steal #4. `src/installers/yt_dlp.rs` mirrors
`node.rs` pattern. Wizard prompts for `yt-dlp` install. `VideoSource::Url`
arm in `video.rs` dispatches to yt-dlp, returning temp file path consumed
by existing frame extraction path. `permissions/` consent gate for egress
URL download. WAL: `ExtendedSubtype::VideoDownloadConsented`.

## Items that contradict the brief's baseline

1. **NEOTH video path is audio-only** — `video.rs` strategy comment says "extract audio
   track" and the MM-02 doc says "frame extraction + multimodal council". The
   `video_frames.rs` strategy enum exists but there is no wired path from a URL or file
   to actual frame extraction feeding a vision synthesizer. The briefing inventory says
   "STT + TTS + VAD + speaker-ID + PDF/Docling all exist as discrete dispatchers" without
   clarifying that the video frame path is data-types-only, not a wired pipeline. Slice
   E-1 is the first time frames would actually feed the vision council from video input.

2. **No OCR gap is called out in the brief** — The brief lists "No OCR engine of its
   own" but frames it as a fact, not a tracked gap. Given that `media/vision.rs` can
   already route images to multimodal LLMs, photo-OCR is achievable today via that path.
   The brief should note this fallback explicitly so the OCR gap is not over-stated in
   future sessions.

3. **MediaCrawler licence is mischaracterised in SPDX as NOASSERTION** — it is actually
   a specific proprietary restrictive licence, not merely unidentified. The practical
   effect is the same (unusable), but future agents should know it is actively restrictive,
   not just unlabelled.
