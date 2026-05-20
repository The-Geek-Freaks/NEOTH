# Local Models

Neoth can run a small language model on your GPU for tasks where you want your data to stay
on your machine. The primary use case is profile extraction — learning about you from your
conversations without sending those conversations to a cloud provider.

**Local model support is a Phase 2 feature.** Not in v0.1.0.

---

## Why local?

**Privacy.** Cloud LLMs are great at answering questions, but they receive your conversation
text. With a local model for profile extraction, that specific task stays entirely on your
hardware. Your raw conversations never leave your machine for that purpose.

**Cost.** Calling a cloud API for every post-conversation extraction adds up (~$985/year at
typical usage volume). Local inference costs electricity only (~$0 per call).

**Trade-off.** Local inference is slower. ~32 seconds for an 800-token extraction window at
25 tokens/second on a mid-range GPU. This is acceptable because profile extraction runs in
the background after you get your response — it is not on the critical path.

---

## Model: Qwen3-4B-INT4

The default local model is **Qwen3-4B** quantized to INT4.

| Property | Value |
|----------|-------|
| Size | ~2.4 GB on disk |
| VRAM required | ~3 GB |
| CPU fallback | Yes, slower (~3-5 tokens/second) |
| Languages | English + German + others |
| License | Apache 2.0 |
| Context window | 32,768 tokens |

---

## Hardware requirements

**Minimum:** 3 GB VRAM. Any CUDA-compatible GPU (NVIDIA) works.
CPU fallback is available but significantly slower. Profile extraction at CPU speed takes
~5-10 minutes per turn — functional, but you may want to adjust extraction frequency.

**Recommended:** 4+ GB VRAM. Leaves headroom for the embedding model (Qwen3-Embedding-0.6B,
~1 GB) running alongside.

Multi-GPU: if you have multiple GPUs, the local model uses one. You can configure which:

```toml
# ~/.neoth/inference.toml
[runtime]
device = "cuda:1"         # use the second GPU
fallback_device = "cpu"
```

---

## Setup

### Step 1 — Download the model

```
neoth model fetch qwen3-4b-int4
```

This downloads to `~/.neoth/models/qwen3-4b-int4.gguf` (~2.4 GB) from HuggingFace.
SHA-256 is pinned and verified before the model loads.

Resume a partial download:

```
neoth model fetch qwen3-4b-int4 --resume
```

### Step 2 — Verify

```
neoth model verify qwen3-4b-int4
```

Should print:

```
qwen3-4b-int4.gguf  OK  (sha256 match)
Smoke test: 10 tokens in 0.4s on cuda:0
```

### Step 3 — Check freedom.yaml

Local extraction is enabled by default once the model is present. The key flag:

```yaml
inference:
  allow_cloud_fallback: false    # default — extraction skipped if local is down, no cloud
  local_model_path: ~/.neoth/models/qwen3-4b-int4.gguf
```

---

## When is the local model used?

| Task | Default model | Notes |
|------|--------------|-------|
| Profile extraction | Local (Qwen3-4B) | Your conversations stay on-device |
| Answering you | Cloud (Claude) | Requires the cloud LLM for quality |
| Council debate | Cloud (Claude, Gemini, Codex) | Multiple providers for diverse perspectives |
| Embeddings | Local (Qwen3-Embedding-0.6B) | Vector search, runs locally |

The split is intentional: use local where privacy matters most (extraction = raw conversation text),
use cloud where quality matters most (your actual response).

---

## Fallback behavior

If the local model is unavailable (not downloaded, GPU offline, OOM):

- **If `allow_cloud_fallback: false` (default):** Profile extraction is skipped for this turn.
  You still get a response. Learning resumes when the local model is back.
- **If `allow_cloud_fallback: true`:** Extraction falls back to the configured cloud provider.
  A WAL event is logged noting the cloud fallback.

---

## Verifying your privacy posture

After running Neoth for a while, check where your requests actually went:

```
neoth privacy audit --last 30d
```

Example output:

```
Last 30 days — LLM request destinations:
  LocalQwen3_4B:   8,234 requests  (profile extraction)
  CloudClaude:     1,012 requests  (response generation)
  CloudGemini:         0 requests
  CloudCodex:         87 requests  (council debate)
```

Zero `CloudGemini` for extraction means the H3 privacy fix is working: your conversations
are not going to Google for profile analysis.

---

## Alternative / fallback local models

If 3 GB VRAM is too tight, a smaller alternative:

```
neoth model fetch qwen3-1.7b-int4
```

~1.5 GB VRAM, weaker extraction quality but functional. Configure in `inference.toml`:

```toml
[models.generative.priority]
order = ["local_qwen3_1b7", "local_qwen3_4b", "cloud_gemini_3_1_pro"]
```

---

## OOM and other failures

See [troubleshooting.md#local-model-oom](troubleshooting.md#local-model-oom).
