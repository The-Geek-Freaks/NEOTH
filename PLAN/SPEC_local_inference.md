# SPEC: Local Inference (Qwen3-4B-INT4) — NEOTH v1.1

> Status: BUILD-READY. Fixes: **H3 (Privacy theater)**, **A1 (local generative model for extraction)**.
> Eliminates: profile-extraction sending the operator's conversations to Google Gemini API permanently.
> Scope: Phase 2 Day 38-42 (after Right Hemisphere wired Day 31-37).

---

## 0. Motivation

**Problem v1.0 (H3 + A1):**
- `profile.extract` pipeline sends conversation window to **Gemini 3.1 Pro API** on every PROVIDER_RESPONSE.
- `freedom.yaml profile.learn.health = false` prevents NEOTH STORING health claims locally — but does NOT prevent SENDING health-containing conversation content to Gemini for analysis.
- The privacy table in `SPEC_proactive_learning.md §11` claims "Profile to outbound providers: Never" — technically true (profile state stays local), operationally false (source data goes to cloud).
- The operator's conversations are processed by both **Anthropic** (Left Hemisphere) AND **Google** (profile extraction). 200+ messages/day = permanent privacy surface across two cloud vendors.
- Mitigation (`freedom.yaml health=false`) is theater because conversation text containing health/PII is sent regardless.

**Fix v1.1:** Run a **local generative model** for profile extraction. Conversations never leave the machine.

**Hardware available:** Operator's Cube (192.168.178.156) has 3 GPUs (per memory). Qwen3-4B-INT4 fits in ~3GB VRAM. ~25 tok/s on a mid-range GPU. Extraction window 800 tokens out → ~32s. Acceptable for Day-N async extraction (not on user-facing critical path).

---

## 1. Model Selection

| Model | Size | VRAM (Q4) | Throughput | Multilingual DE/EN | Function-calling | License |
|-------|------|-----------|------------|---------------------|------------------|---------|
| **Qwen3-4B-INT4** (default) | 4 B | ~3 GB | ~25 tok/s | Yes (operator code-switches DE/EN) | Native | Apache 2.0 |
| Qwen3-7B-INT4 | 7 B | ~5 GB | ~15 tok/s | Yes | Native | Apache 2.0 |
| Llama-3.2-3B-Instruct-Q4 | 3 B | ~2.5 GB | ~30 tok/s | Yes | Limited | Llama 3 license |
| Phi-3.5-Mini-Q4 | 3.8 B | ~3 GB | ~20 tok/s | Limited DE | Limited | MIT |
| Gemma-3-4B-Q4 | 4 B | ~3 GB | ~22 tok/s | Yes | Limited | Gemma license |

**Decision: Qwen3-4B-INT4.gguf.** Reasons:
- Native function-calling output schema (matches ProfileDelta JSON requirement)
- Strong DE+EN bilingual capability (operator code-switches)
- Apache 2.0 = no license friction
- Smaller than Qwen3-7B (~3GB vs ~5GB) — leaves VRAM for parallel processing

Fallback chain: `local_qwen3_4b → local_qwen3_7b → cloud_gemini_3_1_pro_preview`. Operator-configurable in `~/.neoth/inference.toml`.

---

## 2. Runtime: candle (Rust-native)

`candle-core` + `candle-transformers` (HuggingFace's Rust ML framework).

Why candle (not llama.cpp via FFI):
- Pure Rust — no C++ build dependencies on the operator's debian VM (already has issues with system glibc)
- Async-native (works with tokio)
- GGUF quantization support built-in
- candle is added to Cargo.toml at **Day 14** per v1.0 §9 schedule — same dep as embedding model. Single inference runtime.

Cargo:
```toml
candle-core         = "0.6"
candle-transformers = "0.6"
candle-nn           = "0.6"
hf-hub              = "0.3"     # model fetch
tokenizers          = "0.20"
```

---

## 3. Model Storage

```
~/.neoth/models/
  qwen3-4b-int4.gguf              # primary model (~2.4 GB)
  qwen3-4b-tokenizer.json
  qwen3-embedding-0.6b-q8.gguf    # embedding (already in v1.0 Day 14)
  inference.toml                   # runtime config
```

Download via `neoth model fetch qwen3-4b-int4`:
- Source: `huggingface.co/Qwen/Qwen3-4B-Instruct-GGUF/Q4_K_M`
- SHA-256 pinned in `inference.toml`
- Resume on partial download
- Verify SHA before loading

```toml
# ~/.neoth/inference.toml
[models.generative.qwen3_4b_int4]
path = "~/.neoth/models/qwen3-4b-int4.gguf"
sha256 = "abc123..."   # pinned, must match
tokenizer = "~/.neoth/models/qwen3-4b-tokenizer.json"
quantization = "Q4_K_M"
vram_required_mib = 3072
context_window = 32768

[models.generative.priority]
order = ["local_qwen3_4b", "local_qwen3_7b_if_present", "cloud_gemini_3_1_pro"]
fallback_on = ["timeout", "vram_exhausted", "load_failure"]

[runtime]
device = "cuda:0"      # cuda:0 / cuda:1 / cuda:2 / cpu
fallback_device = "cpu"
batch_size = 4         # parallel extractions on same GPU
timeout_ms = 60000     # 60s per inference (Phase 2 budget)
```

---

## 4. Local Inference API

```rust
use candle_core::Tensor;
use candle_transformers::models::qwen::Qwen3Model;

/// Schicht-0 pure tool: `local.generate`.
/// Input: prompt + generation_params. Output: completion text.
/// Deterministic when temperature=0 + seed pinned (G.1 compliance).
pub struct LocalInference {
    model:     Arc<Qwen3Model>,
    tokenizer: Arc<Tokenizer>,
    device:    Device,
    config:    InferenceConfig,
}

#[derive(Debug, Clone)]
pub struct GenerationParams {
    pub prompt:         String,
    pub max_tokens:     u32,        // default 800
    pub temperature:    f32,        // 0.0 for deterministic
    pub seed:           u64,        // SHA-256(prompt) for determinism
    pub stop_sequences: Vec<String>,
    pub timeout_ms:     u32,
}

#[derive(Debug)]
pub struct GenerationResult {
    pub text:               String,
    pub tokens_in:          u32,
    pub tokens_out:         u32,
    pub latency_ms:         u32,
    pub model_id:           String,    // "qwen3-4b-int4@abc123..." (SHA prefix for reproducibility)
    pub prompt_bundle_hash: [u8; 32],  // SHA-256(prompt) for replay determinism
}

impl LocalInference {
    pub async fn generate(&self, params: GenerationParams) -> Result<GenerationResult, InferenceError> {
        // 1. tokenize prompt
        let input_ids = self.tokenizer.encode(&params.prompt, true)?;
        let tokens_in = input_ids.len() as u32;

        // 2. fixed seed → deterministic when temperature=0
        candle_core::utils::set_seed(params.seed);

        // 3. forward pass with timeout guard
        let start = Instant::now();
        let completion = tokio::time::timeout(
            Duration::from_millis(params.timeout_ms as u64),
            self.model.generate(input_ids, &params),
        ).await
            .map_err(|_| InferenceError::Timeout)??;

        let latency_ms = start.elapsed().as_millis() as u32;
        let text = self.tokenizer.decode(&completion.token_ids, true)?;

        Ok(GenerationResult {
            text,
            tokens_in,
            tokens_out: completion.token_ids.len() as u32 - tokens_in,
            latency_ms,
            model_id: format!("qwen3-4b-int4@{}", &self.config.model_sha[..16]),
            prompt_bundle_hash: sha256(&params.prompt),
        })
    }
}
```

---

## 5. Integration into profile_learn.yaml (replaces Gemini in Phase 2+)

```yaml
# pipelines/profile_learn.yaml (v1.1 — see SPEC_proactive_learning.md §3.1 for full)
stages:
  - id: profile_extract
    tool: profile.extract
    schicht: 0
    inputs:
      attributed_window: "{{stages.window_attribute.attributed_window}}"
      existing_profile_summary: "{{idx_profile.summary_for_extractor}}"
      seed: "{{sha256(stages.window_attribute.attributed_window) | take_u64}}"
    outputs: [profile_delta]
    # CHANGED v1.1:
    model: local_qwen3_4b               # was: right_hemisphere (Gemini)
    model_fallback: cloud_gemini_3_1_pro_preview  # only if local unavailable
    temperature: 0.0
    seed_mode: deterministic
    max_tokens: 800
    inject_lowkey: false
    system_prompt_constraint: "claims_only_from_first_person_user_speech"
    on_refusal: mirror_pipeline
```

Fallback policy:
- Local model unavailable (Cube GPU offline, model not loaded, OOM) → emit `0x3A LOCAL_INFERENCE_UNAVAILABLE` event
- IF `freedom.yaml inference.allow_cloud_fallback = true` → call Gemini (operator explicitly opted in)
- ELSE → skip extraction this cycle, emit `0x3B PROFILE_EXTRACTION_SKIPPED` event

**Default freedom.yaml v1.1:**
```yaml
inference:
  allow_cloud_fallback: false   # privacy-first default
```

Operator must explicitly opt in to cloud fallback. Without opt-in, profile extraction simply pauses when local inference is down — pattern matches `profile.pause` semantics.

---

## 6. Privacy Architecture (H3 Resolution)

### 6.1 Updated Privacy Table (SPEC_proactive_learning.md §11 supersession)

| Data flow | Before v1.1 (H3 hole) | After v1.1 (H3 fixed) |
|-----------|----------------------|----------------------|
| Conversation text → profile extraction | **→ Gemini API (Google)** | **→ Local Qwen3-4B on Cube. Stays on machine.** |
| Profile claim storage (`idx_profile`) | Local (correct already) | Local (unchanged) |
| Block-B injection of profile summary | Sent to Left Hemisphere (Claude) when invoking | Same (necessary for hemisphere to use the profile in response) |
| Cloud-fallback if Cube offline | (was always cloud) | OFF by default. `freedom.yaml inference.allow_cloud_fallback` opt-in only. |
| Health/PII categories | Storage gated by `profile.learn.health=false` | Storage gate UNCHANGED. ALSO: conversation never leaves machine for extraction (no cloud) |

### 6.2 Explicit Statement

> **NEOTH's profile extraction NEVER transmits the operator's conversation content to a third-party cloud provider unless `freedom.yaml inference.allow_cloud_fallback = true` is explicitly set by the operator.**

Block-B injection still requires sending the profile **summary** (high-confidence fields only) to the Left Hemisphere provider during response generation — but this is the assembled profile (not raw conversations) and is the minimum necessary for the Left Hemisphere to produce a profile-aware response. This is documented as a known trade-off, not hidden.

### 6.3 PROVIDER_REQUEST audit

Every PROVIDER_REQUEST WAL event (0x0D) gains a typed `target_destination` field:
```rust
pub enum ProviderTarget {
    LocalQwen3_4B,
    LocalQwen3_7B,
    CloudClaude,
    CloudGemini,
    CloudCodex,
    CloudQwen2_5_72B_Local,  // user's own LMStudio instance
}
```

`neoth privacy audit --last=30d` reports counts per target:
```
Last 30 days — PROVIDER_REQUEST destinations:
  LocalQwen3_4B:   8,234 requests
  CloudClaude:     1,012 requests (user-response generation)
  CloudGemini:         0 requests   (good — H3 fixed)
  CloudCodex:         87 requests   (council debate when triggered)
```

---

## 7. Cost / Performance Profile

| Workload | Per-call cost | Latency |
|----------|---------------|---------|
| **Local Qwen3-4B extraction** | **~$0 (electricity only, ~5Wh/call)** | **~32s (800 tokens out @ 25 tok/s)** |
| Cloud Gemini 3.1 Pro extraction (was v1.0) | ~$0.027 | ~3-8s |

Trade-off: local is **slower** (~10x latency) but **free** and **private**. Profile extraction is NOT on user-facing critical path (runs async after PROVIDER_RESPONSE) — latency acceptable.

Cube hardware budget:
- 3 GPUs total
- 1 GPU reserved for Qwen3-4B (3 GB VRAM)
- 1 GPU reserved for embedding worker (Qwen3-Embedding-0.6B, ~1 GB)
- 1 GPU free for future workloads (e.g., Phase 4 ambient processing)

Annual cost saved vs Gemini cloud extraction:
- 100 turns/day × 365 = 36,500 extractions/year
- Cloud cost: 36,500 × $0.027 = **$985/year** saved
- Plus: zero conversations to Google permanently

---

## 8. Health-Check + Failure Mode

```rust
/// Schicht-0 health check tool. Called by BrainStem on startup + every 60s.
pub fn local_inference_health() -> HealthStatus {
    // 1. Model file exists at configured path? SHA matches?
    // 2. Tokenizer loads?
    // 3. GPU available (Cube reachable + VRAM free)?
    // 4. Smoke test: generate 10 tokens from "test" prompt within 5s?
    HealthStatus { /* ... */ }
}
```

Failure modes + responses:
- Model file missing → operator alert, profile-extraction PAUSED, `0x3A LOCAL_INFERENCE_UNAVAILABLE` emitted
- Cube SSH unreachable → same as above
- VRAM exhausted by other process → automatic retry with batch_size=1 (degrade), if still fails → PAUSED
- Generation timeout (60s exceeded) → emit `0x3C LOCAL_INFERENCE_TIMEOUT`, this extraction skipped

---

## 9. Test Plan

```rust
#[test]
fn test_local_inference_deterministic() {
    // Same prompt + seed = byte-identical output across 10 runs.
    let params = GenerationParams {
        prompt: "Extract user profile from: I work as a security researcher in Berlin.",
        seed: 12345,
        temperature: 0.0,
        ..Default::default()
    };
    let results: Vec<_> = (0..10).map(|_| infer.generate(params.clone()).await.unwrap()).collect();
    let first = &results[0].text;
    for r in &results[1..] {
        assert_eq!(r.text, *first);
    }
}

#[test]
fn test_local_extraction_no_cloud_egress() {
    // Pipeline runs profile_extract with local_qwen3_4b model.
    // Assert: zero outbound HTTP requests to Google/Anthropic/OpenAI hosts during extraction.
    let net_monitor = MockHttpClient::expect_no_external_calls();
    profile_learn.run().await;
    net_monitor.assert_zero_external();
}

#[test]
fn test_cloud_fallback_requires_opt_in() {
    // freedom.yaml inference.allow_cloud_fallback = false (default)
    // Local inference fails (mock).
    // Assert: extraction skipped, PROFILE_EXTRACTION_SKIPPED emitted, NO cloud call.

    let net_monitor = MockHttpClient::expect_no_external_calls();
    let mut local = MockLocalInference::always_fails();
    profile_learn.run_with(&mut local).await;
    net_monitor.assert_zero_external();
    assert!(wal.contains_event(0x3B));  // PROFILE_EXTRACTION_SKIPPED
}

#[test]
fn test_cloud_fallback_used_when_opted_in() {
    set_freedom("inference.allow_cloud_fallback", true);
    let mut local = MockLocalInference::always_fails();
    let mut net = MockHttpClient::expect_call_to("generativelanguage.googleapis.com");
    profile_learn.run_with(&mut local).await;
    net.assert_called();
}
```

---

## 10. Schedule Integration

| Phase | Day | Deliverable |
|-------|-----|-------------|
| 1 MVP | 30 | NOT in scope. Day-30 unchanged (Telegram + Left-Claude + recall). |
| 2 | 31-37 | Right Hemisphere (Gemini) wired — prerequisite for Phase-2 work but Gemini for response generation NOT extraction |
| 2 | 38 | `~/.neoth/models/qwen3-4b-int4.gguf` downloaded + verified. SHA pinned. |
| 2 | 39 | `LocalInference` Rust impl + candle integration. `test_local_inference_deterministic` passes. |
| 2 | 40 | `profile_learn.yaml` updated to use `model: local_qwen3_4b`. `test_local_extraction_no_cloud_egress` passes. |
| 2 | 41 | Health-check + fallback policy. `freedom.yaml inference.allow_cloud_fallback` default-false. |
| 2 | 42 | `neoth privacy audit` CLI. Privacy table update in SPEC_proactive_learning.md §11. |

---

## 11. Status

**v1.1 local inference BUILD-READY.** H3 (privacy theater) + A1 (local model) resolved.
Operator's conversations stay on their hardware. Cloud cost saved: ~$985/year. Privacy gained: priceless.
