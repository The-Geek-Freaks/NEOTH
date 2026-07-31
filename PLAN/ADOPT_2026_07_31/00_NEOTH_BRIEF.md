# NEOTH capability brief — for repo-adoption deep-read agents (2026-07-31)

Read this BEFORE touching an external repo. It exists so you do not "discover" a gap
that NEOTH already closed. Everything below was verified by directory listing / ripgrep
on `SRC/neothd/src` at HEAD on 2026-07-31.

## What NEOTH is

Local-first personal AI daemon. Single Rust crate `neoth` (`SRC/neothd`, edition 2024,
rust-version 1.91) + Slint desktop GUI (`SRC/neothd-gui`) + `neoth-relay`,
`neoth-plugin-sdk`, `neoth-migrate`. ~70 top-level modules. Hard architectural rules
live in `PLAN/00_DESIGN_v1.1_FINAL.md`; the release tracker is
`PLAN/ROAD_TO_1_0_GOLD.md`.

### Non-negotiable architecture rules (violating these = automatic REJECT)

1. **Self-contained.** Everything ships inside the binary or is installed by NEOTH's own
   wizard/installers (`src/installers/`). No "user must `pip install` X first".
   A Python/Node sidecar is only acceptable if NEOTH installs, supervises, sandboxes and
   version-pins it itself (precedent: `media/docling.rs` supervises an owned Docling
   process; `src/installers/{node,qwen_weights,paperless,obsidian,tmux}.rs`).
2. **Features default-ON + runtime toggle.** Cargo features decide only whether a backend
   is *compiled in*. Runtime behaviour is gated by `freedom.yaml`, toggleable from wizard
   and GUI. Never gate user-visible behaviour behind a cargo flag alone.
3. **GUI-first + parity.** Every CLI command / slash command needs a GUI panel and a
   settings surface. New capability without a GUI surface is incomplete.
4. **Model-version-agnostic.** No hardcoded model names/versions; CLI pass-through and a
   live catalog (`src/models/catalog.rs`, `discovery.rs`, `refresh_task.rs`).
5. **Consent-gated + audited.** Any new egress, filesystem reach or destructive action
   goes through `src/permissions/` (tier classifier, gate, lease, audit) and emits a WAL
   event. **WAL top-level opcodes 255/255 are exhausted — new events must use the
   Extended-Subtype band** (`ExtendedSubtype` in `src/wal/events.rs`, plus the daemon
   allowlist in `src/daemon/audit_rpc/server.rs`, plus its exhaustive
   `allowlist_contains_exactly_*` test).
6. **Untrusted content is untrusted.** Anything fetched/imported must be defanged before
   it reaches a prompt (`defang_prompt_delimiters`, `security/ingress_sanitizer.rs`,
   `security/content_scanner.rs`, `security/redact.rs`).
7. **Retrieval indexes are never truth-authors.** Canonical ownership is explicit;
   SQLite/embedding indexes are derived views only.
8. **Cross-platform, "Alex's mom on Win11" filter.** Windows is a first-class target.
   No bash-only, no POSIX-only assumptions.
9. **No primitive ahead of its consumer.** Only adopt something that has a real caller.
10. **Immutability / small files.** 200–400 lines typical, 800 max, high cohesion.

## Existing subsystems — the honest inventory

| Area | Where | State |
|---|---|---|
| LLM provider routing | `src/providers/` (~45 files): `anthropic_api`, `openai_api`, `gemini_api`, `cohere_api`, `ollama_api`, `aws_bedrock`+`aws_sigv4`, `azure_openai`, `copilot`, `claude_cli`+`claude_tmux`+`claude_session`, `local_qwen`, `whisper`, `embed` | Mature. Plus `fallback.rs`, `circuit_breaker{,_stream}.rs`, `quota.rs`, `cost.rs`, `cost_authorization.rs`, `meter.rs`, `token_cap.rs`, `singleflight.rs`, `response_bounds.rs`, `model_roles.rs`, `recursive_mas*.rs` |
| Model catalog / selection | `src/models/`: `catalog`, `discovery`, `selector`, `benchmark_scores`, `gguf_variants`, `hemisphere_preset`, `cli_detect`, `refresh_task` | Mature, version-agnostic |
| Memory | `src/memory/` (~45 files): `archive`, `assoc_graph`, `consolidate`, `consolidation_sweep`, `contradiction`, `decay_task`, `drift`, `embeddings`, `entities`, `forget`, `gc{,_task}`, `groundtruth`, `hindsight`, `indexer`, `integrity`, `foreign_import`, `ingress`, `channel_weights`, `dimension`, `eval_harness`, `compaction_guard`, `change_bus`, `bulk_text`, `context_inject`, `migrations/` | Very mature 5-tier system |
| Recall | `src/recall/`: `conversational`, `reconstruct`, `citation_check`, `goldset`, `parity{,_run}` | Mature |
| Skills | `src/skills/` (34.8k LOC): `installer`(8.2k), `authority`(5.8k), `store`, `registry`, `mutation_lifecycle`, `loader`, `bundled`, `router`, `creator`, `schema`, `test_harness`, `auto_extract`(659), `teacher`(566), `versioning`, `mode_registry`, `plan_attestation` | Mature install/authority/lifecycle. **`auto_extract::maybe_extract_skill` = post-conversation skill extraction; `teacher.rs` = correction→skill.** No document/book→skill path. |
| Media | `src/media/`: `stt_dispatch`, `stt_provider`, `stt_postprocess`, `tts_dispatch`, `tts_provider`, `tts_cloud`, `dictation`, `vad/{mod,smoothed}`, `speaker_encoder{,_ecapa,_xvector}`, `speaker_profile`, `resampler`, `audio`, `vision`, `video`, `video_dispatch`, `video_frames`, `frame_decoder`, `pdf`, `docling`, `document`, `model_manager`, `hw_probe`, `multimodal_synth` | STT + TTS + VAD + speaker-ID + PDF/Docling all exist as **discrete dispatchers**. **There is NO realtime full-duplex conversation loop, no barge-in/interruption, no streaming-chunk pipeline between them** (verified: the only `full_duplex` hits in the tree are the Keet channel bridge, unrelated to audio). |
| Documents | `media/document.rs` (docx/pptx/epub/rtf/zip with archive limits + byte ceilings), `media/pdf.rs`, `media/docling.rs` (supervised owned sidecar) | Extraction exists. No knowledge-distillation on top. |
| Obsidian / vault | `src/installers/{obsidian,obsidian_vault,obsidian_vault_w02,obs}.rs`, `L6_Vault_Template/`, `src/wiki/{sources,renderer,ingest,writer,capabilities,release_snapshot}.rs` | Vault install + wiki render exist. Preload/provenance items are tracked open in ROAD (B04/B05/B13). |
| Code intelligence | `src/code_map/` + `graphify-out/` graphs + `src/lsp/` + codegraph MCP server | Symbol index, per-root `index_generation`, staleness via sha256 re-scan, recall containment by active root |
| Web / research | `src/tools/`: `web_fetch`(1.9k), `web_search`, `web_extract`, `web_selector_cache`, `web_doc_cache`, `search_cache`, `search_analytics`, `deep_research`, `jina_reader`, `arxiv`, `github`, `external_http`, `caldav`, `todoist`, `google_tasks`, `microsoft_todo` | Mature fetch/search/extract with caching + SSRF hardening |
| Governance | `src/permissions/` (`mod` 2.1k, `gate` 1.4k, `tier_classifier`, `policy`, `lease`, `audit`), `src/policy/`, `src/consent.rs`, `src/security/` (`dep_health` 3.3k, `refusal_recovery`, `redact`, `osv_check`, `ingress_sanitizer`, `content_scanner`, `email_{sanitizer,threat}`, `secrets_scan`, `risk_gate`, `api_tokens`, `credential_redact`, `stream_batch_sanitizer`, `refusal_{abliterated,hard_block,cause}`) | Very mature. Consent tiers, leases, redaction, OSV/dep-health, refusal taxonomy |
| Council (multi-agent review) | `src/council/`: `orchestrator`(1.5k), `types`, `quality_score`, `callosum`, `self_reflect`, `trigger`, `daily_budget`, `budget`, `nspace`, `day_counter`, `factual_check`, `diversity`, `dissent`, `stop_verifier`, `motive_ident`, `mds_tone`, `eval` | Mature adversarial-panel machinery |
| Coding agent | `src/coding/`: `decomposer`, `dispatcher`, `task_executor`, `worker`, `provider_worker`, `plan_review`, `plan_writer`, `review`, `second_opinion`, `tdd_preflight`, `validate`, `early_stop`, `retry`, `intent`, `classifier`, `self_source{,_gate}`, `cerebellum_provider`, `tokenjuice_rules`, `tool_router`, `model_profile`, `analyze`, `brainstorm`, `cargo_check`, `feed`, `store` | Mature |
| Autonomy / scheduling | `src/loop_engine/`, `src/cron/`, `src/daemon/*_cron.rs` (babel, doctor, drift_alert, consolidation_sweep, contradiction_resolve, guidance, g02_surfacing, arxiv_skill_scan, omi_ingest, bg_monitor), `src/proactive/{mod,action_staging}.rs`, `src/reflection/{mod,periodic}.rs`, `src/self_improve.rs`, `src/ecology/` | Mature cron + proactive staging |
| Integration surfaces | `src/mcp/`, `src/hooks/`, `src/slash/`, `src/channels/` (11+ channels), `src/n8n_api/`, `src/oai_serve/` (OpenAI-compatible server), `src/cluster/` (hyperswarm + iroh), `src/paperless/`, `src/os_tools/`, `src/computer_use.rs`, `src/integrations/`, `src/wasm_plugin/` | Mature |
| Audit / durability | `src/wal/` (signed WAL, Extended-Subtype band), `src/recovery/`, `src/telemetry/`, `src/feedback/`, `src/adr/`, `src/domain_events/` | Mature |
| **Absent entirely** | finance / market data / trading / backtesting: ripgrep for `stock\|ticker\|backtest\|ohlcv\|yfinance` finds **zero** real hits (only substring noise like "upgrading"). No OCR engine of its own (`media/vision.rs` + Docling only). No social-media crawler. No video-editing/rendering pipeline. | — |

## Your deliverable contract

For **each** repo assigned to you, produce these five sections. Ground every claim in a
file path you actually read.

1. **What it actually does** — derived from source, not the README. Name the files.
2. **Where it beats NEOTH** — the specific logic/algorithm/prompt/data, `their-file:line`
   vs. our equivalent `SRC/neothd/src/...:line`. If NEOTH already does it as well or
   better, say so plainly — a "no gap" verdict is a valid and valuable result.
3. **Steal-list** — ranked, concrete. Each entry: what exactly to port, which NEOTH module
   it lands in, roughly how (new file / extend existing fn), the real consumer that will
   call it, and effort (S/M/L/XL).
4. **Architecture-fit check** — for each steal-list entry, walk the 10 rules above and
   name any that it strains (especially self-contained, consent/WAL, GUI parity,
   cross-platform, untrusted-content).
5. **Verdict** — `ADOPT-NATIVE` (port the logic into Rust) / `GROUND-TRUTH` (keep as
   reference data or a bundled skill/prompt, do not port code) / `SKIP` (say why).
   Include license (SPDX) and any attribution obligation.

### Method

- `gh api repos/<owner>/<repo>/git/trees/<default_branch>?recursive=1 --jq '.tree[].path'`
  to enumerate, then fetch the high-value source files via
  `https://raw.githubusercontent.com/<owner>/<repo>/<branch>/<path>`.
  Read the actual implementation. **Do not evaluate from the README.**
- For NEOTH-side claims use ripgrep/read on `SRC/neothd/src`. Every "NEOTH lacks X" must
  be backed by a search you actually ran — quote the command. Prior sessions burned real
  time on hallucinated gaps; a wrong "NEOTH lacks this" is the most expensive error you
  can make here.
- Prefer `wc -l`/`rg` over dumping whole files into context.
