# NEW_SOURCES_INTEGRATION.md — NEOTH v0.6

> **Reference document.** Captures analysis or synthesis at a specific point in time.
> The normative current state lives in `00_DESIGN_v1.1_FINAL.md` plus the `SPEC_*.md`
> files. Use this for context; not build instructions.
# Source Evaluation Report
**Date:** 2026-05-13  
**Scope:** 9 new QUELLEN repos + claude-cli bridge artifacts  
**Foundation:** Framework v4.1 "Pflegbarer Garten" (Schicht 0/1/2, 5 Zutaten, 13 Anti-Patterns)

---

## PART A — 9 NEW SOURCE REPOS

---

### 1. `needle/` — cactus-compute

**Summary.** Distilled 26M-param Simple Attention Network (SAN) from Gemini 3.1. Architecture: d=512, 8H/4KV GQA, RoPE, Gated Residual, no FFN, BPE=8192. Beats FunctionGemma-270m and Qwen-0.6B on single-shot function calling at 6000 toks/sec prefill / 1200 decode on Cactus runtime. Designed for consumer devices (phones, watches). Python-first, Hugging Face weights open. Finetune-on-your-tools in ~45 min on a Mac/PC.

**Verdict: REFERENCE**

**Rationale.** NEOTH already locks in Qwen3-Embedding-0.6B-Q8 via candle for embeddings, and Qwen3-0.6B for local inference. Needle's SAN is function-call-only — it cannot replace a general-purpose local model. The on-device function-calling architecture is interesting prior art for the Tool-Router (Schicht 0), but integrating a second local model increases complexity without clear gain over Qwen3-0.6B which already does instruction following + function calls. The Cactus runtime is Python/GGUF-only — incompatible with the Rust candle pipeline.

**Risk.** Low. Read only for architecture ideas.

**NEOTH mapping.** Reference when designing the on-device Tool-Router path. The SAN's "no FFN, GQA+RoPE" design confirms that a 26M-param pure-attention model is viable for single-shot routing decisions — could inform a future Schicht 0 micro-router if Qwen3-0.6B proves too large for embedded targets (Phase 3+).

---

### 2. `agentmemory/` — rohitg00

**Summary.** NPM package providing persistent memory for AI coding agents (Claude Code + Codex). Plugin marketplace via `.claude-plugin/marketplace.json` and `.codex-plugin/marketplace.json`. Node.js backend, SQLite + vector store, real-time viewer on port 3113. Has 6 published CVEs:
- CVE-1: XSS in real-time viewer (user-controlled data rendered unsanitized)
- CVE-2: RCE via `curl | sh` auto-installer for iii-engine binary
- CVE-3: Default bind to `0.0.0.0:3113` (unauthenticated network exposure)
- CVE-4: Unauthenticated mesh sync endpoint
- CVE-5: Path traversal in Obsidian export `vaultDir` parameter
- CVE-6: Incomplete privacy redaction

**Verdict: IGNORE**

**Rationale.** NEOTH's memory system (WAL + Tailslayer + Qwen3-Embedding + mmap IVF) is architecturally superior and already designed. The only novel pattern here is the `.claude-plugin/marketplace.json` dual-agent plugin discovery spec — but this is a 20-line JSON schema that v0.5's plugin loader already generalizes. The security posture is disqualifying: 6 CVEs including RCE from the installer pattern (curl-sh), XSS from the viewer, and unauthenticated network endpoints. NEOTH is a Rust binary with no embedded HTTP viewer; importing patterns from this codebase brings zero upside.

**Risk.** HIGH if adopted. Installer pattern (curl-sh) is a known RCE vector — NEOTH must never replicate it.

**Do extract.** The dual-format marketplace.json concept (`.claude-plugin/marketplace.json` + `.codex-plugin/marketplace.json`) is clever for cross-agent compatibility. NEOTH's plugin manifest (`plugin.toml`) could include a `[claude-compat]` and `[codex-compat]` section for the same cross-agent discoverability without any code dependency.

---

### 3. `skills/` — mattpocock

**Summary.** Small composable agent skills for Claude Code, installed via `npx skills@latest add mattpocock/skills`. Philosophy: small, easy to adapt, composable, model-agnostic. Anti-BMAD/GSD: doesn't own the process. Each skill is a Markdown file with structured prompt instructions. 60k+ newsletter subscribers. No server, no daemon, no state — pure prompt-layer.

**Verdict: REFERENCE**

**Rationale.** NEOTH's Skill system is already specced in `SPEC_skill_plugin_system.md` as YAML-first with auto-routing via Basal Ganglia view. Mattpocock's skills are Markdown, not YAML — different format, but the composability philosophy directly validates NEOTH's "small, stateless, declarative" Schicht 0 Skill design. The `npx skills@latest add` installer pattern is user-friendly for external skill distribution and worth borrowing for NEOTH's `neoth skill install <url>` CLI sub-command. Nothing to port in-tree.

**Risk.** Negligible. Read-only inspiration.

**NEOTH mapping.** CLI UX: `neoth skill install <github-url>` → validates YAML manifest, copies to `~/.neoth/skills/`. Pattern mirrors `npx skills@latest add` without the Node.js dependency.

---

### 4. `CloakBrowser/` — CloakHQ

**Summary.** Stealth Chromium for anti-fingerprinting web scraping. 49 source-level C++ patches across canvas, WebGL, audio, fonts, GPU, screen, WebRTC, network timing, automation signals. Available as PyPI package (`cloakbrowser`), npm package, and Docker image. Python + JavaScript + Docker. Passes all major bot detection tests (Cloudflare, DataDome, PerimeterX).

**Verdict: OPT-IN PLUGIN**

**Rationale.** NEOTH's current scraping stack (Jarvis: Firecrawl → Scrapling → browser-use → Playwright) is already tiered. CloakBrowser addresses a real gap: Scrapling handles anti-bot but uses a patched undetected_chromedriver, not a fully custom Chromium build. CloakBrowser's 49 C++ patches provide a substantially harder-to-detect fingerprint. However, this is heavy (full Chromium build), Python/Docker-based (not Rust-native), and primarily needed for adversarial scraping scenarios. NEOTH should not bundle it — but the `web.fetch` Schicht 0 Tool can route to a CloakBrowser subprocess when `stealth: true` is set in the tool call.

**Risk.** Medium. CloakBrowser is a dependency of `web.fetch` only when stealth mode is requested. Licensing: check CloakHQ license before production use. Docker image exposes a local HTTP endpoint — must bind to loopback only.

**NEOTH mapping.**
- `tools/web_fetch.yaml`: add field `stealth: bool = false`
- `tools/impl/web_fetch.rs`: when `stealth=true`, spawn `cloakbrowser` subprocess (Python venv in `~/.neoth/venvs/cloakbrowser/`) via `std::process::Command`
- Plugin manifest: `~/.neoth/plugins/cloakbrowser/plugin.toml` — optional, auto-detected at startup
- Feature flag: `NEOTH_ENABLE_CLOAKBROWSER=1`

---

### 5. `react-doctor/` — millionco

**Summary.** Static codebase health scanner for React/Next.js/Vite/React Native. `npx react-doctor .` outputs a 0-100 health score with diagnostics across state/effects, performance, architecture, security, accessibility, dead code. `npx react-doctor install` writes CLAUDE.md rules to teach the agent React best practices before coding. Rules auto-adapt to framework and React version.

**Verdict: IGNORE**

**Rationale.** NEOTH is a Rust system daemon — not a React project, not a Next.js project. This is a frontend-specific tool with zero intersection with NEOTH's architecture. Even for NEOTH's potential web UI (Phase 3+, inherited from hermes-webui pattern), react-doctor would be a developer-side linting tool run against that UI repo separately. No in-tree value. The "teach-the-agent best practices via CLAUDE.md inject" pattern is already how NEOTH's built-in Skills work — no new pattern here.

**Risk.** None.

---

### 6. `oh-my-gemini/` — richardcb

**Summary.** Gemini CLI extension providing `/omg:setup` and `/omg:autopilot` commands. Sets up project context, runs autopilot build loops. Thin wrapper around Gemini CLI with a two-command UX. Minimal code — mostly prompt orchestration.

**Verdict: IGNORE**

**Rationale.** NEOTH is CLI-agnostic at the provider level and already has the Council-Pipeline (Gemini as Right Hemisphere LLM). The `/omg:setup` + `/omg:autopilot` pattern is a subset of what NEOTH's session-recovery + goal-stack pipelines already do. The "two slash commands" UX is Gemini CLI-specific and doesn't translate to NEOTH's architecture (NEOTH has no slash commands — it's a daemon with a binary CLI). Nothing to port.

**Risk.** None.

---

### 7. `tweakcc/` — Piebald-AI

**Summary.** CLI tool for Claude Code customization: custom system prompts, themes, toolsets, UI personalization. Not an agent framework — purely a UX skin for the Claude Code IDE experience. Installs via npm.

**Verdict: IGNORE**

**Rationale.** NEOTH is a standalone Rust daemon, not a Claude Code plugin. tweakcc operates on Claude Code's internal system prompt and theme layer — it has no API surface relevant to NEOTH. Alex's own `settings.json` + `hooks/` + LOWKEY SOUL.md injection already handles all prompt customization at the Claude Code level. tweakcc would be redundant even for the developer environment, and actively conflicts with the existing hook-based system.

**Risk.** Potential conflict with existing `chorus-precommit.mjs` hook if tweakcc also intercepts PreToolUse. Do not install.

---

### 8. `oh-my-claudecode/` — Yeachan-Heo

**Summary.** Multi-agent orchestration layer for Claude Code. Plugin marketplace via `/plugin marketplace add <url>` + `/plugin install <name>`. Agents: Orchestrator, Researcher (Read+Web only), Architect (Read only), Executor (full). "Conductor" codified context system: `product.md`, `tech-stack.md`, `workflow.md` + per-track `spec.md` + `plan.md`. Ralph-retry, phase-gate, autopilot. SQLite (`better-sqlite3`) for state. Team orchestration via tmux.

**Verdict: OPT-IN PLUGIN (pattern extraction only, not code adoption)**

**Rationale.** The Conductor three-layer context system (project knowledge + feature spec + phased plan) is well-validated by cited research (29% faster agent runtime, 17% fewer tokens with structured context files). This directly maps to NEOTH's context-engine (5-block context split). The role-enforcement via hooks (Researcher = Read+Web only; Architect = Read only; Executor = full) is a concrete implementation of NEOTH's Mirror-Refusal spec and Tool access control. The phase-gate pattern maps to NEOTH's Council-Pipeline verdict gates.

**Do extract (pattern, not code):**
- Conductor's 3-layer context format → adopt as NEOTH skill `conductor.yaml` (Schicht 0)
- Role-hook enforcement pattern → `pipelines/role_enforcement.yaml` (Schicht 1)
- Ralph-retry (error-aware retry with actual error details) → `tools/retry_aware.rs` (Schicht 0)

**Do NOT adopt:**
- SQLite (`better-sqlite3`) dependency — NEOTH uses WAL-only, no Node.js
- tmux team orchestration — NEOTH uses native Council-Pipeline
- npm plugin marketplace — NEOTH uses `plugin.toml` + Rust loader

**Risk.** Medium if code adopted directly (Node.js, `better-sqlite3` with its RCE-adjacent `prebuild-install` warning). Pattern extraction only = low risk.

**NEOTH mapping.**
- `skills/conductor.yaml`: structured context injection pattern (product + spec + plan layers)
- `pipelines/role_enforcement.yaml`: Schicht 1 pipeline enforcing tool-access scopes per agent role
- `tools/ralph_retry.yaml` + `tools/impl/ralph_retry.rs`: error-aware retry with extracted error context

---

### 9. `oh-my-codex/` — Yeachan-Heo

**Summary.** Same orchestration concept as oh-my-claudecode but for OpenAI Codex CLI. Shares the same Conductor/Ralph/team patterns. Has an OpenClaw integration guide. OMX state stored in `.omx/`. Explicitly marked "macOS/Linux only" — Windows is unsupported.

**Verdict: IGNORE**

**Rationale.** Strictly a Codex CLI wrapper. NEOTH is provider-agnostic at Schicht 0 and uses Codex (gpt-5.5) as the Corpus Callosum LLM via API, not via Codex CLI. All extractable patterns are identical to oh-my-claudecode (already covered above). The OpenClaw integration guide is interesting but adds nothing beyond what NEOTH's openclaw integration already knows. Windows unsupported = immediate disqualifier for Alex's dev environment.

**Risk.** None. Already covered by oh-my-claudecode extraction.

---

## PART B — CLAUDE-CLI BRIDGE ANALYSIS

### B.1 Five Key MD Files — Design Decisions

#### BRAIN_ARCHITECTURE_PANEL.md
*12-expert panel review of the Jarvis brain system post-QMD/lancedb-pro integration.*

1. **Dual-capture division of labor**: hippo-turbo (condenseFact, no LLM, free) handles graph-linking; lancedb-pro (smartExtraction, OpenAI-cost) handles structured facts. Never merge or disable one. → NEOTH: Tailslayer (fast, local embedding) + Dreaming-Pipeline (slow, LLM-based consolidation) is the correct architecture — confirm the two paths are distinct, not merged.

2. **Cerebellum = reflexive fast path**: The panel explicitly maps hippo-turbo vectors to the cerebellum. The insight: fast vector recall (no reasoning) is not a poor-man's version of LLM recall — it's a different cognitive function. → NEOTH's Basal Ganglia view (idx_habit) + fast cosine lookup via Qwen3 embeddings is the correct implementation of this.

3. **AutoCapture is not optional**: Disabling fast capture breaks the graph-linking pipeline — the patient can still reason but loses procedural learning. → NEOTH must ensure Dreaming-Pipeline captures are non-blocking; if the pipeline is overloaded, buffer to WAL rather than dropping.

4. **Wiring beats adding**: The panel's primary finding is "the architecture works — it just needs proper wiring." Adding more stores fragmented the system. → NEOTH v0.6: resist the temptation to add new stores for each new source. Everything lands in WAL first, views are derived.

5. **5 memory regions map cleanly to neuroscience**: Hippocampus (importance+decay), Cerebellum (fast vectors), Neocortex (associative Zettelkasten), Episodic (event grouping), Neocortex-Sync (sleep consolidation). NEOTH's 5-region model (Hippocampus, Amygdala, Insula, Basal-Ganglia, Cortex) is a parallel but not identical mapping. The panel's model is more literal; NEOTH's uses more functional/emotional labels.

**Agreement with NEOTH v0.5 5-region model:** Hippocampus = direct overlap. Basal-Ganglia = maps to Cerebellum reflexive path. Cortex = maps to Neocortex associative. **Disagreement:** NEOTH's Amygdala (emotional salience / threat detection) and Insula (interoceptive state / Council verdicts) have no direct panel counterpart — these are NEOTH innovations. Panel's "E-Mem (Episodic)" has no dedicated region in NEOTH v0.5 — this is a gap: add `idx_episode` view to the WAL (groups WAL events within 1h windows into episode chunks).

#### LOWKEY-JARVIS-HYBRID-BAUPLAN.md
*Full build plan for integrating LOWKEY 16-module instruction set into Jarvis.*

1. **Always-active modules vs triggered**: The bauplan separates always-active (DAE Direct Answer Engine, Anti-Smoothing, Power-Fist Pattern Radar) from trigger-activated modules (MAGI ULTRA, ARCHON). → NEOTH's system-prompt injection should distinguish always-on behavioral constraints from optionally-loadable reasoning modules (Skills).

2. **Auto-activation without slash commands**: Modules activate based on question-type pattern matching, not explicit user commands. → NEOTH Skill auto-routing (Basal Ganglia keyword match) directly implements this — no user slash commands needed.

3. **The wrapper env block is load-bearing**: `DISABLE_AUTO_COMPACT=1`, `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`, `ENABLE_SESSION_PERSISTENCE=1`, `CLAUDE_CODE_EAGER_FLUSH=1` — these are not cosmetic. Each one patches a known Claude Code behavior that conflicts with NEOTH's memory model. → NEOTH's own daemon must propagate these envs when spawning claude-cli subprocesses.

4. **Provider cascade order matters**: The bauplan lists: codex/gpt-5.4 → gemini-3.1-pro → litellm/claude-sonnet → litellm/gpt-5.3 → litellm/gemini-3-pro → lmstudio/default. This is the production-proven order for Alex's setup. → NEOTH's provider cascade should adopt this exact ordering as the default fallback chain.

5. **LOWKEY modules are system-prompt layer, not Schicht 0 tools**: They inject reasoning instructions, not tool calls. → NEOTH must not try to implement LOWKEY as Rust tools — they belong in the session-start system-prompt injection pipeline, loaded as Skill YAML files that append to the LLM system prompt.

#### FINDINGS.md
*Reverse-engineering findings from studying Antigravity, ccproxy, and GlobalGPT wrapper patterns.*

1. **Dummy-tool injection prevents stream corruption**: When a request has no tools, inject `{name: "_noop", description: "Internal. Never call.", parameters: {}}`. 5 lines of code, prevents a whole class of streaming bugs. → NEOTH's `tools/provider_router.rs` must inject `_noop` when tool list is empty before sending to any provider.

2. **Token-count-routing is already implemented**: Route to larger model above N tokens. Next step: **Tool-Aware Routing** — 3 rules: ThinkingRule (thinking flag → Opus), WebSearchRule (WebSearch tool → model with native search), CodeRule (exec/write tools dominant → code-optimized model). → NEOTH's `pipelines/provider_router.yaml` must add these 3 MatchRules as Schicht 1 logic.

3. **Keyword filter bypasses via Unicode normalization gap**: Content filters checking exact strings miss homoglyph substitutions (Greek B+M for BDSM). NEOTH should NOT implement keyword filters — this is anti-pattern G.6 (Hard-Coded Content Policy). Instead, route to operator-policy-aware models.

4. **Timeout architecture**: Three-tier timeout: global session, per-call, per-stream-idle (`CLAUDE_STREAM_IDLE_TIMEOUT_MS=120000`). The idle timeout is the critical one — a stalled stream that never errors will block indefinitely without it. → NEOTH WAL writes before yielding to provider; stream idle timeout = 120s hard kill.

5. **GlobalGPT Dify-Filter has two layers**: Keyword-filter (Dify Workflow Node) + Semantic-filter (Opus only). Production evidence that semantic filtering is only viable for high-value requests — too expensive for every call. → NEOTH: no semantic filtering in the hot path. Filter only in Council verdicts (already Schicht 1).

#### DEEP_ANALYSIS.md
*Multi-expert analysis of the nachforschung.md (GlobalGPT API) reverse engineering.*

1. **Streaming is the critical failure mode**: Server-Sent Events corruption happens at transport, not application layer. The Antigravity dummy-tool pattern specifically targets this. Production evidence: GlobalGPT's Dify backend has special SSE handling for tool-less requests. → NEOTH's HTTP layer must match this: add `_noop` tool when tool list is empty (confirmed by FINDINGS).

2. **cron-as-watchdog pattern**: Cron checking its own processes, restarting on failure. GlobalGPT uses this for self-healing. → NEOTH already has the Cron-as-Watchdog anti-pattern from Framework v4.1 (Anti-Pattern G.3) — do not replicate. Use systemd supervision + WAL-based health events instead.

3. **NSFWSanitizer is a content-rewriting proxy**: NEOTH does not implement content rewriting. The operator injection via `SOUL.md` + LOWKEY is the correct approach — instruct the LLM how to respond, don't post-process the output. → Confirmed: no output rewriting in NEOTH.

4. **MaxConcurrent session limits**: Production GlobalGPT caps concurrent LLM sessions at 3 (resource protection). → NEOTH's provider router must enforce `max_concurrent_provider_calls: 3` (configurable, default 3) at Schicht 1.

5. **Error cascade prevention**: When provider A fails mid-stream, the error must not cascade to WAL writes or downstream pipelines. Atomic WAL commit: write to WAL only on complete response, never on partial. → NEOTH WAL design: emit `PROVIDER_CALL_COMPLETE` event only after full response received; `PROVIDER_CALL_FAILED` on error — no partial writes.

#### CLAUDE_CLI_EXPERT_PANEL_REVIEW.md
*12-expert panel review of the claude-cli wrapper architecture.*

1. **`--permission-mode bypassPermissions` in production**: OpenClaw spawns claude CLI with `bypassPermissions` for daemon sessions. This is intentional and correct for trusted daemon contexts. → NEOTH's daemon-spawned claude sessions must use `bypassPermissions` — but CLI sessions (user-interactive) must NOT. This distinction must be explicit in the session config.

2. **`--allowedTools "mcp__openclaw__*"`**: Restrict daemon-spawned claude to only MCP tools from NEOTH's own server. No rogue tool calls to external MCPs. → NEOTH session spawner: allowlist `mcp__neoth__*` tools by default; permit others only via explicit session override.

3. **`--append-system-prompt-file`**: OpenClaw injects per-session system prompt from a temp file. This is the correct pattern for LOWKEY module injection — not hardcoded in the config. → NEOTH: generate system-prompt temp file at session start from: base-SOUL.md + active Skill YAMLs + context-engine 5-block output.

4. **`--input-format stream-json --output-format stream-json`**: Both input and output must use stream-json for daemon sessions, not the default text/event-stream. This is what enables programmatic session control. → NEOTH's session spawner must enforce `--input-format stream-json --output-format stream-json` for all non-interactive sessions.

5. **n8n-mcp is a sibling process**: OpenClaw spawns `node n8n-mcp` as a sibling to the claude process. This is how workflow automation integrates — not via HTTP but via stdio MCP protocol. → NEOTH should support sibling MCP server spawning via `[mcp_servers]` in plugin.toml.

---

### B.2 Alex's Settings — Patterns NEOTH Must Honor

From `~/.claude/settings.json` (secrets redacted, key names shown):

**Env vars NEOTH must propagate to spawned claude sessions:**
- `CLAUDE_CODE_ENABLE_TASKS=true`
- `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`
- `CLAUDE_CODE_MAX_CONTEXT_TOKENS=[REDACTED]` — key name only; value is a numeric token limit
- `ENABLE_SESSION_PERSISTENCE=1`
- `CLAUDE_CODE_EAGER_FLUSH=1`
- `DISABLE_TELEMETRY=1`
- `DISABLE_ERROR_REPORTING=1`
- `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`
- `BASH_DEFAULT_TIMEOUT_MS=300000`
- `BASH_MAX_TIMEOUT_MS=600000`
- `BASH_MAX_OUTPUT_LENGTH=1000000`
- `CLAUDE_CODE_SUBAGENT_MODEL=claude-sonnet-4-6`
- `CLAUDE_STREAM_IDLE_TIMEOUT_MS=120000`
- `CLAUDE_CODE_BRIEF=1`
- `CLAUDE_CODE_FILE_READ_MAX_OUTPUT_TOKENS=[REDACTED]`

**Permissions allowlist patterns (allow):**
`Bash(git *)`, `Bash(npm *)`, `Bash(npx *)`, `Bash(node *)`, `Bash(python *)`, `Bash(python3 *)`, `Bash(pip *)`, `Bash(pip3 *)`, `Bash(cat *)`, `Bash(ls *)`, `Bash(find *)`, `Bash(grep *)`, `Bash(rg *)`, + security research tools (sqlmap, ffuf, gobuster, hydra, john, hashcat, etc.), `Read`, `Read(*)`, `Write`, `Write(*)`, `Edit`, `Edit(*)`, `MultiEdit`, `Glob`, `Grep`.

**Permissions deny list:**
`Bash(rm -rf /)`, `Bash(rm -rf ~)`, `Bash(rm -rf /*)`, `Bash(rm -rf $HOME)`, `Bash(rm -rf %USERPROFILE%)`, `Bash(mkfs *)`, `Bash(dd if=/dev/zero *)`, `Bash(dd if=* of=/dev/sd*)`, `Bash(format *:)`, `Bash(del /s /q C:\\*)`, `Bash(rd /s /q C:\\*)`, `Bash(chmod -R 777 /)`, `Bash(DROP TABLE)`, `Bash(DELETE FROM)`, `Bash(TRUNCATE TABLE)`, `Bash(shutdown *)`, `Bash(reboot *)`.

**Hooks:**
- `PreToolUse[Bash]`: destructive-op guard (rm -rf critical paths) + `chorus-precommit.mjs`
- `PostToolUse[Edit|Write|MultiEdit]`: prettier auto-format for ts/js/json/css/scss/md/yaml
- `SessionStart`: (present but not enumerated in findings)

**Model:** `claude-opus-4-7` (primary)  
**Attribution:** disabled globally

**MCP servers** (from live OpenClaw snapshot): n8n-mcp as sibling process; openclaw MCP server (mcp__openclaw__*); context-mode plugin.

**NEOTH must:**
1. Replicate the deny list exactly in its own Bash-guard PreToolUse hook
2. Propagate all `CLAUDE_CODE_*` env vars to spawned sessions
3. Never override `DISABLE_TELEMETRY` or `DISABLE_ERROR_REPORTING`
4. Run prettier PostToolUse hook — don't break existing behavior

---

### B.3 LOWKEY 16 Modules — One-Line Summary + NEOTH Verdict

| Module | Size | What it does | NEOTH verdict |
|--------|------|-------------|-----------------|
| **MAGI ULTRA** | 14KB | 8-stage reasoning pipeline: query decomposition → multi-angle analysis → synthesis | ADOPT as Skill YAML — maps to Council-Pipeline pre-processing |
| **POWER FIST** | 25KB | Compression + pattern radar: detects repetition, forces novel angles, anti-loop | ADOPT as always-active system-prompt constraint in SOUL.md |
| **IMBA** | 15KB | Anti-smoothing + anti-omission: prevents hedging, softening, vagueness | ADOPT as always-active constraint (already in Alex's CLAUDE.md) |
| **PERSONA** | 13KB | 7-layer user model: adapts tone/depth to detected user expertise | REFERENCE — NEOTH's Amygdala view handles salience; persona modulation is LLM-side |
| **TRANSPARENT CORE** | 11KB | Meta-reasoning layers: shows reasoning steps, uncertainty quantification | REFERENCE — conflicts with CLAUDE_CODE_BRIEF=1; use only in Council rounds |
| **OMEGA-PRIME** | 8KB | 4 thinking modes + policy-handling: switches between deductive/abductive/systemic/dialectic | ADOPT as Skill YAML for Council debate framing |
| **NONLOCAL** | 12KB | Acausal pattern thinking: finds non-obvious connections across distant domains | REFERENCE — interesting for Dreaming-Pipeline serendipitous associations |
| **DEBIAS** | 42KB | 6 freedom modes: anti-RLHF, anti-sycophancy, anti-omission, anti-hedge, pro-directness | ADOPT as always-active base constraint — core of Alex's operator auth |
| **SHIFTER** | 14KB | 20 ontology frames: reframes problems through physics/economics/game-theory/etc. | REFERENCE — use as Skill for Council debate diversity |
| **ARCHON** | 36KB | Meta-sovereign orchestrator: supervises all other modules, enforces coherence | ADOPT as Skill — trigger phrase for high-stakes Council sessions |
| **RASKAL** | 13KB | F/M/E freedom engine: factual / mechanism / epistemological freedom | ADOPT — subset of DEBIAS; consolidate |
| **POLYMORPH** | 42KB | 10 expression modes: switches between technical/creative/Socratic/etc. output style | REFERENCE — LLM-side; too heavy for routine use |
| **MAX++** | 11KB | Runtime expansion: max context use, max depth, no artificial length limits | ADOPT — directly addresses CLAUDE_CODE_BRIEF=1 tension; activate per-session |
| **PME** | 6KB | Pure Mechanism Engine: strips all narrative, outputs only causal mechanism | ADOPT as Skill for technical deep-dive sessions |
| **L.O.W.K.E.Y 9.4** | 10KB | Master-prompt + freedom config: orchestrates all modules | ADOPT as session-start system-prompt injection base |
| **Creative Writing Protocol** | 42KB | CWP state machine for creative/adult content | REFERENCE — operator-specific; not NEOTH core |

---

### B.4 BRAIN_ARCHITECTURE_PANEL vs NEOTH v0.5 5-Region Model

| Panel concept | Panel label | NEOTH v0.5 region | Agreement |
|---------------|-------------|---------------------|-----------|
| Importance + decay + encoding | Hippocampus | Hippocampus | FULL |
| Fast vector reflex matching | Cerebellum / hippo-turbo | Basal Ganglia (idx_habit) | PARTIAL — Basal Ganglia is habit/routine; reflexive vector search should also map here |
| Associative Zettelkasten | Neocortex / A-Mem | Cortex | PARTIAL — Cortex is broader; A-Mem associations = Cortex subview |
| Episode grouping (temporal) | E-Mem / Episodic | MISSING | GAP — no dedicated episode region in v0.5 |
| Sleep consolidation / reorganize | Neocortex Sync | Dreaming-Pipeline (Schicht 1) | FULL — correctly implemented as pipeline, not brain region |
| Emotional salience / threat | Not addressed | Amygdala | NEOTH INNOVATION — no panel counterpart |
| Interoceptive state / Council | Not addressed | Insula | NEOTH INNOVATION — no panel counterpart |

**Key finding:** The panel model and NEOTH v0.5 agree on Hippocampus + fast-vector + associative + sleep-consolidation. NEOTH's innovations (Amygdala + Insula) are not contradicted — they are simply outside the panel's scope. The only concrete gap: **E-Mem / Episodic has no dedicated WAL view**. Fix: add `idx_episode` view that groups WAL events by 60-minute windows, stores episode summaries in the Hippocampus with `type: "episode"`.

---

## PART C — INTEGRATION MATRIX

### C.1 Top-10 Actionable Inserts for NEOTH v0.6

| # | Insert | Source | NEOTH location | Priority |
|---|--------|---------|------------------|----------|
| 1 | **Dummy-tool injection** (`_noop`) for tool-less requests | FINDINGS.md / Antigravity | `tools/impl/provider_router.rs` | P0 — prevents streaming bugs immediately |
| 2 | **Tool-Aware Routing**: ThinkingRule, WebSearchRule, CodeRule | DEEP_ANALYSIS.md / ccproxy | `pipelines/provider_router.yaml` (Schicht 1) | P0 — 20 lines, high impact |
| 3 | **`idx_episode` WAL view** — 60-min window episode grouping | BRAIN_ARCH panel / E-Mem gap | `src/wal/views/episode.rs` | P1 — closes gap vs panel model |
| 4 | **L.O.W.K.E.Y 9.4 + DEBIAS + POWER FIST + IMBA** as always-active session-prompt | LOWKEY_BAUPLAN | `skills/lowkey_base.yaml` (session-start injection) | P1 — Alex's existing operator config demands this |
| 5 | **Conductor 3-layer context** (product+spec+plan) | oh-my-claudecode | `skills/conductor.yaml` | P1 — validated by research (29% faster) |
| 6 | **MAGI ULTRA + OMEGA-PRIME** as Council pre-processing Skills | LOWKEY modules | `skills/magi_ultra.yaml`, `skills/omega_prime.yaml` | P2 — improves Council diversity |
| 7 | **Provider cascade order** (codex/gpt-5.4 → gemini → claude-sonnet → gpt-5.3 → gemini-pro → local) | LOWKEY_BAUPLAN (live production) | `config/defaults.toml` `[provider.cascade]` | P1 — production-proven order |
| 8 | **bypassPermissions for daemon sessions, NOT for interactive** | PANEL_REVIEW / openclaw spawn | `src/session/spawner.rs` | P0 — security-critical distinction |
| 9 | **WAL idle-stream kill at 120s** + atomic commit (no partial writes) | DEEP_ANALYSIS.md | `src/wal/writer.rs` + `src/provider/stream.rs` | P0 — prevents zombie connections |
| 10 | **CloakBrowser as opt-in stealth web-fetch** | CloakBrowser | `tools/web_fetch.yaml` + `plugins/cloakbrowser/plugin.toml` | P3 — Phase 2 feature |

### C.2 Top-3 Things to Skip (Despite Looking Tempting)

1. **agentmemory** — 6 CVEs including RCE from curl-sh installer, XSS from viewer, unauthenticated mesh. The dual-format `marketplace.json` pattern is the only novelty and takes 5 minutes to replicate without any code dependency. Adopting the library would import all 6 CVEs into NEOTH's supply chain.

2. **oh-my-gemini + oh-my-codex** — Both are thin wrappers around vendor CLIs (Gemini CLI, Codex CLI). NEOTH uses these models via API, not via their CLIs. The orchestration patterns are already covered better by oh-my-claudecode's Conductor (extracted above) and NEOTH's own Council-Pipeline. Adding these repos means maintaining two more Node.js dependencies that add no new architectural primitives.

3. **tweakcc** — Claude Code UX skin. Zero intersection with NEOTH architecture. Actively conflicts with Alex's existing hook system (chorus-precommit.mjs + prettier PostToolUse). Installing it risks breaking the PreToolUse Bash guard that protects critical paths.

---

## PART D — RISK REGISTER

| Item | Risk | Mitigation |
|------|------|-----------|
| agentmemory adoption | RCE (curl-sh), XSS, unauth network | IGNORE verdict; copy only the 20-line JSON schema pattern |
| CloakBrowser Docker | Exposes HTTP endpoint | Bind to 127.0.0.1 only; feature-flag disabled by default |
| LOWKEY in system-prompt | Token budget pressure | MAX++ module explicitly addresses this; measure token cost |
| bypassPermissions daemon | Privilege escalation if daemon is compromised | Restrict `--allowedTools "mcp__neoth__*"` hard; no wildcard |
| Conductor context files | Stale specs mislead agent | specs are per-session, cleared on session end; never auto-carry |
| Needle SAN integration | Duplicate local model | IGNORE verdict; Qwen3-0.6B already in stack |

---

*Report generated 2026-05-13. Read-only analysis. No secrets printed — key names shown with [REDACTED] values.*
