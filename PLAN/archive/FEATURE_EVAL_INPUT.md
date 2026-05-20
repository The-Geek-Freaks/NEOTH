# NEOTH feature evaluation — input for parallel agent review

This file lists the candidate features Alex collected from the OpenClaw / OpenHuman / Hermes ecosystems plus power-user wishlist items. Each agent reads this + the NEOTH source at `C:\Users\Shadow-PC\CascadeProjects\AGENTER\SRC\` and produces a scorecard. Design specs live at `C:\Users\Shadow-PC\CascadeProjects\NEOTH\docs\superpowers\specs` (junction).

NEOTH's current shipped surface (from `PLAN/PROGRESS.md`):
- WAL persistent memory (4 tiers: hot 7d / warm 90d / long-term Hebbian / ground-truth)
- `idx_embedding` vector store + cross-modal recall (image + text via CLIP)
- Multimodal pipeline (PDF / image / audio / video) via candle 0.8 + symphonia + ffmpeg
- 8 LLM providers (claude_cli, openai_api, openai_compat, gemini_api, local_qwen, hermes, openclaw, anthropic via OAuth)
- Channels: Telegram (live, with photo/voice/audio ingest); WhatsApp + Slack + Keet (scaffolds, Phase 2 transport deferred)
- Slint GUI wizard (welcome / license / identity / provider / autonomy / channels / keys / done) + hardware autodetect
- Autonomy levels (strict/standard/elevated/full/custom) + PermissionToken gates
- TOML hooks engine (8 stages, allow/replace/block)
- Sub-agents: code-reviewer / security-reviewer / planner + `/agent` dispatch
- Slash commands: `/help`, `/recall`, `/status`, `/jobs`, `/agent`
- ADR auto-extraction from conversation
- HMAC-signed WAL compaction
- Backup/restore/export (GDPR)
- Obsidian vault auto-sync timer
- R-3 Hysteria encrypted egress (subprocess + NEOTH_HTTP_PROXY auto-set)
- R-8 Cloud archive folder-mirror (Dropbox/GDrive/OneDrive via desktop client)
- Hardware probe v2 (CPU/RAM/CUDA/Metal/OpenVINO/disk/cached-models)
- `neoth models pull` for CLIP + whisper cache management
- `neoth ingest` multimodal CLI
- `neoth cluster status|plan` (LocalOnly + LeastLoaded policies, real Hyperswarm transport deferred)
- 711 unit + 8 GUI + 3 plugin-sdk + 1 integration tests, fmt + clippy `-D warnings` clean

---

## Block A — 50 mainstream features

### Productivity & Knowledge (1-10)
1. Notion (Pages, DBs, Search)
2. Google Workspace (Gmail/Calendar/Drive/Docs/Sheets) — `gogcli` is the heavy-hitter
3. GitHub PR workflow (branch → commit → PR → review → merge)
4. GitHub Issues (create/triage/label/assign)
5. Linear (Issues, Projects, Teams via GraphQL)
6. Jira (Composio plugin)
7. Slack (messages, channels, workspace integration)
8. Obsidian Vault (read/write notes, backlinks) — NEOTH has sync, NOT plugin curation
9. Calendar Management (events create/move/find)
10. Cold Email / Outreach sequences

### Communication & Channels (11-17)
11. Telegram Bot — **NEOTH has it, with media**
12. Discord Bot (slash commands, threads)
13. WhatsApp Business — **NEOTH has scaffold**
14. Signal
15. Email (SMTP/IMAP)
16. Microsoft Teams (plugin in Hermes)
17. Feishu/Lark / WeCom / DingTalk (asian channels)

### Browser & Web Automation (18-24)
18. Playwright MCP — real browser steering, backbone of serious web automation
19. Playwright Scraper (structured extraction)
20. Web Search (Brave/Google/Tavily provider)
21. Web Fetch / Scraper (HTML → Markdown, token-efficient)
22. OpenStreetMap / OSRM (geocode, POIs, routes)
23. Tenor GIF Search
24. ArXiv (paper search + retrieval) — Alex specifically asks if this should land

### Coding & Dev (25-32)
25. Claude Code Delegation (features, PRs, refactors)
26. OpenAI Codex Delegation
27. OpenCode CLI Delegation
28. Git Operations (clone, branch, rebase, remotes)
29. GitHub Code Review (inline PR comments)
30. Python/Node runtime skills (fs, lint, test, grep)
31. MCP Server Integration (generic, central in all three frameworks)
32. AWS / Azure DevOps / CI-CD pipeline controller

### Memory & Knowledge (33-37)
33. Memory backend — NEOTH has 4-tier WAL + idx_embedding **(strongest in class)**
34. memU (hierarchical knowledge graph)
35. Skill Workshop / Skill Factory (auto-create new skills from workflows)
36. Self-improving agent / Curator (rate + consolidate skills)
37. Long-term conversation search (FTS5 / vector recall) — **NEOTH has both**

### Content Creation (38-43)
38. Blog writer / content creator (SEO, long-form, brand voice)
39. SEO audit
40. Markdown converter (anything → MD)
41. PowerPoint / Slide generation
42. Excalidraw diagrams (hand-drawn JSON: arch/flow/seq)
43. Drawio / dark-themed architecture diagrams

### Voice, Media, Vision (44-47)
44. STT (speech-to-text input) — **NEOTH has whisper-large-v3-turbo**
45. TTS (ElevenLabs / native for replies)
46. Voice Call (Twilio outbound, multi-step calls)
47. Image Generation (ComfyUI, FLUX skills)

### Security & Ops (48-50)
48. SecureClaw / OWASP-LLM hardening (real-time auditing, prompt-injection prevention)
49. Workflow Engine (Lobster pipelines, Kanban orchestration, typed + approval-gates)
50. Composio Universal Connector (200-850+ SaaS tools, one plugin)

---

## Block B — Power-user heavy hitters (Round 2)

- `gogcli` ("gog") — Google Workspace via single binary (35k+ installs)
- Apple Ecosystem Skills (Mail, Calendar, Reminders, Notes, Shortcuts) — native macOS, no API keys
- Browser landscape granular:
  - Built-in `web_fetch` — breaks on JS-heavy pages
  - Playwright MCP / browser-automation v2 — auto tab cleanup, retry, smart waiting
  - **CloakBrowser** — stealth Chromium with C++ source-level patches, passes 30/30 bot-detection tests, drop-in for Playwright/Puppeteer, bypasses Cloudflare Turnstile / DataDome / Akamai
  - camoufox (Firefox variant), nodriver
  - Browser Relay — Chrome extension hooking a real login tab to the gateway
- `macos-computer-use` — background desktop steering without stealing cursor (Hermes)
- Firecrawl — clean Markdown from JS-heavy pages
- Mcporter — agent-driven MCP server discovery + OAuth flows from chat
- GStack / gstack-lite — Garry Tan's "AI Engineering Team" skill pack
- Capability Evolver — most-clicked self-improvement skill
- Skill-Vetter / ClawDex / clawdstrike — pre-install security scanners (after 341 malware skills March 2026)
- 1Password / Dashlane / credential-manager
- N8N-Bridge — natural language interface for n8n workflows
- Mobile Nodes (iOS/Android) — camera, canvas, device actions to gateway
- BlueBubbles — iMessage/SMS on macOS
- Honcho — dialectic user modeling (Hermes)
- Atropos — RL trajectory export from Hermes
- `/rollback` — snapshot-based working-dir restore before file ops (Hermes-exclusive)
- Terminal backends — local, Docker, SSH, Singularity, Modal, Daytona, Vercel Sandbox (Daytona + Modal hibernate cheaply)
- Cron + Subagents — Hermes' killer feature for background loops
- Moltbook / Molthub — OpenClaw social network (demo)
- ArXiv learner from Alex's Jarvis stack

---

## Block C — "Niemand baut, alle wollen" (18 items)

1. **Agent der widerspricht** — no "Sie haben recht", real pushback. Sycophancy is reddit #1 complaint.
2. **Agent mit eigenen Zielen** — autonomous self-improvement, research what you'll need tomorrow
3. **Group Mode / Family Agent** — shared knowledge graph for household
4. **Skin in the Game** — economic stakes when agent screws up
5. **Verifiable truth about behaviour** — TEE attestation, cryptographic proof
6. **Death of the Prompt** — calendar shows meeting → agent already has agenda + notes ready
7. **The "Her" layer** — warmth, humor, personality that ages with you
8. **Real federation** — agent learns from successes of other agents (anonymized, opt-in)
9. **Live steering** — interrupt agent mid-execution, correct, resume — no state loss
10. **Persistent identity across providers** — switch Claude → GPT → local Qwen without persona drift
11. **Adversarial multi-agent** — one agent argues AGAINST another's interest
12. **Embodiment beyond mascot** — context-reading smart home, Apple Watch as sensor layer
13. **Capability decay tracking** — skill health auto-monitoring as APIs drift
14. **Cost transparency ex ante** — "this needs 3 LLM calls ~$0.07, proceed?" BEFORE running
15. **Real forgetting** — DSGVO-compliant retroactive memory wipe across embeddings + summaries
16. **Inner-monologue audit** — true reasoning chain, not post-hoc rationalisation
17. **Sub-200ms voice latency** — real conversation with interruption handling
18. **Quality signal that isn't stars** — anonymous agent reviews from real runs

---

## Block D — Design constraints from Alex

- All UI surfaces must align with `docs/superpowers/specs` design definition
- Need clients for: macOS, Windows, Linux, Android, iOS — chat client via Hysteria/Tailscale
- Roadmap for each client platform
- Onboarding choice: CLI-only OR GUI (changeable later)
- Obsidian: are we using it perfectly? Which plugins should ship pre-configured?
- Everything must fit NEOTH's framework (memory tiers, autonomy gates, WAL events, hooks)
- Must not break or nerf existing functionality
- Must be consistent / non-contradictory in NEOTH's logic
