# QUELLEN Adoption Verdict: cc-switch → NEOTH

**Date:** 2026-05-21  
**Analyst:** Claude Code (Sonnet 4.6)  
**Source:** `QUELLEN/cc-switch/` v3.15.0 (MIT, Jason Young)  
**Target:** `SRC/neothd/` + `SRC/neothd-gui/`

---

## §1 What cc-switch is

CC Switch is a cross-platform desktop app (Tauri 2 + React/TypeScript frontend, Rust backend, SQLite storage) that serves as a unified GUI manager for five AI coding CLIs: Claude Code, Codex, Gemini CLI, OpenCode, and OpenClaw. Its core value proposition is eliminating manual config-file editing when switching API providers — it writes `settings.json` / `.env` / TOML files on behalf of the user. Version 3.15 adds a local HTTP proxy with circuit-breaker failover, per-app provider isolation, usage/cost tracking pulled from a proxy-intercepted request log, skills installer (GitHub ZIP/symlink), unified MCP server management, WebDAV cloud sync, and a deep-link import protocol (`ccswitch://`). The backend is a Tauri 2 Rust binary; real proxy and file I/O logic lives in `src-tauri/src/`.

---

## §2 Domain inventory

### Core data model (TypeScript types, mirrored in Rust DAOs)

| Type | Key fields | Storage |
|------|-----------|---------|
| `Provider` | `id, name, settingsConfig: Record<string,any>, category, inFailoverQueue, icon, meta` | SQLite `providers` table |
| `AppConfig` | `providers: Record<id, Provider>, current: string` | per-app JSON on disk, written atomically |
| `UniversalProvider` | cross-app config with per-app model slots (`claude/codex/gemini`) | SQLite `universal_providers` |
| `RequestLog` | `requestId, providerId, model, input/outputTokens, cost, latencyMs, statusCode` | SQLite WAL-appended |
| `UsageSummary` | aggregated costs, cache hit rate, success rate | computed view |
| `SettingsFormData` | tray, autolaunch, configDirs per app, skillSyncMethod, webdavSync | SQLite `settings` |
| `UsageScript` | JS code run in-process to scrape quota from provider APIs | per-provider blob |

### Key source files

- `src-tauri/src/proxy/` — `provider_router.rs` (circuit-breaker failover), `failover_switch.rs` (dedup, tray update)
- `src-tauri/src/database/dao/` — providers, failover, proxy, mcp, skills, usage_rollup, universal_providers
- `src-tauri/src/commands/` — ~24 Tauri command modules (proxy, failover, skill, mcp, usage, settings, session_manager, webdav_sync, deeplink…)
- `src/components/providers/` — ProviderCard, ProviderList, HealthStatusIndicator, FailoverPriorityBadge, forms
- `src/components/settings/` — 10 settings panels (GlobalProxy, Directory, Theme, Terminal, SkillSync…)
- `src/components/mcp/` — UnifiedMcpPanel, McpWizardModal, McpFormModal
- `src/lib/schemas/` — Zod provider + settings schemas

---

## §3 Feature-by-feature adoption verdict

| cc-switch Feature | NEOTH Status | Verdict | Notes |
|---|---|---|---|
| Provider list management (CRUD, drag-sort, preset import) | Providers exist as `Provider` trait impls; no GUI management panel | **ADOPT-AS-GUI** | Port to `SRC/neothd-gui/ui/providers.slint` + Rust IPC commands |
| 50+ provider presets (base URLs, model IDs, icons) | `known_endpoints.rs` has some; no full preset catalog | **ADOPT-AS-CORE** | Port `universalProviderPresets.ts` + `providers_seed.rs` to `SRC/neothd/src/providers/presets.rs` |
| One-click provider switching + live config write | Only wizard sets provider; no runtime switch | **ADOPT-AS-CORE** | Add `neoth provider switch <id>` CLI + freedom.yaml hot-reload |
| Local HTTP proxy with format conversion | Not in NEOTH | **ADOPT-AS-CORE** | Port `src-tauri/src/proxy/` → `SRC/neothd/src/proxy/`; this is the highest-value standalone Rust module |
| Circuit-breaker failover (provider_router.rs) | Not in NEOTH | **ADOPT-AS-CORE** | Direct Rust port; cc-switch circuit_breaker.rs is clean, no Tauri coupling |
| Provider health monitoring + health badge | Not in NEOTH | **ADOPT-AS-GUI** | `HealthStatusIndicator.tsx` → Slint `ProviderHealthBadge` component |
| Usage/cost dashboard (token, latency, cache rate) | `meter.rs` + `cost.rs` exist; no GUI dashboard | **ADOPT-AS-GUI** | Port `UsageSummary` schema → SQLite view; port dashboard panel to Slint |
| Per-request log (RequestLog schema) | WAL events capture raw data; no cost-per-request table | **ADOPT-AS-CORE** | Add `request_log` SQLite table to `SRC/neothd/src/db/` mirroring `RequestLog` type |
| System tray quick-switch | Not in NEOTH GUI | **ADOPT-AS-GUI** | Low-priority; needs Slint tray support or tray-icon crate |
| Skills installer (GitHub ZIP / symlink) | Plugin SDK + WASM host exists; no skills installer | **ADOPT-AS-CORE** | Port `commands/skill.rs` + `dao/skills.rs` → `SRC/neothd/src/skills/` |
| Unified MCP panel + bidirectional sync | Plugin/WASM host is different from MCP | **ADOPT-AS-CORE** | Port `claude_mcp.rs` + `commands/mcp.rs`; NEOTH needs MCP client side anyway |
| Prompts editor (CLAUDE.md / AGENTS.md cross-sync) | NEOTH has memory tiers; no prompt file editor | **ADOPT-AS-GUI** | Port `MarkdownEditor.tsx` concept to `SRC/neothd-gui/ui/prompts.slint` |
| Session manager (browse/restore conversation history) | NEOTH has 3-tier memory + session archive | **SKIP-DUPLICATE** | NEOTH `recall` already searches hot+warm+cold; cc-switch session manager re-solves this differently |
| Workspace editor (AGENTS.md etc.) | Covered by NEOTH memory hierarchy + NEOTH.md | **SKIP-DUPLICATE** | NEOTH's NEOTH.md layer is the equivalent |
| WebDAV cloud sync | NEOTH has OpenDAL cloud-connector matrix (R-8) | **SKIP-OUT-OF-SCOPE** | OpenDAL covers this and more; don't add WebDAV-only dependency |
| Deep link import (`ccswitch://`) | Not in NEOTH | **SKIP-OUT-OF-SCOPE** | NEOTH is self-contained; deep links require a URI scheme registration per-OS, not worth it for v1 |
| i18n (zh/en/ja) | Not in NEOTH | **SKIP-OUT-OF-SCOPE** | NEOTH targets solo English-primary operator today; file under backlog |
| First-run onboarding dialog | NEOTH wizard (`cli/init.rs`) already ships | **SKIP-DUPLICATE** | `SRC/neothd/src/cli/init.rs` covers this |
| Auto-updater | NEOTH has auto-update spec (arch extensions) | **SKIP-DUPLICATE** | cargo-dist + GitHub Releases is the plan; not cc-switch's updater model |
| Codex / Gemini CLI config write-through | Out of NEOTH's scope | **SKIP-OUT-OF-SCOPE** | NEOTH manages its own providers, not external CLI config files |
| Signature bypass utilities | SKIP | **SKIP-OUT-OF-SCOPE** | Offensive tooling, no place in NEOTH core |
| Role-based model mapping (sonnet/opus/haiku) | Partially in `ProviderKind` enum | **ADOPT-AS-CORE** | Promote `UniversalProviderModels` pattern → `SRC/neothd/src/providers/model_roles.rs` |
| Color / icon picker for providers | Not in NEOTH | **ADOPT-AS-GUI** | Port `ColorPicker.tsx` + `IconPicker.tsx` concept to Slint provider form |
| ProviderCard visual + FailoverPriorityBadge | Not in Slint GUI | **ADOPT-AS-GUI** | Design reference for `SRC/neothd-gui/ui/providers.slint` |

---

## §4 Top 5 things NEOTH should steal (prioritised)

### 1. Local proxy with circuit-breaker failover
**Why:** cc-switch's `src-tauri/src/proxy/` (provider_router + circuit_breaker + failover_switch) is a complete, production-tested Rust implementation. NEOTH's hemisphere routing already dispatches to providers but has no failover. Porting this closes the highest operator pain point (provider downtime) and enables the LOWKEY autonomy preset to silently recover.  
**Port to:** `SRC/neothd/src/proxy/` (new module) — `provider_router.rs`, `circuit_breaker.rs`, `failover_switch.rs`. Remove Tauri/AppHandle coupling; replace with WAL event emission at 0xE0-0xE5 cluster band.  
**LOC estimate:** ~600 LOC (circuit_breaker ~200, router ~250, failover_switch ~150).

### 2. Provider preset catalog + GUI management panel
**Why:** NEOTH currently switches providers by editing `freedom.yaml` manually. cc-switch's 50-preset seed (`providers_seed.rs` + `universalProviderPresets.ts`) and CRUD panel (`ProviderCard`, `AddProviderDialog`, `ProviderList`) are exactly what `PLAN/SPEC_gui_settings.md` specifies as mandatory. The preset catalog also covers AWS Bedrock, NVIDIA NIM, and the relay providers NEOTH users will actually want.  
**Port to:** `SRC/neothd/src/providers/presets.rs` (preset catalog) + `SRC/neothd-gui/ui/providers.slint` (panel).  
**LOC estimate:** ~400 LOC core + ~350 LOC Slint panel.

### 3. Request-log SQLite schema + usage dashboard
**Why:** `RequestLog` / `UsageSummary` / `ModelPricing` from `src/types/usage.ts` and `database/dao/usage_rollup.rs` map cleanly onto NEOTH's existing `meter.rs` + `cost.rs`. The missing piece is a persistent `request_log` table and a GUI panel. Without it NEOTH operators have no cost visibility — a hard blocker for the "noob wizard" requirement.  
**Port to:** `SRC/neothd/src/db/usage.rs` (schema migration + DAO) + `SRC/neothd-gui/ui/usage.slint`.  
**LOC estimate:** ~350 LOC Rust + ~300 LOC Slint.

### 4. Skills installer (GitHub ZIP / symlink)
**Why:** NEOTH has a plugin SDK and WASM host but no way to install skills from GitHub. cc-switch's `commands/skill.rs` + `dao/skills.rs` handles GitHub repo discovery, ZIP download, and symlink/copy placement. This directly enables NEOTH's skill marketplace without writing from scratch.  
**Port to:** `SRC/neothd/src/skills/` (new module) under existing WASM host; adapt install paths to `~/.neoth/skills/`.  
**LOC estimate:** ~300 LOC.

### 5. Role-based model mapping (`UniversalProviderModels` pattern)
**Why:** cc-switch's role→model-ID indirection (sonnet/opus/haiku slots per provider) avoids hardcoding model strings per provider and enables smooth model upgrades. NEOTH's hemisphere Left/Right/Cerebellum currently reads `model` as a plain string from `freedom.yaml`. Promoting the role pattern here decouples the UI from raw model IDs and enables per-hemisphere model selection (SPEC item SP-5d).  
**Port to:** `SRC/neothd/src/providers/model_roles.rs` + `SRC/neothd/src/config/mod.rs` (extend `FreedomConfig::inference`).  
**LOC estimate:** ~150 LOC.

---

## §5 Things to explicitly NOT copy

| Item | Reason |
|------|--------|
| **Tauri AppHandle coupling in proxy/failover** | cc-switch's proxy emits tray/window events via `tauri::Emitter`. NEOTH uses Slint + IPC; remove this coupling entirely and replace with WAL events + IPC push. Copying the Tauri coupling would pull in Tauri as a dep. |
| **Multi-CLI config write-through** (claude/codex/gemini config file editing) | NEOTH manages its own providers in `freedom.yaml`; it does not manage external CLI tools' configs. cc-switch's entire `AppConfig.settingsConfig: Record<string,any>` approach (write arbitrary JSON to other apps' config files) is antithetical to NEOTH's self-contained model. |
| **WebDAV sync** | NEOTH's cloud-connector matrix (R-8) uses OpenDAL which covers S3/Dropbox/OneDrive/GDrive/WebDAV uniformly. Porting cc-switch's dedicated WebDAV module would be redundant and narrower. |
| **UsageScript (JS eval for quota scraping)** | Running arbitrary JavaScript in-process to scrape provider quota pages is a security surface NEOTH doesn't need. NEOTH's quota module already handles structured API responses. |
| **i18n + locale files** | zh/ja translations add ongoing maintenance burden with zero operator benefit today. Defer until NEOTH targets public non-English users. |
| **Deep link URI scheme** | Requires per-OS registration (Windows registry, macOS `Info.plist`, `.desktop` entry). Not self-contained. Adds attack surface. Operator imports providers via `neoth provider add` CLI. |
| **Signature bypass / plugin integration hacks** | `enableClaudePluginIntegration`, `skipClaudeOnboarding` settings patch Claude Desktop's signed bundle. Not relevant to NEOTH's architecture. |
| **Chinese-only comments in Rust code** | cc-switch's backend is heavily commented in Simplified Chinese. Port logic only; rewrite comments in English per NEOTH coding standards. |
| **React/TypeScript frontend** | NEOTH GUI is Slint. Do not introduce a second frontend stack. All GUI concepts must be ported to `.slint` files, not transplanted as React components. |
| **Tauri 2 as GUI runtime** | NEOTH deliberately chose Slint for a smaller binary and no webview dependency. cc-switch's entire Tauri layer (IPC bridge, capability system, tray integration) must be re-implemented natively in Slint + NEOTH's existing IPC. Adopting Tauri would violate the self-contained binary hard rule. |
