# DES-09 — Settings-GUI-Editability Audit (2026-07-05)

Ziel: alle CLI/freedom.yaml-tunbaren Felder auch in der GUI editierbar
(Operator-Wunsch). READ-ONLY-Audit; ~50 Gaps gefunden, in 5 S-Effort-
Wellen batchbar. Build-Hinweis: touch settings.slint + main.rs (heiße
Shared-Files) → bei Parallel-Session KOLLISIONSGEFAHR, in Worktree bauen.

## Bereits GUI-editierbar (Baseline)
provider_kind (Config), autonomy (Privacy, mit Ceremony), cluster.mdns.enabled
(Cluster), skills.always_embed_route (Skills), inference.{L/R/C}.{provider,model}
(Hemispheres), self_activation.enabled + proactive.enabled (Buddy), Profile-Presets,
Skills/Plugins enable/disable/install/remove. Read-only angezeigt (kein Write):
Obsidian-Pfade, Babel, council-budget, cluster-topology, hardware, usage-meter.

## STATUS (2026-07-06)
DONE + pushed: Welle A (G3-G9,G35,G36 + **G28 elicitation.min_intensity combo** `25527893`),
Welle B core (G14,G26,G27,G38), Welle C core (G10-G12), Welle E (G21-G24, coalescing writer).
OPEN restgaps (S-effort, config-shape verified, next-up):
  - **G40 consolidation_sweep** (Memory-Tab): `consolidation_sweep.{enabled(bool)/interval_secs(u64,def 21600)/cosine_threshold(f64,def 0.65)}` → wire_nested_bool!/_i64_str!/_f64_str!. Struct automation.rs:1028, FreedomConfig mod.rs:717.
  - **G37 proactive.quiet_hours_utc** (Privacy-Tab): `Option<[u8;2]>` (automation.rs:81) — 2 num, needs Null-when-empty like obsidian_auto_sync_secs.
  - G13 operator_md_extra_dirs (M — list editor), Welle D G1/G2 language/role (needs `neoth profile` CLI).
Build-note: main.slint + settings.slint + main.rs = parallel-session hot files (DES-10 live). Edit in clean regions, gate, selective-stage (they `git commit -a`-sweep frequently → may commit for you).

## Build-Plan — 5 Wellen, alle S-Effort (Toggle/Textfield/Combo)

### Welle A — Config-Tab (Council + Provider + Profile Cards)
G3 council.daily_usd_cap (num, council-card zeigt's schon read-only → write-back)
G4 council.max_calls_per_user_message (spinner 1-50)
G5 council.max_recursion_depth (spinner 1-4, 3^n-Warnung existiert)
G6 council.selection_mode (combo legacy_majority/consensus_or_best)
G8 provider_model (textfield/model-combo; combo-infra aus Hemispheres da)
G35 provider_endpoint (textfield, advanced)
G36 provider_region / provider_api_version (2 textfields, gated auf bedrock/azure)
G7 persona_mode (combo)
G9 user_tz (tz-combo/textfield)
G28 elicitation.enabled/.min_intensity (toggle+combo)
G29 tone_modifier.enabled (toggle)

### Welle B — Privacy-Tab
G14 review_gate_enabled (toggle)
G26 media.cloud_stt/tts/vision_enabled (3 toggles, Egress-Warnung — PRESET_WARN_PATHS)
G27 media.vad_enabled/.dictation_enabled (2 toggles)
G37 proactive.quiet_hours_utc (2 num)
G38 proactive.idle_only (toggle)

### Welle C — Memory-Tab
G10 memory.name_sessions (toggle)
G11 memory.recall_shortcut (toggle)
G12 memory.vector_index.backend (combo brute_force/hnsw, Rebuild-Hinweis)
G40 consolidation_sweep.enabled/.interval/.cosine (toggle+2 num)
G13 memory.operator_md_extra_dirs (M — Listen-Editor+Folder-Picker)

### Welle D — Language & Role Card (neu, Config-Tab; braucht `neoth profile language/role` CLI)
G1 language_primary/language_code (combo+textfield) — GAP-06
G2 role/role_custom (combo+conditional textfield) — GAP-06

### Welle E — Obsidian-Panel Write-Back (Panel existiert, nur Write fehlt)
G21-24 obsidian_vault/_subdir/_auto_sync_secs/_vault_reader_enabled
(neuer helper set_obsidian_*_in_freedom, Muster wie set_cluster_mdns_enabled)

### Optional (M-Effort, eigene Karten)
G19 email_ingest (host/port/user; Passwort bleibt credentials.yaml), G20 feeds
(RSS-Listen-Editor), G25 deep_research, G30 calendar-toggles, G31 auto_update,
G32 coding-gates, G33 task_engine, G34 models_aliases (kv-editor), G48 arxiv-topics,
G49 skills.visibility_overrides (per-row combo), G15-18/39/41-47 diverse cron-toggles.

## DO NOT auto-edit (Security/Ceremony/Secrets — kein naives Widget)
autonomy (Ceremony, GAP-09 ok), sovereign_buddy (Ceremony, bc-toast-only intended),
self_activation.skill_allowlist/allow_cron_registration (Escalation), security.*
(Policy-Gate = PRESET_DENYLIST), provider_key/telegram_token/cluster_key (→credentials.yaml),
provider_binary + hook_chain (Code-Exec = PRESET_DENYLIST), operator_id (WAL-Integrity-Root),
ssh_tunnels/hysteria (falsch = tötet Konnektivität).

## Evidenz
config: mod.rs FreedomConfig, inference.rs CouncilConfig, policy/automation/features/ops/memory.rs.
GUI-Writes: main.rs set_top_level_string_in_freedom:4488, set_cluster_mdns_enabled:4443,
set_skills_always_embed_route:4528, hemisphere-subprocess:5349; council-card read-only settings.slint:2833.
