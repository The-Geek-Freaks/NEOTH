# DES Next-Waves Recon (2026-07-05) — buildable specs

Recon-Output für die nächsten DES/GAP-Waves. Jeder Punkt = build-ready
Spec mit Daemon-Surface + GUI-Slot + Effort. (Recon-Workflow wf_17b95dea.)

## DES-10 — Channel-Watch live (GUI Channels-Tab zeigt Chat live)
**WAL ist metadata-only** (Text ist xxh3-64-gehasht — kein Body). Event-Types
(wal/events.rs): 0x32 CHANNEL_INGRESS {channel,sender_id(plain),text_hash,bytes,ts},
0x33 EGRESS, 0x3A PROACTIVE_SENT, 0x3B GATE_REJECTED, 0x67 CHANNEL_SEND.
- **Option A (metadata-feed, ~80 Z Rust):** gui_stream.rs 200ms-Tick + `poll_channel_feed(wal_dir, &mut last_id)` via `wal::scan::for_each_frame` (dekryptet transparent), push `{push:true, channel_feed:[{event_id,event_type,channel,sender_id,bytes,ts_ns}]}`. GUI akkumuliert Ring, gruppiert by channel, Richtung by event_type. Kein Body.
- **Option B (echter Text, +0.5d):** gui_stream hält `open_warm_conn()` → `SELECT channel,sender_id,body,ts FROM idx_episode ORDER BY ts DESC LIMIT N` (innerhalb ADV-09/15 read-only-ceiling). DAS will der Operator ("chat beobachten").
- Integration: cli/gui_stream.rs (HOT — Parallel-Session-Kollisionsrisiko). Privacy: eigene Maschine, GUI zeigt eh Chat → kein neues Gate.

## GAP-01 — Cron CRUD ✅ GEBAUT (33b4ae3a, ui/cron.slint CronView)
Daemon war 100% fertig. GUI-Panel ersetzt Automation-ProbeView.

## GAP-03 — Kanban write ops — GRÖSSTENTEILS FERTIG
move/assign/comment/promote sind GUI-wired. FEHLT nur (GUI-only, daemon done):
archive-session-Button (`neoth kanban archive <sid> --status done`), finish-task
(`kanban finish <id> --verify-tests`), add-task-to-existing-session (spec-form
öffnet immer neue Session). Klein. Detail-Pane settings.slint:2632.

## GAP-19 — Channel Add — braucht DAEMON-CLI zuerst
`neoth channel add` ist NUR interaktiv (stdin-prompts, kein Flag-Surface).
GUI linkt neothd NICHT (separates Crate) → kann `stage_channel_add` nicht
in-process rufen. BRAUCHT: non-interaktives `neoth channel add <ch> --token …
[--phone-id …]` pro Channel-Typ (telegram/slack/whatsapp/discord/signal/…,
schreibt credentials.yaml via Credentials::write, AES-GCM-SIV). Dann GUI-Form
mit per-Channel-Feldern. Daemon-Effort M + GUI M.

## DES-12 — Plugin-provided Tabs — DAEMON GEBAUT-ABER-GESWEEPT
SAFE-Design (Recon): plugins declarieren nur read-only `[ui_surface] kind="wal-feed"
title="…"` (kein exec/file — Plugin-Dir ist attacker-controlled). Daemon:
manifest.rs `PluginUiSurface::WalFeed{title}` (serde-tag, unknown-kind rejected,
title≤80) + render_list exposed ui_surface + `neoth plugin events <id> --output
json --last N` (scan 0xC4 PLUGIN_HOSTCALL-Frames by plugin-id, reuse ledger's
walk_cap_frames). GUI: PluginRow +has_ui_surface/ui_title, Inline-Detail-Pane im
Plugins-Tab (KEIN neuer NAV-Tab — NAV_PANELS ist static drift-guarded), text-only
render (escape <>[]). Effort ~300 Z / 4 Files. **Daemon-Teil war gebaut, wurde von
Parallel-Session-`git add -A` weggewischt (uncommitted) — neu bauen.**

## Rest WS-DES
DES-11 Self-Reprogramming = FEAT-05 v1.1 (daemon nicht gebaut). DES-13 Mesh-Full-
Failover = foreign-indexer (L, daemon). Beide daemon-gated.

## ⚠ KOLLISION (durable lesson)
Parallel-Claude-Session im SELBEN primary-Tree macht periodisch `git add -A`-
Commits → **wischt jede uncommittete Arbeit** (DES-12-Daemon so verloren) + macht
denselben Backlog (DES-08/09 doppelt). Build-Scripts sind main-hardcoded → kein
sauberer Worktree-Build. → Sessions müssen koordiniert werden ODER getrennte
Worktrees mit eigenen Build-Scripts. Committed+pushed Arbeit überlebt immer.
