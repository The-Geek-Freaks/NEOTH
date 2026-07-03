# Ultra Review — 2026-07-03

4 parallel review agents (security/consent/WAL, providers/council/recall,
channels/cluster/transport, GUI-parity) over committed HEAD `8f57c9c8`, then
each finding **verified against the real code** before triage. Many raw
findings were overstated or flag intentional design — those are marked so the
loop doesn't chase false positives. Genuine bugs are fixed or listed as
precise backlog.

Legend: ✅ FIXED · 🔧 FIX-WORTH (genuine, not yet done) · ⚖️ INTENTIONAL/JUDGMENT
(verified — design choice, not a bug) · 📉 OVERSTATED (real but lower severity
than reported) · 🕰️ MULTI-WEEK (real gap, large refactor).

## Fixed this pass

- ✅ **Secret leak — `from_config_for_learn`** (`providers/mod.rs:433`). Cloned
  the main config and only swapped `provider_kind`, so a cross-vendor
  `profile.learn_provider` received the MAIN vendor's `provider_key` (secret
  egress) + foreign `provider_model` (404). Now strips key/endpoint/model when
  the learn kind differs, mirroring `build_utility_config`. Commit `f6b4c0b4`.
- ✅ **GUI Agents tab showed cluster status** (`neothd-gui/src/main.rs:1275`).
  `on_agents_refresh_clicked` probed `["cluster","status"]`; now `["agents","list"]`.
  Commit `99db83e1`.

## Genuine, fix-worth (verified real, small-to-moderate)

- 🔧 **Rate-limiter state lost on restart** (`channels/rate_limit.rs`). Buckets
  are in-memory only; a restart refills a throttled sender to full burst. Fix:
  persist non-idle buckets + TTL-decay on load. (Genuine; moderate — needs a
  persistence layer; deferred pending test verification.)

### Re-verified as OVERSTATED on second pass (moved down from fix-worth)

- 📉 **Identity merge "drops aliases"** (`channels/identity.rs:145`). The dropped
  rows are **exact-triple duplicates** the canonical identity already covers
  (`UPDATE OR IGNORE` reassigns, the leftover DELETE removes only the redundant
  victim copy of a triple canonical already owns — the comment states this).
  The triple still resolves to canonical; no unique data is lost. Not a bug.
- 📉 **FallbackProvider `name()` misattribution** (`providers/fallback.rs:118`).
  The `0x25 PROVIDER_FALLBACK_ATTEMPTED` frame already records the actual
  `to_provider` (correlatable by `prompt_hash`), so the failover IS auditable.
  `name()` is a `&'static str` provider-identity method — it structurally cannot
  return a per-call runtime-selected provider. No clean fix, no real gap.

## Config that silently does nothing (wire it — matches operator "couple it" rule)

- 🔧 **mDNS announce unwired** (`cluster/mdns.rs:148` `spawn_announcer`, 0
  callers). `cluster.mdns.enabled` is a documented knob with no consumer and no
  config field; the daemon announces over the DHT only, never mDNS → pure-LAN
  peers can't discover this node (browse works, announce dark). Wire: add
  `mdns_enabled` to `ClusterConfig`, build `MdnsIdentity` at the serve.rs
  cluster-up site, `spawn_announcer` + hold the `ServiceDaemon` handle.
- 🔧 **SSH tunnel unwired** (`transport/ssh_tunnel.rs:186` `spawn_tunnel`, 0
  callers, no config field). TERMIX-01 marked DONE with a wiring claim
  (`ssh_transport.enabled`) that doesn't exist. Wire: add
  `transport.ssh_tunnels: Vec<SshTunnelConfig>`, iterate + `spawn_tunnel` in the
  transport-init block (feature `ssh-tunnel`).
- 🔧 **`council.groundtruth_injection` + `consolidation_sweep.enabled` default
  `false`** — fully-built adversarial-grounding + memory-consolidation stay off
  for operators who never set the flag. Not a bug, but they should be surfaced
  in `neoth doctor` / `neoth init` (advisable-config hint) so the built feature
  is discoverable.

## Overstated — real but lower severity than reported

- 📉 **os_tools `risk_gate` not called** (`os_tools/gate.rs`). Agent called it
  CRITICAL (LLM runs `rm -rf`). Reality: `launch_os_app` **Layer 1 is a
  fail-closed exec-allowlist** (`resolve_exec_program` against
  `allowed_exec_paths`, exact canonical match) — the LLM can only launch
  operator-approved programs. The missing `evaluate_tool_risk` is **arg-level
  defense-in-depth** (matters only if the operator allowlists a shell like
  `bash`), not an open hole. MEDIUM defense-in-depth, not CRITICAL.
- 📉 **WAL frame decoder `u32 as usize` wrap** (`wal/frame.rs:79`). Only a DoS
  on **32-bit** targets; all NEOTH targets (x86_64, aarch64, musl-x86_64) are
  64-bit where the cast is widening and safe. Cheap defensive `MAX_PAYLOAD`
  guard is fine hardening but fixes nothing on shipped targets.
- 📉 **MCP audit frames absent on CLI path** (`cli/mcp.rs:170`). Real (one-shot
  `neoth mcp call` has no WAL writer so 0xC0/0xC1 aren't emitted), but the
  gate's **enforcement** (allowlist + permission) still runs — it's an audit
  completeness gap on an interactive CLI path, not an enforcement bypass.

## Intentional / judgment — verified NOT bugs

- ⚖️ **Inner council passes `None` embed** (`cli/chat.rs:4874`). Commented
  "inner council uses the cheap Jaccard dissent" — a deliberate cost/quality
  tradeoff (no embedding call per recursive sub-debate), not a bug.
- ⚖️ **`let _ = dir.sync_all()`** (`wal/cpt_format.rs:96`, `wal/writer.rs:438`).
  Both `#[cfg(unix)]` and explicitly commented "best-effort parent-dir fsync"
  (Windows no-op). Forcing `?` could regress writes on quirky FSes; the file
  rename itself is already durable. Left as-is by design.
- ⚖️ **`RecallTier::Multi` == `Single` budget** (`memory/recall_lanes.rs`).
  The Reflex lane it unlocks is documented-deferred; the classifier distinction
  is forward-infra, not a live no-op bug (cosmetic until Reflex ships).
- ⚖️ **`ConfirmStrategy::Channel` → Unavailable** (`permissions/gate.rs`).
  Documented "not implemented until AU-4-part-2; falls through FailClosed" —
  fail-closed is the safe default; distinct-WAL-event is a nice-to-have.

## Multi-week (real gaps, large refactors — not this pass)

- 🕰️ **Gossip WAL ingestion deferred** (`cluster/wal_sync.rs:24`). Accepted
  foreign frames converge the vector clock then DROP the payload — cluster
  memory federation is observably hollow until `idx_foreign_events` + the
  foreign indexer land. Stated next step in `SPEC_cluster_phase6`.
- 🕰️ **Warm daemon HNSW index** (`memory/embeddings.rs`). `find_similar_dispatch`
  cold-rebuilds the HNSW graph from the snapshot on every recall call; a warm
  `Arc<RwLock<EmbeddingIndex>>` in daemon state is the fix (WIRE-07b, deferred).
- 🕰️ **Hot-reload doesn't reach live channel adapters** (`cli/serve.rs`).
  Adapters snapshot `Arc<FreedomConfig>` at boot; `neoth reload` swaps the
  ArcSwap but running Telegram/Slack/webhook listeners keep the old secret →
  credential rotation needs a restart. Thread `ReloadController` into
  `PipelineHandlerDeps`.
- 🕰️ **Webhook ACK-before-persist** (`channels/webhook_listener.rs:488`) +
  **`unsafe set_var` in async** (`transport/hysteria.rs`) + **Hysteria child no
  watchdog** — each a real robustness gap; see GR-011/GR-012 history for the
  webhook ACK tradeoff (intentional to avoid Meta retry storms; durable inbound
  spool is the real closure).

## Wave 2 — un-reviewed subsystems (coding/dispatch, media/ingest, skills/config)

Three more agents over the subsystems wave 1 didn't cover. Same verify-then-
triage discipline. 6 genuine bugs fixed (all `cargo check` verified):

- ✅ **Skills path-gate failed OPEN** (`skills/router.rs:176`). A malformed
  `paths:` glob made `GitignoreBuilder::build()` fail → `return true` → the
  skill became eligible for **every** message (a file-scoped skill turned
  global). Now fail-closed + warn. Commit `01809658`.
- ✅ **`self-improve disable` silently overridden** (`cli/self_improve.rs`).
  Disable set `enabled=false` but not `asked=true`; `effective()` re-enables
  under Full autonomy (`Full && !asked`), so disable did nothing. Now sets
  `asked=true` like Enable. `01809658`.
- ✅ **Obsidian vault → ground truth had no ingress gate**
  (`daemon/obsidian_vault_reader_cron.rs`). Note bodies (external: n8n sync,
  plugins, shared files) were promoted VERBATIM to `idx_groundtruth` with no
  `ingress_sanitizer` — a prompt-injection path into the highest-trust tier.
  Now gated + quarantine-skip like every other ingest path. `01809658`.
- ✅ **OMI transcript failure invisible** (`daemon/omi_ingest_task.rs`).
  `debug!` → `warn!` so silent ground-truth-promotion loss shows at default
  log level. `01809658`.
- ✅ **Audio decode OOM** (`media/audio.rs`). No size cap → a multi-GB file
  OOMs the daemon. Added a 512 MiB metadata gate before `fs::read`. `14f9020b`.
- ✅ **Dispatcher task-strand** (`coding/dispatcher.rs`).
  `handle_retryable_failure`'s re-queue used `?` (the only propagating write in
  a fn all callers `let _ =`) → DB failure silently stranded the task
  InProgress. Now logs loudly. `14f9020b`.

Genuine-but-moderate, NOT rushed (documented for focused follow-up):
- 🔧 **WASM invoker not rebuilt on `neoth reload`** (skills-agent #1, HIGH) —
  a plugin added to `revoked_ids` keeps running until daemon restart; the
  reload swaps the ArcSwap but not the compiled invoker. Fix: re-bootstrap the
  invoker on `ReloadResult::Reloaded`, or check live `revoked_ids` in
  `invoke()`.
- 🔧 **`smart_loader::plan_loader` unwired** (coding-agent #2, HIGH) — N-04
  per-turn MCP schema selection is dead; every turn loads all servers' full
  tool lists (token burn). Fix: call `plan_loader` in `run_tool_loop_with_cap`.
- 🔧 **Email ingest cron skips `triage_inbound` / `sanitize_email_body`**
  (media-agent #2/#3) — phishing-scored + quoted-reply-injection emails reach
  the vault. Fix: route the cron through `email::inbound::triage_inbound`.
- 🔧 **faster-whisper bypasses `allow_huggingface_downloads`** (media-agent #6/
  #7) — air-gapped policy silently violated by a PATH binary. Fix: gate the
  faster-whisper path on the same flag as the candle path.
- 🔧 **Dispatcher counter skew on DB-write failure** (coding #4/#5) —
  `tasks_blocked` incremented before the confirming write; inflated on failure.

Verified INTENTIONAL/OVERSTATED (not bugs): loop_engine round-1 budget skip,
plan-review APPROVED-injection guard, zero-test all_green guard, evolver/accept
no-autonomy-gate (staging ≠ applying), paperless quarantine fail-closed, wiki
groundtruth (NEOTH-controlled slugs), VAD thresholds.

## GUI feature parity (part 2)

Measured, not assumed: the GUI has **51 wired callbacks across 14 nav tabs**
(chat, memory, hemispheres, channels, coding/kanban, agents, automation, loops,
privacy/trust, plugins, mesh/cluster, resources/hardware, doctor, config). The
loop's B7+B8 "GUI mega-wave" already delivered DAU-facing parity. The parity
agent's gap table was **partly overstated** (it flagged the Privacy tab as
"no content" — it actually has Safety-Rails + a Trust panel populated by
`set_trust_privacy`; coding/loops/config showed as "0 refs" only because they
use different handler names — kanban/loop/etc.).

Fixed: the one real GUI bug — Agents tab probed `cluster status` (99db83e1).

Genuine remaining gaps (verified absent — 0 refs), all Pro/long-tail, each =
one Slint element + one `neoth <cmd> --output json` probe handler:

- `fact-check` — a "verify this" action in the chat context (0 refs).
- `undo` — an undo button in the chat toolbar (0 refs).
- **Privacy AUDIT output** — the Privacy tab shows trust/safety-rails config but
  not `neoth privacy audit --last 30d` (what actually left the device — NEOTH's
  headline privacy proof). Highest-value GUI add.
- `jobs` panel (background-job visibility), `self-improve`/`moral-core`
  read-only panels, `goal` tracker, `credential` manager (post-onboarding key
  rotation), standalone recall browser.

These are **not shipped here on purpose**: building Slint UI blind (compile-only,
no render test in this environment) would violate verify-before-done — a panel
can compile and still mis-render. They belong in the GUI wave where the loop
render-tests against the design-taste gate. Each is small (the subprocess
bridge is uniform); the list above is the actionable backlog.

## Method note

Local build was toolchain-blocked (GNU `link` shadowing MSVC + vcvars not
populating LIB/INCLUDE). Fixed via explicit SDK `10.0.22621.0` env; recipe in
`AUDIT_FINDINGS_2026-07-03.md`. Every fix here was `cargo check -p neothd`
verified. GUI↔daemon is subprocess `neoth <cmd> --output json` (uniform, 20+
sites) — GUI parity = new panel + one probe call, no transport work.
