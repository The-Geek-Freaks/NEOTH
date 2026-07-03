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

- 🔧 **Channels/identity merge silently drops colliding aliases**
  (`channels/identity.rs:145`). `UPDATE OR IGNORE` + `DELETE` on a UNIQUE
  `(channel,sender_id,chat_id)` collision drops the alias with no record on the
  tombstone → `neoth identity split` can't restore it. Fix: SELECT conflicting
  triples pre-merge, store on the tombstone `dropped_aliases` JSON.
- 🔧 **FallbackProvider misattributes the serving provider**
  (`providers/fallback.rs:118`). `name()` always returns the primary → after a
  429 failover the `PROVIDER_RESPONSE` frame credits the primary; WAL cost audit
  by provider is wrong. (`provider_fallback_attempted` IS emitted, so the data
  exists; the response frame just carries the wrong name.) Fix: propagate the
  actually-serving name.
- 🔧 **Rate-limiter state lost on restart** (`channels/rate_limit.rs`). Buckets
  are in-memory only; a restart refills a throttled sender to full burst. Fix:
  persist non-idle buckets + TTL-decay on load.

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
