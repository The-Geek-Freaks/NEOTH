# Feature / Wiring Audit — 2026-07-03

Scope: every `[x]`-DONE item in `ROAD_TO_1_0_GOLD.md` + progress files, checked
for compile errors, unfinished stubs, and built-but-unwired features. Tools:
`cargo check` (real MSVC toolchain), graphify structural graph (27 363 nodes),
targeted call-site analysis.

## Headline: committed HEAD compiles clean

`cargo check -p neothd --lib` on a **clean isolated worktree at committed HEAD
(bbb1ac8a)** → `Finished` / exit 0. **NEOTH is not bricked.** No compile errors
in committed code.

- A transient `error[E0609]: no field 'aliases' on ModelsCatalog`
  (`models/catalog.rs`) appeared when checking the **main working tree** — it
  was a parallel instance's in-flight uncommitted refactor (−137 lines,
  self-resolving), NOT a committed defect. The dirty working tree is being
  actively edited by another instance across ~12 files
  (catalog/config/chat/serve_pipeline/hyperswarm/n8n_api/…); it is not part of
  committed HEAD.

### Local toolchain note (fixed for this audit; not a NEOTH bug)

The local Windows build was blocked by two environment issues, both fixed via
an explicit MSVC env (documented here so the next audit doesn't re-derive it):
1. GNU `link` (`/usr/bin/link`, Git Bash coreutils) shadowed MSVC `link.exe` →
   `link: missing operand`. Fix: build from a `vcvars64.bat` / cmd shell.
2. `vcvars64.bat` did not fully populate `LIB`/`INCLUDE` → `LNK1104 ucrt.lib`
   and `cc-rs cl.exe` failures on C deps (zstd). Fix: explicitly prepend
   Windows SDK `10.0.22621.0` ucrt/um/shared + MSVC 14.40 lib/include.
   (This is why ChatGPT's earlier `cargo check` was "not belastbar".)

## Built-but-unwired findings

Per operator rule (WS-D): **unwired modules are FEATURES TO WIRE, never
deletions.** These are backlog-to-wire, not bugs to delete.

### 1. `#![allow(dead_code)]` crate-wide masks the whole unwired map — RECOMMEND SCOPE-DOWN

`neothd/src/lib.rs:55` carries a crate-wide `#![allow(dead_code)]` ("allowed
during the Day-2..Day-30 ramp-up"). At 1.0-RC this suppresses every
dead-code/unused-item warning across the entire crate — which is exactly the
"built but not wired" signal this audit needed. Removing it in an isolated
worktree surfaced the map below (20 private dead items). Recommendation:
remove the crate-wide allow before 1.0 and either wire or `#[cfg]`/annotate the
survivors, so "clippy clean" actually implies "no dark code".

### 2. SSH tunnel (`transport/ssh_tunnel::spawn_tunnel`) — DONE-marked, wiring claim inaccurate

`GOLD-ADAPT-TERMIX-01` is `[x]` with "auto-use wiring: fires when
`freedom.yaml::ssh_transport.enabled=true`". Reality:
- No `ssh_transport` config field exists. The Cargo.toml comment names a
  different key (`transport.ssh_tunnels`) which also does not exist in
  `FreedomConfig`.
- `spawn_tunnel` has **zero callers** anywhere in the workspace (only tests).
- It is behind the off-by-default `ssh-tunnel` feature.
- Building blocks (`ssh_tofu`, `ssh_socks5`, `SshHandler`, `ssh_jump`) ARE
  used; only the top-level local-forward entry point is unwired.

Consistent with README marking mesh **Partial**, but the plan's specific
auto-wire claim is false. To wire: add a `transport.ssh_tunnels` config
consumer in `serve.rs` that calls `spawn_tunnel` when enabled (feature-gated).

### 3. mDNS announce (`cluster/mdns::spawn_announcer`) — announce side unwired

The daemon announces itself over the Hyperswarm **DHT** (serve.rs SL-00(1b)),
never over mDNS. `cluster::mdns` is used only for **browsing** in the
`neoth cluster` CLI (`DEFAULT_SERVICE_TYPE`); `spawn_announcer` has zero
callers. README claims "Pairs nodes over LAN/mDNS" — the browse side works,
the announce side is dark, so a pure-LAN/mDNS peer can't discover this node.
To wire: spawn the mDNS announcer alongside the DHT transport when clustering
comes up (feature `cluster`, default-on).

### 4. Private dead items (20) — surfaced with the allow removed

Mostly benign superseded helpers; a couple are unwired enhancements. None
breaks a core feature (verified each is either superseded or has a live
alternative path):

| Item | Location | Assessment |
| :-- | :-- | :-- |
| `build_synthesis_prompt` | council/callosum.rs:109 | Superseded by `build_synthesis_prompt_with_profile` (live). Benign. |
| `emit_claim_event`, `emit_profile_delta_frame` | profile/apply.rs | Profile→WAL audit is live via `serialise_claim_event` (multiple PROFILE_DELTA paths). Superseded helpers. |
| `build_judge_prompt`, `parse_judge_response` | mcp/smart_approve.rs | LLM-judge batch smart-approve built + tested but not wired; the per-server readonly gate (GR-018) is the live path. Unwired enhancement. |
| `spawn_discovery` | cluster/hyperswarm.rs:192 | No-WAL convenience wrapper; `spawn_discovery_with_wal` is the live path (serve.rs:1480). Benign. |
| `send_hello`, `receive_hello` | cluster/hyperswarm.rs | Handshake helpers, superseded by the SL-00(1b) cluster_key handshake. |
| `now_unix` | tools/web_doc_cache.rs | Superseded by `crate::time` helpers (ARCH-07b). |
| `new_session_id`, `json_response`, `auth_header_value`, `decode_wal_frames`, `extract_markers`, `DEFAULT_REGION`, `Punct`, `cache_dir`×2, `prompt_hash`, `OuroForward` | various | Superseded/leftover helpers, unread fields, unused constant/variant. Low impact. |

## Wiring spot-checks that PASSED (WS-D built-but-unwired, now verified wired)

- `GOLD-WIRE-02` recall/conversational → live in `cli/serve_pipeline.rs:1104` + `cli/recall.rs` (the plan said `chat.rs`; file was imprecise, wiring is real).
- `GOLD-WIRE-04` CouncilAction::Voices → dispatched `cli/council.rs:189`.
- `GOLD-WIRE-07` HNSW EmbeddingIndex → `find_similar_dispatch` backend routing live.
- `GOLD-WIRE-11` `neoth fact-check` → `FactCheck` subcommand in `cli/mod.rs`.
- `GOLD-DELTA` babel cron → spawned `serve.rs:1056` → daemon `spawn_babel_cron_loop`.
- All ~30 daemon `spawn_*_cron/_loop` tasks referenced in `serve.rs`/`serve_tasks.rs`.

## Stub-macro scan — clean

Only 3 `todo!()`/`unimplemented!()` in source, all benign:
- `council/trigger.rs:535` — inside a test string literal, not code.
- `providers/compactor.rs:321,459` — test-mock `stream()` methods, never called.

## Verdict

Committed HEAD compiles clean; no bricked or broken core feature. The genuine
"unfinished/unwired" items are: (a) the crate-wide dead_code allow that hides
them, (b) 2 mesh entry points (`spawn_tunnel`, `spawn_announcer`) marked DONE
with wiring that isn't there — both in the honestly-"Partial" mesh area, (c) a
handful of superseded dead helpers. Recommended follow-ups: scope the
dead_code allow, correct the TERMIX-01 wiring claim, and wire (not delete) the
two mesh entry points if LAN/mDNS + SSH-tunnel are 1.0 scope.
