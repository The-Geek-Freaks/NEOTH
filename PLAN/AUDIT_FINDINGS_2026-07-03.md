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

### 2. SSH tunnel (`transport/ssh_tunnel::spawn_tunnel`) — HISTORICAL false-positive, superseded 2026-07-10

This section accurately described the `bbb1ac8a` audit snapshot, but is not a
current unwired finding. The old prose named the wrong `ssh_transport.enabled`
key. Current source loads the private
`credentials.yaml::ssh_tunnels: Vec<SshTunnelConfig>` authority into a
runtime-only `FreedomConfig` field:

- `config/mod.rs` excludes the runtime field from every public serialization;
  the coherent two-file loader atomically migrates a historical
  `freedom.yaml::ssh_tunnels` block into the private authority without losing
  unrelated YAML. When `secrets_backend: keychain` is selected and no explicit
  file override exists, migration must first open and read the compound
  keychain authority successfully; only a proven-absent bundle permits the
  legacy fallback, while availability/corruption errors leave both files
  byte-identical and create no PREPARED journal.
- Feature-on `cli/serve.rs` step `5a-ssh` opens the durable TOFU store and
  calls `spawn_tunnel` for every configured entry before provider construction;
  the returned tunnel handles own and drain their task trees during shutdown.
- Feature-off builds still load the private authority and emit a concrete
  warning rather than pretending the requested tunnels started.
- The deterministic in-process loopback proof for the SSH transport boundary
  is the SOCKS5 dialer round-trip; TOFU, jump-order and local-forward client
  behavior remain separately feature-on contract evidence under
  `GOLD-DEP-RUSSH-01`, not an asserted live-network test result in this audit.

The implementation is wired; the current dependency/remediation evidence is
tracked separately and remains open until its locked feature-on and
supply-chain gates are recorded.

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

Committed `bbb1ac8a` compiled clean; this file is a historical audit snapshot,
not a current-head clearance. Its original genuine unwired map was the
crate-wide dead-code allow, two mesh entry points and a handful of superseded
helpers. Subsequent verify-first work removed the crate-wide allow and wired
both `spawn_tunnel` and `spawn_announcer`; their current contracts are recorded
in the Road and Progress files. The remaining `russh` remediation is a
separate current-head R3-10 child and must not be inferred green from this
historical compilation result.
