# NEOTH Feature Evaluation Recheck - 2026-05-16

Scope: rechecked `SRC/` against `PLAN/FEATURE_EVAL.md` and `PLAN/PROGRESS.md`.
`QUELLEN/` is treated as source material / vendored references, not shipped NEOTH
surface. The workspace root is not a Git repository, so this is a filesystem
inspection plus local Cargo verification attempt, not a diff-based review.

Update 08:55: rechecked again after the latest `PROGRESS.md` + source changes.
Update 10:35: rechecked again after the CDX-03 / CH-06 audit / B-6 / B-9 /
C-15 audit-anchor changes.
Update 11:10: verification rerun through VS 2022 BuildTools `vcvars64.bat` plus
explicit Windows SDK UCRT paths; workspace tests and clippy are now green in
this shell.
Update 14:55: rechecked after the next build wave. Raw tracked completion is
now 60.1%; fmt, clippy, and tests are all locally green through the MSVC/UCRT
path.
Update 16:40 WIP: rechecked during active coding. Raw tracked completion is now
60.2%. After one local clippy-nit fix in `cli/rollback.rs`, the current
snapshot is green: fmt, clippy, and workspace tests all pass through the
MSVC/UCRT wrapper.
Update 19:35 active-coding recheck: strict checkbox parsing now puts tracked
completion at 379 / 622 = 60.9%. The new webhook listener / callosum / profile
lookup / MCP autoroute / rollback-tail work verifies green after one local
guard-test allowlist fix for the inbound-only webhook listener self-tests.
Update 2026-05-19 07:55: rechecked after the Session-14 build wave. Strict
tracked completion is now 507 / 723 = 70.1%. After applying rustfmt and fixing
one stale Keet fallback test, fmt, clippy, and workspace tests are green again
with 2031 passed, 0 failed, 3 ignored.
Update 2026-05-19 14:23: active-coding recheck after Session-15 edits. Strict
tracked completion is now 508 / 723 = 70.3%. After one rustfmt-only touch in
`cli/chat.rs`, fmt, clippy, and workspace tests are green with 2103 passed, 0
failed, 3 ignored.
Update 2026-05-19 15:15: active-coding recheck after the next Session-15 wave.
Strict tracked completion is now 512 / 723 = 70.8%. After fixing one misplaced
`resolved_profile_provider()` impl, two stale provider variant names, one
Discord Gateway doc-lint indentation, and running rustfmt, fmt, clippy, and
workspace tests are green with 2134 passed, 0 failed, 3 ignored.
Update 2026-05-19 17:32: active-coding recheck after the next Session-15 wave.
Strict tracked completion is now 512 / 728 = 70.3%. Done count stayed flat, but
scope grew by five open checklist rows. After one rustfmt-only GUI touch, fmt,
clippy, and workspace tests are green with 2186 passed, 0 failed, 3 ignored.
Update 2026-05-19 20:29: active-coding recheck after the next WASM/plugin/WAL
wave. Strict tracked completion is still 512 / 728 = 70.3%, but source test
attributes grew from 2202 to 2278 and workspace tests grew to 2222 passed, 0
failed, 3 ignored. After rustfmt-only cleanup, fmt, clippy, and workspace tests
are green.
Update 2026-05-20 09:05: active-coding recheck after the coding/Kanban wave.
Strict tracked completion is still 512 / 728 = 70.3%, but source test
attributes grew from 2278 to 2403 and workspace tests grew to 2341 passed, 0
failed, 3 ignored. After rustfmt-only cleanup, fmt, clippy, and workspace tests
are green.

## Verification status

- `rustc --version`: `rustc 1.95.0 (59807616e 2026-04-14)`; MSRV 1.86 is met.
- `cargo fmt --all -- --check`: PASS from `SRC/`. `rustfmt.toml` still emits
  stable-toolchain warnings for nightly-only options; PowerShell also prints
  unrelated `Import-Clixml` prompt noise, but Cargo exits 0 and the workspace is
  formatted.
- `.\scripts\cargo-msvc.ps1 clippy --workspace --all-targets -D warnings`:
  PASS. This is the same check VS Code was effectively getting right.
- `.\scripts\cargo-msvc.ps1 test --workspace`: PASS. Result: 1148 passed, 0
  failed, 3 ignored. Breakdown: plugin SDK 10/10, `neothd` 1122 passed / 2
  ignored, multimodal smoke 7/7, no-outbound-network 1/1, GUI 8/8, plugin SDK
  doctest 0 passed / 1 ignored.
- Static test-attribute count: 1149 `#[test]` / `#[tokio::test]` attributes
  across `SRC/`; this is a source-shape count, not the Cargo pass count.

Progress math from `PLAN/PROGRESS.md`:

- Total tracked boxes: 619.
- Done: 372.
- Open: 236.
- In progress: 2.
- Blocked: 0.
- Deferred: 9.
- Raw completion: 372 / 619 = 60.1%.
- Pre-master implementation/history section: 328 / 421 = 77.9%.
- Master open checklist: 3 / 115 = 2.6%.
- Production roadmap: 0 / 36 (`v0.2`, `v0.3`, `v1.0`, `v1.x` all still open).
- Post-roadmap session additions: 41 / 47 = 87.2%.

Working Windows verification command shape is now checked in as
`scripts/cargo-msvc.ps1`:

```powershell
.\scripts\cargo-msvc.ps1 test --workspace
.\scripts\cargo-msvc.ps1 clippy --workspace --all-targets -D warnings
```

Equivalent raw command shape:

```powershell
$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$ucrtLib = 'C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64'
$ucrtInclude = 'C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt'
cmd /V:ON /d /s /c "`"$vcvars`" >nul && set `"LIB=!LIB!;$ucrtLib`" && set `"INCLUDE=!INCLUDE!;$ucrtInclude`" && cargo test --workspace"
```

The important detail is delayed expansion (`!LIB!`, `!INCLUDE!`) after
`vcvars64.bat`; `%LIB%` expands too early and drops the SDK paths.

Conclusion: formatting, workspace tests, and workspace clippy are now verified
green in this environment. The earlier blocker was shell environment, not code.

## Delta against 2026-05-15 feature eval

### Items that moved from "priority" to shipped / mostly shipped

| Item | Old eval | Current state | Recheck verdict |
|---|---:|---|---|
| C-14 cost transparency | 50%, top priority | `cli/cost.rs`, `providers/cost.rs`, `chat.rs` WAL `COST_ESTIMATE_SHOWN`, `Action::PaidProviderCall` gate | 85%. Real operator surface exists. Unknown cloud models now fall back to a conservative high estimate instead of pricing as free. Still uses 4-char token heuristic + static price table. |
| C-1 / C-11 anti-sycophancy + adversarial critic | 25-50%, top priority | Built-in `critic` sub-agent and `/critic` slash command shipped | 70%. Usable on demand and in review-gate path. Not yet a default council behavior and no hard anti-sycophancy scoring loop. |
| C-7 persona layer | 25%, phase 1 | `tweaks.toml::persona_override` is prepended in chat system prompt | 65%. Good pragmatic layer; not persistent identity across providers by itself. |
| CH-04/05/06 hemisphere provider selection | open in master checklist | `cli/hemispheres.rs`, `config::inference`, `providers::from_config_for_role`, WAL `0x1F HEMISPHERE_REBOUND` | 70%. `show`, `set`, `test`, wizard recommendations, role-aware provider construction, chat/profile left-role routing, and immediate rebind audit frame exist. Still not a real council/debate dispatcher and no GUI panel. |
| A-20 web search | 0%, easy | `tools/web_search.rs` + `neoth search`, Brave/Tavily | 70%. CLI works with API key. Needs credentials.yaml integration polish and tests with mocked HTTP. |
| A-21 web fetch | 0%, easy | `tools/web_fetch.rs` + `neoth fetch`, HTML-to-readable-text stripper | 75%. Self-contained non-JS fetch is usable. Not a full Markdown converter and not JS-browser capable. |
| A-24 ArXiv | 0%, requested | `tools/arxiv.rs` + `neoth arxiv search` | 75%. Search/list is live. Learner loop / scheduled ingestion is not. |
| A-3 / A-4 GitHub PR + issues | 0/easy | `tools/github.rs` + `neoth github` wraps `gh` | 65%. Practical shim exists. Full branch-commit-PR workflow and permission integration are still partial. |
| MCP integration | old eval treated as prerequisite / absent | `mcp/{client,config,transport,gate,sanitizer,catalogue,tool_call_parser,dispatch_loop}.rs` + `neoth mcp list/tools/call` + chat catalogue injection + opt-in autoroute | 85%. Stdio JSON-RPC client, config, manual CLI calls, `allow_tools`, prompt-injection sanitizer, autonomy gate, WAL `0xC0/0xC1` audit, system-prompt catalogue, fenced-call parser, and dispatch loop exist. Still opt-in via `NEOTH_MCP_AUTOROUTE=1`; needs full stub-server / live-server e2e coverage and eventual council integration. |
| Bridge V2 warm Claude sessions | deferred | `providers/tmux_session.rs`, `providers/singleflight.rs`, `claude_cli.rs` dedup wiring | 45%. `Singleflight` is actually wired into Claude CLI `complete`; tmux lifecycle primitive is real and tested but not configured or used by the adapter yet. |
| A-45 TTS | future | `neoth tts speak`, ElevenLabs live; Piper explicit Phase 2 error | 45%. Cloud TTS path exists; local Piper not shipped. |

### Items that are still mostly scaffold

| Item | Current state | Recheck verdict |
|---|---|---|
| Slack channel A-7 | `channels/slack.rs::send_text` uses `chat.postMessage`; `neoth slack send --channel --message` exists; `neoth slack test` validates tokens / gets WSS URL | 55%. Outbound is real. Socket-Mode receive loop is still not shipped. |
| WhatsApp A-13 | `channels/whatsapp.rs::send_text` uses Meta Graph `/messages`; webhook receiver still bails with Phase-2 message | 45%. Outbound is real. Inbound webhook / delivery correlation is still deferred. |
| Keet R-2 | `channels/keet.rs` accepts seed but bails until Hyperswarm transport | 20%. Stub only. |
| Discord A-12 | `ChannelKind::Discord` exists; no adapter module | 10%. Still not implemented. |
| B-rollback | `/rollback` slash command previews backup restore; actual automatic pre-op snapshot is not enforced at file mutation sites | 35%. Operator UX wrapper exists, safety primitive not system-wide. |
| Local Piper TTS | enum/provider path exists but returns Phase 2 error | 15%. Explicit placeholder only. |

### C-15 real forgetting correction

The old eval called C-15 "75%" and recommended Phase 1. Current code is now
better than the 08:55 recheck, but still not GDPR-grade physical erasure:

- `memory/forget.rs` does cascade-delete from SQLite views:
  `idx_episode`, `idx_consolidated`, `idx_longterm`, `idx_embedding`, and
  revokes matching `idx_groundtruth`.
- `neoth memory --forget <topic>` has dry-run and `--confirm`.
- Confirmed forget now writes a `TOMBSTONE_REQUESTED` (`0xF1`) WAL audit-anchor
  frame with topic, per-tier row counts, timestamp, and source.
- The module still explicitly says physical WAL payload tombstoning + HMAC
  recompaction are deferred.

Recheck verdict: 65%. Operator-visible recall forget plus durable erasure-intent
audit is real. GDPR-grade retroactive erasure is not real until original WAL
payload bytes are rewritten/tombstoned and the HMAC chain is recomputed.

## 14:55 category read

Keyword-weighted progress from `PROGRESS.md` is noisy but useful as a shape
check. This uses exact checkbox parsing plus category keywords; it is not a
canonical product-area denominator.

| Area | Current done | Read |
|---|---:|---|
| Local inference / providers | 80 / 104 = 76.9% | Stronger than before; real-weight and accelerator proof still gate confidence. |
| Profile / adaptive memory | 100 / 134 = 74.6% | Semantically strong; proactive/adaptation UX still open. |
| MCP / tools / security | 77 / 110 = 70.0% | CDX-04/05 landed; autonomous routing exists but is opt-in and needs real server e2e. |
| Channels | 51 / 74 = 68.9% | Outbound Slack + WhatsApp changed the shape; inbound loops still block full channel maturity. |
| Council / hemispheres | 21 / 35 = 60.0% | Config/routing primitives landed; council itself still open. |
| GUI / product | 62 / 104 = 59.6% | Better than the old read, still product-maturity drag versus core. |

## Updated top priorities

The previous "ship first" list is stale because several items have landed.
The next work should focus on closing trust and production gaps, not adding
more feature surface.

1. Preserve verification truth: wire the checked-in MSVC/UCRT wrapper into CI
   and onboarding docs so future local shells do not regress to false blockers.
2. Finish C-15 WAL tombstone rewrite. SQLite-only forget is not enough for the
   claim "real GDPR forgetting".
3. Wire one second production channel end-to-end. Slack is the best candidate:
   token preflight already exists, so add socket-mode receive/send loop.
4. Convert B-rollback from a slash preview into a system-level pre-mutating-op
   snapshot hook.
5. Add mocked HTTP tests for web search/fetch/ArXiv/GitHub shims. Current tests
   mostly cover parser/error surfaces, not provider behavior.
6. Connect the new hemisphere primitives into actual council routing; otherwise
   they are strong configuration surface, not the brain architecture yet.
7. Add real MCP e2e coverage with a stub server, then decide whether autoroute
   graduates from opt-in chat path to default/council path.

## Revised scorecard highlights

- Strong shipped core remains: WAL + SQLite views, recall, cost preview,
  hooks, permissions, credentials split, local Qwen skeleton/forward path,
  multimodal modules, Telegram path, CLI breadth.
- Biggest honesty gap fixed in this session: tests/clippy are no longer blocked
  locally. The Codex shell needs the VS 2022 BuildTools + explicit UCRT wrapper,
  but the workspace verifies green once that environment is loaded.
- Biggest architectural gap: lots of useful CLI surfaces exist, but channel
  delivery and action gating are not uniformly applied to every tool path yet.
- Biggest risk: rapid feature accretion without the same verification gate.
  `PLAN/PROGRESS.md` already reads like production truth; it needs a hard rule:
  no item moves to "shipped" unless fmt, clippy, tests, and at least one
  behavior-level test are green in CI.

## Bottom line

NEOTH advanced materially since the 2026-05-15 eval and again since the 08:55,
10:35, and 14:55 rechecks. The correct current framing is no longer "which
features should we build first?" It is:

> Stop adding breadth for a sprint. Make the shipped claims testable, close
> C-15 at the WAL layer, then complete one non-Telegram channel end-to-end.

Current best estimate:

- Overall NEOTH vision: 60.1% by raw tracked work; 60-62% by engineering
  judgement because the latest work is high-leverage, not just checklist mass.
- Core daemon / CLI / memory / WAL: 80%.
- MCP/tooling/security: 78-82%. Manual MCP was already strong; catalogue
  injection plus opt-in autoroute moves this into real autonomous-tool territory.
- Channels: 68-70%. Telegram plus Slack/WhatsApp outbound are real; Slack and
  WhatsApp inbound loops still block "done".
- v0.2 production-readiness: 52-55%. Local verification is now green, but the
  production roadmap is still 0/36, so this is not release-ready yet.
- Quality: core architecture 8.1/10, product maturity 6.3/10, verification
  confidence 8.4/10 locally. CI/matrix proof and live integration coverage are
  still the next confidence jump.

## 16:40 WIP recheck

Current `PROGRESS.md` math:

- Total tracked boxes: 621.
- Done: 374.
- Open: 233.
- In progress: 4.
- Blocked: 1.
- Deferred: 9.
- Raw completion: 374 / 621 = 60.2%.
- Pre-master implementation/history section: 329 / 422 = 78.0%.
- Master open checklist: 4 / 116 = 3.4%.
- Production roadmap: 0 / 36.
- Post-roadmap session additions: 41 / 47 = 87.2%.

Fresh source movement since the 14:55 checkpoint:

- `channels/slack_events.rs`: Slack Socket-Mode / Events API frame decoder and
  ACK shape. This is inbound parsing foundation, not the socket loop yet.
- `channels/whatsapp_webhook.rs`: WhatsApp webhook payload decoder. This is
  inbound parsing foundation, not public HTTPS webhook serving yet.
- `council/{types,dissent,orchestrator,trigger,eval}.rs`: Council foundation,
  trigger policy, and adversarial fixture harness started.
- `wal/redact.rs`, `cli/memory.rs`, `cli/verify.rs`: physical WAL redaction /
  verification work for C-15 moved materially.
- `wal/snapshot.rs`, `cli/rollback.rs`, `config::RollbackConfig`,
  `cli/hemispheres.rs`: rollback pre-mutation snapshot primitive plus first
  mutation-site wiring.

Verification for the WIP snapshot:

- `cargo fmt --all -- --check`: PASS.
- `.\scripts\cargo-msvc.ps1 clippy --workspace --all-targets -D warnings`:
  PASS after changing the rollback test's JSON float fixture from `3.14` to
  `1.25`.
- `.\scripts\cargo-msvc.ps1 test --workspace`: PASS. Result: 1273 passed, 0
  failed, 3 ignored. Breakdown: plugin SDK 10/10, `neothd` 1247 passed / 2
  ignored, multimodal smoke 7/7, no-outbound-network 1/1, GUI 8/8, plugin SDK
  doctest ignored.

WIP estimate:

- Overall vision: 60.2% raw; 61-63% engineering judgement because the recent
  work is high-leverage and tests are green.
- Current checkpoint deserves 62-64% by engineering judgement.
- Current verification confidence for the snapshot: 8.5/10. Environment
  confidence remains high and the code is locally verified green.

## 19:35 active-coding recheck

Counting method changed here to strict checklist rows only:
`^\s*-\s+\[(x| |~|!|defer)\]`. This avoids counting legend text and inline
documentation examples such as `` `[!]` marker `` as real work items.

Current `PROGRESS.md` math:

- Total tracked boxes: 622.
- Done: 379.
- Open: 227.
- In progress: 6.
- Blocked: 1.
- Deferred: 9.
- Raw completion: 379 / 622 = 60.9%.
- Pre-master implementation/history section: 329 / 422 = 78.0%.
- Master open checklist: 5 / 116 = 4.3%.
- Production roadmap: 3 / 36 = 8.3%.
- Post-roadmap session additions: 42 / 48 = 87.5%.

Fresh source movement since the 16:40 checkpoint:

- `channels/webhook_verify.rs`, `channels/webhook_router.rs`,
  `channels/webhook_listener.rs`: A7 is no longer just crypto/router
  primitives. There is now a Hyper 1.x localhost HTTP listener with 1 MiB body
  cap, Meta `/webhook` verification and Slack `/slack/events` URL
  verification. Verified WhatsApp POSTs flow through the payload decoder and
  into the operator `PipelineHandler`; Slack event callbacks are verified but
  the Slack adapter event-loop remains CDX-06.
- `mcp/config.rs`, `mcp/dispatch_loop.rs`, `mcp/gate.rs`, `cli/chat.rs`: MCP
  autoroute now defaults to AUTO when enabled servers exist; chat integrates
  the dispatch loop and the MCP gate can emit rollback snapshots for tool
  invocations.
- `cli/rollback.rs`, `cli/init.rs`, `channels/mod.rs`, `wal/snapshot.rs`:
  rollback moved from primitive/list/apply into wider capture coverage:
  ConfigWrite reconfigure snapshots, ChannelSend snapshot helper, platform
  delete/edit/manual templates, SQL inverse dispatcher, and MCP snapshot
  wiring. It is still not every mutation site in the system.
- `council/callosum.rs`, `cli/chat.rs`, `profile/lookup.rs`: Split council
  outcomes can now escalate once to Cerebellum/callosum, optionally injecting
  high-confidence, non-redacted profile claims into the synthesis prompt. This
  is meaningful brain-architecture progress, but smart-trigger/default council
  routing is still not done.
- `README.md` and `scripts/setup-windows.ps1`: Windows MSVC onboarding moved
  from session knowledge into project artifacts; CDX-05 is now done in
  `PROGRESS.md`.

Verification for this snapshot:

- `cargo fmt --all -- --check`: PASS.
- `.\scripts\cargo-msvc.ps1 clippy --workspace --all-targets -D warnings`:
  PASS.
- First `.\scripts\cargo-msvc.ps1 test --workspace`: failed only in
  `tests/no_outbound_network.rs`, because the static no-phone-home guard saw
  `reqwest::get` / `reqwest::Client` inside `webhook_listener.rs` tests.
- Local fix applied: added `src/channels/webhook_listener.rs` to the guard's
  documented allowlist, mirroring `daemon/healthz.rs`: inbound localhost server,
  test module connects to itself; production listener is still inbound-only.
- Final `.\scripts\cargo-msvc.ps1 test --workspace`: PASS. Result: 1356
  passed, 0 failed, 3 ignored. Breakdown: plugin SDK 10/10, `neothd` 1330
  passed / 2 ignored, multimodal smoke 7/7, no-outbound-network 1/1, GUI 8/8,
  plugin SDK doctest ignored.

Current read:

- Overall NEOTH vision: 60.9% raw; 64-66% engineering judgement. The raw
  number barely moves because scope keeps growing, but the shipped surfaces are
  high-leverage: inbound HTTP listener, rollback coverage, MCP autonomy, and
  callosum/profile synthesis.
- v0.2 readiness: 59-61%. Production roadmap is no longer 0/36, but 33/36
  roadmap rows are still open, so this is still not release-ready.
- Core daemon / CLI / memory / WAL: 84-86%.
- MCP / tooling / security: 84-87%.
- Channels: 72-75% by engineering read. Telegram plus Slack/WhatsApp outbound,
  WhatsApp verified inbound listener, and Slack URL verification are real; Slack
  Socket-Mode event loop and full adapter integration still block "done".
- Council / hemispheres: 68-72%. Env-gated debate, callosum recovery, WAL audit,
  and profile-context injection exist; smart trigger and default chat routing
  remain the gap.
- Profile / adaptive memory: 77-80%. Profile pipeline and lookup are strong;
  adaptation/product feedback loops still lag.
- Verification confidence: 8.8/10 locally. fmt, clippy, workspace tests are
  green through the checked-in MSVC wrapper; CI/matrix and live integration e2e
  are still the next confidence jump.

## 2026-05-19 active-coding recheck

Current `PROGRESS.md` math with strict checklist-row parsing:

- Total tracked boxes: 723.
- Done: 507.
- Open: 203.
- In progress: 4.
- Blocked: 1.
- Deferred: 8.
- Raw completion: 507 / 723 = 70.1%.
- Pre-master implementation/history section: 337 / 414 = 81.4%.
- Master open checklist: 18 / 65 = 27.7%.
- Production roadmap: 8 / 43 = 18.6%.
- Post-roadmap session additions: 144 / 201 = 71.6%.

Major fresh movement since 19:35 on 2026-05-16:

- Session-14 provider/model expansion: AWS Bedrock SigV4 adapter, Azure OpenAI
  adapter, known endpoint catalogue, dynamic model catalog/discovery sources,
  daily refresh task, catalog CLI, provider-known CLI, and model-select wizard
  integration.
- Council redesign advanced from env-gated debate into real selection
  architecture: `quality_score`, `self_reflect`, `BudgetToken`,
  provider-diversity preflight, `COUNCIL_WINNER_SELECTED`, diversity warning
  WAL event, and per-hemisphere sub-provider config.
- Code-map / repo-context shipped in three layers: file walker, regex symbol
  extraction, SQLite persistence/search, relevance scoring, CLI surface, and
  opt-in chat system-prompt injection via `CodeMapConfig.auto_context_max_files`.
- Channels advanced with Discord send-only REST adapter, Discord/Keet
  formatter matrix, canonical reply formatting, and Slack socket parsing
  primitives. Discord receive remains Gateway/WebSocket Phase 2.
- Profile consistency hardened with WAL-first outbox and daemon startup drain.
- Permission/autonomy integration tests now pin several high-risk paths:
  Standard expensive deny, Strict ChannelSend deny, Full allow, and cost-predict
  spine.

Verification for this snapshot:

- Initial `cargo fmt --all -- --check`: FAIL. Rustfmt deltas were mechanical
  across the new Session-14 files.
- Local fix applied: ran `cargo fmt --all`.
- Initial workspace test run then exposed one stale assumption:
  `channels::tests::send_canonical_falls_back_to_plain_text_when_no_formatter`
  still expected Keet to have no formatter. Session 14 made Keet/Discord
  formatters real, so the test was updated to assert the Keet formatter keeps
  the plaintext body and fenced code block.
- Final `cargo fmt --all -- --check`: PASS.
- Final `.\scripts\cargo-msvc.ps1 clippy --workspace --all-targets -D warnings`:
  PASS.
- Final `.\scripts\cargo-msvc.ps1 test --workspace`: PASS. Result: 2031
  passed, 0 failed, 3 ignored. Breakdown: plugin SDK 10/10, `neothd` 2005
  passed / 2 ignored, multimodal smoke 7/7, no-outbound-network 1/1, GUI 8/8,
  plugin SDK doctest ignored.
- Static source test-attribute count: 2030 `#[test]` / `#[tokio::test]`
  attributes across `SRC/`.

Current read:

- Overall NEOTH vision: 70.1% raw; 72-75% engineering judgement. The jump is
  real, but not all of it is release-hardening: a lot is new surface area.
- v0.2 readiness: 67-70%. Production roadmap is now 8/43 instead of 3/36, but
  most production-roadmap rows remain open, so this is still not release-ready.
- Core daemon / CLI / memory / WAL: 88-90%.
- Providers / model management: 88-91%.
- MCP / tooling / security: 85-88%.
- Council / hemispheres: 78-82% by implementation surface; lower for
  production trust until live multi-provider e2e and cost/budget telemetry are
  proven under real workloads.
- Channels: 76-79%. Telegram, Slack/WhatsApp outbound, WhatsApp verified
  inbound, Discord send-only, and formatter matrix are real. Slack full
  Socket-Mode loop, Discord Gateway receive, and long-tail adapters remain.
- Code-map / repo context: 70-75% for the intended v0.2 usefulness. Tree-sitter
  AST parsing and semantic rerank remain future work, but the opt-in chat wire
  is real.
- Verification confidence: 9.0/10 locally. The suite is large and green through
  the MSVC wrapper. Remaining confidence gap is CI matrix + live external e2e,
  not local compile/lint/test.

## 2026-05-19 14:23 active-coding recheck

Current `PROGRESS.md` math with strict checklist-row parsing:

- Total tracked boxes: 723.
- Done: 508.
- Open: 202.
- In progress: 4.
- Blocked: 1.
- Deferred: 8.
- Raw completion: 508 / 723 = 70.3%.
- Pre-master implementation/history section: 340 / 417 = 81.5%.
- Master open checklist: 23 / 116 = 19.8%.
- Production roadmap section: 21 / 39 = 53.8%.
- Post-roadmap session additions: 124 / 151 = 82.1%.

Fresh movement since the prior recheck:

- The strict checkbox score only moved from 507 to 508 done rows, but that
  understates the implementation movement: several Session-15 picks are mostly
  hardening/refactor/test depth rather than new top-level boxes.
- Test surface grew materially: final local result is 2103 passed, 0 failed, 3
  ignored; static source test-attribute count is now 2112 across `SRC/`.
- Session-15 now records the formatter splitter O(N) fix, credential-age doctor
  check, `claude_cli` auto-to-subprocess warning, `HemisphereOutcome` bridge,
  Type #13 Phase-2 production migration, and `docs/channels.md` status refresh.
- Feedback-queue items now marked as picked up include Slack Socket-Mode full
  loop, Discord Gateway v0.3 marker, CI matrix, and OpenAI wiremock provider
  tests. The live external provider/council e2e half is still correctly
  operator-deferred.

Verification for this snapshot:

- Initial `cargo fmt --all -- --check`: FAIL, one mechanical formatting delta in
  `src/cli/chat.rs`.
- Local fix applied: ran `cargo fmt --all`; no semantic code change.
- Final `cargo fmt --all -- --check`: PASS.
- Final `.\scripts\cargo-msvc.ps1 clippy --workspace --all-targets -D warnings`:
  PASS.
- Final `.\scripts\cargo-msvc.ps1 test --workspace`: PASS. Result: 2103
  passed, 0 failed, 3 ignored. Breakdown: plugin SDK 10/10, `neothd` 2077
  passed / 2 ignored, multimodal smoke 7/7, no-outbound-network 1/1, GUI 8/8,
  plugin SDK doctest ignored.

Current read:

- Overall NEOTH vision: 70.3% raw; 74-77% engineering judgement. The project is
  no longer "prototype with many stubs"; it is now a large, locally-verifiable
  daemon/tooling system with real operator surfaces. The remaining gap is mostly
  release trust, live-provider proof, long-tail adapters, and v1 packaging.
- v0.2 checklist: effectively complete by the roadmap rows. Product release
  readiness is lower, about 74-78%, because live external e2e and real-world
  channel/provider soak are still missing.
- Core daemon / CLI / memory / WAL: 89-91%.
- Providers / model management: 88-91%.
- MCP / tooling / security: 86-89%.
- Council / hemispheres: 80-84%; architecture is strong, but production trust
  still depends on live multi-provider budget/cost/WAL telemetry verification.
- Channels: 78-82%; Telegram/WhatsApp/Slack/Discord/Keet surfaces are much more
  real now, but Discord receive and long-tail adapters still keep it below
  "done".
- Code-map / repo context: 72-76%; useful v0.2 path exists, semantic/AST depth
  remains future work.
- Verification confidence: 9.2/10 locally. fmt, clippy, and the full workspace
  suite are green through the MSVC wrapper. Remaining confidence gap is not this
  shell anymore; it is CI/live external integration evidence.

## 2026-05-19 15:15 active-coding recheck

Current `PROGRESS.md` math with strict checklist-row parsing:

- Total tracked boxes: 723.
- Done: 512.
- Open: 198.
- In progress: 4.
- Blocked: 1.
- Deferred: 8.
- Raw completion: 512 / 723 = 70.8%.
- Pre-master implementation/history section: 340 / 417 = 81.5%.
- Master open checklist: 23 / 116 = 19.8%.
- Production roadmap section: 25 / 39 = 64.1%.
- Post-roadmap session additions: 124 / 151 = 82.1%.

Fresh movement since the 14:23 recheck:

- Four more checklist rows are marked done. The visible delta is concentrated
  in the production roadmap section, which moved from 21 / 39 to 25 / 39.
- Session-15 now records additional v1/readiness closures: Discord Gateway WSS
  scaffold / v0.3 receive prep, V10-10 security disclosure recheck closure,
  V10-07 H3 profile privacy WARN foundation, R-1 GUI theme/screen closure,
  V10-09 CI recheck closure, V10-01 OPEN_DECISIONS recheck closure,
  V10-06 migration registry foundation, V10-04 WASM plugin host stub,
  V10-03 plugin publish-readiness, V10-08 HNSW telemetry signal,
  PROFILE_BASELINE_SNAPSHOT registry/event work, and Bedrock/Azure cost parity.
- Static source test-attribute count is now 2137 across `SRC/`.

Verification for this snapshot:

- Initial `cargo fmt --all -- --check`: PASS.
- Initial `.\scripts\cargo-msvc.ps1 clippy --workspace --all-targets -D warnings`:
  FAIL at compile/lint stage:
  - `config/inference.rs`: `resolved_profile_provider()` was attached to
    `SubHemisphereSlots` although `profile_provider` / `embedding_provider`
    live on `InferenceTopology`.
  - `config/inference.rs` tests used stale enum names `GeminiApi` and
    `OpenaiApi`; the actual variants are `Gemini` and `OpenAi`.
  - `channels/discord_gateway.rs`: Clippy `doc_lazy_continuation` on the
    continued `+ message content` doc-list line.
- Local fixes applied:
  - Moved `resolved_profile_provider()` into `impl InferenceTopology`.
  - Updated the stale provider variant names in the new tests.
  - Indented the Discord Gateway doc continuation line.
  - Ran `cargo fmt --all`.
- Final `cargo fmt --all -- --check`: PASS.
- Final `.\scripts\cargo-msvc.ps1 clippy --workspace --all-targets -D warnings`:
  PASS.
- Final `.\scripts\cargo-msvc.ps1 test --workspace`: PASS. Result: 2134
  passed, 0 failed, 3 ignored. Breakdown: plugin SDK 10/10, `neothd` 2108
  passed / 2 ignored, multimodal smoke 7/7, no-outbound-network 1/1, GUI 8/8,
  plugin SDK doctest ignored.

Current read:

- Overall NEOTH vision: 70.8% raw; 75-78% engineering judgement.
- v0.2 checklist/readiness: 76-80%. The roadmap section is much healthier now
  at 25 / 39, but real live-provider/council/channel soak is still the missing
  release-confidence evidence.
- Core daemon / CLI / memory / WAL: 90-92%.
- Providers / model management: 89-92%.
- MCP / tooling / security: 87-90%.
- Council / hemispheres: 81-85%.
- Channels: 79-83%; Discord Gateway prep is now real scaffold, but receive is
  still not equivalent to an operationally-soaked adapter.
- GUI / installer / release polish: 68-74%; the GUI theme/screen work raises
  confidence, but v1 packaging/distribution still has meaningful open surface.
- Verification confidence: 9.3/10 locally. The current shell can prove fmt,
  Clippy, and full workspace tests green. The remaining confidence gap is live
  external integration, not local toolchain capability.

## 2026-05-19 17:32 active-coding recheck

Current `PROGRESS.md` math with strict checklist-row parsing:

- Total tracked boxes: 728.
- Done: 512.
- Open: 203.
- In progress: 4.
- Blocked: 1.
- Deferred: 8.
- Raw completion: 512 / 728 = 70.3%.
- Pre-master implementation/history section: 340 / 417 = 81.5%.
- Master open checklist: 23 / 116 = 19.8%.
- Production roadmap section: 25 / 44 = 56.8%.
- Post-roadmap session additions: 124 / 151 = 82.1%.

Fresh movement since the 15:15 recheck:

- Done count stayed at 512, but total tracked scope grew from 723 to 728. The
  visible percentage therefore moved down from 70.8% to 70.3% despite more code
  and tests landing.
- Production roadmap scope changed from 39 to 44 rows. The correct dynamic
  heading-based count is now 25 / 44 = 56.8%; older fixed-line section math is
  stale after the new roadmap insertions.
- New Session-15 items recorded in `PROGRESS.md` include:
  - Pick #27: `neoth-migrate` binary scaffold plus Markdown/JSON readers.
  - Pick #26: V10-04 plugin discovery under `~/.neoth/plugins/<id>/`.
  - Pick #25: V10-04 `plugin.toml` manifest parser.
  - Pick #24: V10-04 wasmtime engine behind feature defaults.
  - Pick #23: V10-07 `profile_provider` config layer.
  - Pick #32: GUI Settings panel with tab layout and wizard rerun/reset hooks.
- Static source test-attribute count is now 2202 across `SRC/`.

Verification for this snapshot:

- Initial `cargo fmt --all -- --check`: FAIL, one mechanical formatting delta in
  `neothd-gui/src/main.rs`.
- Local fix applied: ran `cargo fmt --all`; no semantic change.
- Final `cargo fmt --all -- --check`: PASS.
- Final `.\scripts\cargo-msvc.ps1 clippy --workspace --all-targets -D warnings`:
  PASS.
- Final `.\scripts\cargo-msvc.ps1 test --workspace`: PASS. Result: 2186
  passed, 0 failed, 3 ignored. Breakdown: `neoth-migrate` 11/11, plugin SDK
  10/10, `neothd` 2149 passed / 2 ignored, multimodal smoke 7/7,
  no-outbound-network 1/1, GUI 8/8, plugin SDK doctest ignored.

Current read:

- Overall NEOTH vision: 70.3% raw; 75-79% engineering judgement. Raw percentage
  dipped only because scope expanded; engineering maturity improved.
- v0.2/readiness: 76-80%. The release-critical path is still blocked more by
  live external integration evidence than by local build quality.
- Core daemon / CLI / memory / WAL: 90-92%.
- Providers / model management: 89-92%.
- MCP / tooling / security: 87-90%.
- Council / hemispheres: 81-85%.
- Channels: 79-83%.
- WASM/plugin/migration surface: 55-65%. It moved from stub into real parser /
  discovery / feature-gated engine scaffolding, but hostcalls and full runtime
  execution remain open.
- GUI / installer / release polish: 70-76%. Settings panel work improves the
  GUI read, but the broader release/distribution story still has open edges.
- Verification confidence: 9.4/10 locally. The shell now proves fmt, Clippy,
  and a larger workspace test suite green. Remaining confidence gap: live
  provider/council/channel e2e plus CI/artifact install proof.

## 2026-05-19 20:29 active-coding recheck

Current `PROGRESS.md` math with strict checklist-row parsing:

- Total tracked boxes: 728.
- Done: 512.
- Open: 203.
- In progress: 4.
- Blocked: 1.
- Deferred: 8.
- Raw completion: 512 / 728 = 70.3%.
- Pre-master implementation/history section: 340 / 417 = 81.5%.
- Master open checklist: 23 / 116 = 19.8%.
- Production roadmap section: 25 / 44 = 56.8%.
- Post-roadmap session additions: 124 / 151 = 82.1%.

Fresh movement since the 17:32 recheck:

- Formal checklist completion did not move: done stayed at 512 and total stayed
  at 728.
- Code/test surface did move: static source test-attribute count grew from 2202
  to 2278.
- Workspace tests grew from 2186 passed to 2222 passed.
- New tested areas visible in the run include:
  - `neoth-migrate` readers: Faiss flat + SQLite reader coverage, still keeping
    Lance/Git as explicit unimplemented statuses.
  - Discord Gateway receive prep: heartbeat, identify, resume, reconnect
    backoff, opcode/envelope classification.
  - WASM/plugin runtime surface: hostcall WAL audit payloads, plugin event-code
    registry, `try_append_sync` writer path.
  - Plugin discovery/manifest tests remain green after the new hostcall work.

Verification for this snapshot:

- Initial `cargo fmt --all -- --check`: FAIL, mechanical formatting deltas in
  `channels/discord_gateway.rs`, `wal/events.rs`, `wal/writer.rs`, and
  `wasm_plugin/hostcalls.rs`.
- Local fix applied: ran `cargo fmt --all`; no semantic change.
- Final `cargo fmt --all -- --check`: PASS.
- Final `.\scripts\cargo-msvc.ps1 clippy --workspace --all-targets -D warnings`:
  PASS.
- Final `.\scripts\cargo-msvc.ps1 test --workspace`: PASS. Result: 2222
  passed, 0 failed, 3 ignored. Breakdown: `neoth-migrate` 17/17, plugin SDK
  10/10, `neothd` 2179 passed / 2 ignored, multimodal smoke 7/7,
  no-outbound-network 1/1, GUI 8/8, plugin SDK doctest ignored.

Current read:

- Overall NEOTH vision: 70.3% raw; 76-80% engineering judgement. The raw number
  is unchanged because `PROGRESS.md` boxes were not flipped, but maturity
  improved through deeper tests and runtime scaffolding.
- v0.2/readiness: 76-80%.
- Core daemon / CLI / memory / WAL: 90-92%.
- Providers / model management: 89-92%.
- MCP / tooling / security: 87-90%.
- Council / hemispheres: 81-85%.
- Channels: 80-84%; Discord Gateway is gaining real protocol mechanics, though
  not full operational receive yet.
- WASM/plugin/migration surface: 62-70%; hostcall/WAL wiring and reader
  expansion make this materially stronger than the 17:32 snapshot, but full
  linker/runtime execution is still open.
- GUI / installer / release polish: 70-76%.
- Verification confidence: 9.5/10 locally. The remaining gap is almost entirely
  live external integration and CI/artifact install proof.

## 2026-05-20 09:05 active-coding recheck

Current `PROGRESS.md` math with strict checklist-row parsing:

- Total tracked boxes: 728.
- Done: 512.
- Open: 203.
- In progress: 4.
- Blocked: 1.
- Deferred: 8.
- Raw completion: 512 / 728 = 70.3%.
- Pre-master implementation/history section: 340 / 417 = 81.5%.
- Master open checklist: 23 / 116 = 19.8%.
- Production roadmap section: 25 / 44 = 56.8%.
- Post-roadmap session additions: 124 / 151 = 82.1%.

Fresh movement since the 20:29 recheck:

- Formal checklist completion did not move: done stayed at 512 and total stayed
  at 728.
- Code/test surface moved substantially: static source test-attribute count
  grew from 2278 to 2403.
- Workspace tests grew from 2222 passed to 2341 passed.
- New tested areas visible in source + test output include:
  - Coding/Kanban operator flow: `neoth code`, `neoth kanban`, session/task
    store, feed parsing, review auto-promotion, task decomposition and
    heuristic hemisphere classification.
  - WAL coding-band events: kanban event-code uniqueness and immediate-sync
    tests.
  - `neoth-migrate` reader coverage remains expanded: Faiss-flat and SQLite
    readers are now in the green test run.
  - WASM/plugin hostcall and discovery/manifest tests remain green under the
    larger workspace.

Verification for this snapshot:

- Initial `cargo fmt --all -- --check`: FAIL, mechanical formatting deltas
  across new `cli/code.rs`, `cli/kanban.rs`, `coding/*`,
  `wasm_plugin/hostcalls.rs`, and related touched files.
- Local fix applied: ran `cargo fmt --all`; no semantic change.
- Final `cargo fmt --all -- --check`: PASS.
- Final `.\scripts\cargo-msvc.ps1 clippy --workspace --all-targets -D warnings`:
  PASS.
- Final `.\scripts\cargo-msvc.ps1 test --workspace`: PASS. Result: 2341
  passed, 0 failed, 3 ignored. Breakdown: `neoth-migrate` 17/17, plugin SDK
  10/10, `neothd` 2298 passed / 2 ignored, multimodal smoke 7/7,
  no-outbound-network 1/1, GUI 8/8, plugin SDK doctest ignored.

Current read:

- Overall NEOTH vision: 70.3% raw; 77-81% engineering judgement. The raw number
  is unchanged because `PROGRESS.md` boxes were not flipped, but implementation
  maturity improved again.
- v0.2/readiness: 76-80%.
- Core daemon / CLI / memory / WAL: 91-93%.
- Providers / model management: 89-92%.
- MCP / tooling / security: 87-90%.
- Council / hemispheres: 81-85%.
- Channels: 80-84%.
- Coding/Kanban subsystem: 55-65%. It now has real schema/store/feed/review
  test coverage and CLI surfaces, but still needs more live agent execution
  proof before being treated as production-grade.
- WASM/plugin/migration surface: 63-71%.
- GUI / installer / release polish: 70-76%.
- Verification confidence: 9.5/10 locally. Remaining confidence gap is live
  external e2e, CI/artifact install proof, and production soak.
