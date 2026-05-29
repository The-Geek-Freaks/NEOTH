# NEOTH Threat Model

**Last updated:** 2026-05-29 (DOC-03 — road-to-v1.0 surface expansion)
**Audience:** operators running NEOTH on a personal machine,
security reviewers, and anyone reasoning about what NEOTH can and
cannot do over the network or with local files.

This document is the operator-readable counterpart to
[`SECURITY.md`](../../SECURITY.md). It maps every NEOTH outbound
surface, names the consent gate that protects it, and shows how to
verify the audit trail. If you find a gap that contradicts what is
written here, report it via the [SECURITY.md disclosure
flow](../../SECURITY.md).

## TL;DR

NEOTH talks to the network through **thirteen controlled surfaces**.
Every surface honours your `autonomy` setting in `freedom.yaml`,
emits a WAL audit frame, and runs through the SSRF guard for any
URL the operator hands it. Beyond the original six (web_fetch,
provider APIs, n8n loopback, HuggingFace downloads, cluster gossip,
Obsidian sync) the map now also covers the search APIs (web_search,
arXiv), cloud TTS, the self-updater, the Discord channel, the Pears
localhost bridge, and the (scaffold-only) Gmail surface. Local file
IO goes only to `~/.neoth/`, your Obsidian vault (if you opted in),
and the WAL + SQLite views database.

## 1. The 13 outbound surfaces

| # | Surface | Code module | Where it goes | Status |
|---|---|---|---|---|
| 1 | `web_fetch` | `tools/web_fetch.rs` | Any operator-supplied URL | SX-01 SSRF-guarded |
| 2 | Provider API calls | `providers/*.rs` | Cloud LLM endpoints (OpenAI, Anthropic via CLI, Gemini, Azure, AWS Bedrock) | Consent + autonomy gate; circuit-broken |
| 3 | n8n localhost API | `n8n/api_client.rs` | `http://127.0.0.1:5678` only | Loopback-only by construction |
| 4 | Hugging Face downloads | `providers/local_qwen.rs`, `clip_engine.rs`, `whisper.rs`, `ouro/adapter.rs`, `cli/models.rs` | `huggingface.co` model weights | One-time per model; **HF-01 consent gate shipped** (`updater.allow_huggingface_downloads`) + `0xD7/0xD8` audit |
| 5 | Cluster gossip | `cluster/*` | Operator-confirmed peers only | mTLS + per-peer confirmation; defer-mesh (Phase 5) |
| 6 | Obsidian sync | `obsidian/*` | Local filesystem ONLY (operator's vault path) | No network |
| 7 | Web search | `tools/web_search.rs` | `api.search.brave.com` / `api.tavily.com` | Fixed cloud endpoint; operator API key; autonomy gate |
| 8 | arXiv search | `tools/arxiv.rs` | `export.arxiv.org/api/query` | Anonymous, read-only, fixed endpoint (no key) |
| 9 | Cloud TTS | `tools/tts.rs` | `api.elevenlabs.io` | Cloud TTS; operator API key; opt-in |
| 10 | Self-updater | `updater/self_update.rs` | `api.github.com` releases + GitHub CDN | SHA-256 **integrity**-checked (NOT signature-verified — see §1.10); operator-initiated apply only |
| 11 | Discord channel | `channels/discord.rs` | `discord.com/api` | Send-only; operator bot token; CHANNEL_EGRESS audit |
| 12 | Pears bridge | `channels/pears_bridge.rs` | `127.0.0.1` localhost only | Localhost-only by construction; per-session token |
| 13 | Gmail (scaffold) | `email/gmail.rs` | `accounts.google.com` + `imap.gmail.com` | **Not network-live** — scaffold only; consent gate planned (EM-01b) |

### 1.1 `web_fetch` (SX-01 guarded)

`tools/web_fetch.rs::fetch(url)` is the only path that takes an
operator-supplied URL and opens an HTTP connection. After the
v0.2.1 hotfix (SX-01), the call:

1. Parses the URL via `url::Url::parse` — rejects malformed input
   AND every scheme that is not `http` or `https`. `file://`,
   `gopher://`, `dict://`, `javascript:`, `data:`, `ftp://` all
   fail at parse time.
2. Checks the hostname against a literal blocklist that catches
   cloud-metadata names even on misconfigured DNS:
   `metadata.google.internal`, `metadata.azure.internal`, the
   literal `169.254.169.254`, and the bare `metadata`.
3. Resolves every IP via `tokio::net::lookup_host` and rejects
   the request if ANY resolved IP falls in: loopback, RFC-1918,
   RFC-3927 link-local (`169.254/16`, covers AWS/GCP/Azure
   metadata), RFC-4193 IPv6 unique-local (`fc00::/7`),
   `fe80::/10` IPv6 link-local, RFC-6598 CGNAT (`100.64/10`),
   RFC-2544 benchmarking (`198.18/15`), `0.0.0.0`, broadcast,
   documentation ranges, or multicast.
4. Closes the IPv4-mapped IPv6 bypass — `::ffff:127.0.0.1` is
   unwrapped and re-validated as if the embedded `127.0.0.1` had
   been written directly.
5. Disables HTTP redirects (`reqwest::redirect::Policy::none()`).
   A public 302 cannot bounce the daemon into a private network
   after the initial validation passed. Operators who need
   redirects see the 3xx + Location header and call `fetch`
   again — each call re-validates from scratch.

### 1.2 Provider API calls

Each cloud provider lives in its own adapter under
`providers/*.rs` and routes through `providers/http_client.rs`
which honours `NEOTH_HTTP_PROXY` for Hysteria egress. After
v0.2.1 (GR-04), every `Provider::complete` call is wrapped in
`circuit_breaker::run_with_breaker(name, ...)` so a sustained
upstream outage produces a fast local error after the failure
threshold (default 5 consecutive failures / 30s cooldown).

Per-provider naming for breaker correlation:

| Provider | breaker id |
|---|---|
| OpenAI / OpenAI-compat | `openai_api` (or operator-configured `name`) |
| Gemini | `gemini_api` |
| Azure OpenAI | `azure_openai` |
| AWS Bedrock | `aws_bedrock` |
| Claude CLI bridge | `claude_cli` |
| Local Qwen (in-process) | `local_qwen` |
| Local Ouro (in-process) | `local_ouro` |

`Provider::stream` is NOT yet breaker-wrapped (a streaming
permit-holder needs a different RAII design; tracked as a v0.3
enhancement).

### 1.3 n8n localhost API

`n8n/api_client.rs` hits `http://127.0.0.1:5678` by construction.
The URL is built from a `host: "127.0.0.1"` constant plus the
operator-configured port — no operator-supplied URL ever reaches
this surface, so SSRF guarding is unnecessary. Local-only by
design (the `n8n` workflow engine runs on the same machine as
NEOTH).

### 1.4 Hugging Face model downloads

`providers/local_qwen.rs`, `clip_engine.rs`, `whisper.rs`, and
`ouro/adapter.rs` use the `hf-hub` crate to download model
weights on first use. After the v0.2.1 hotfix (SX-05b),
`hf-hub` is pinned at `0.5.0` with `default-features = false,
features = ["tokio", "rustls-tls"]` — `openssl-sys` is gone from
the dependency graph entirely (was a banned transitive via the
0.3.x `native-tls` path).

**HF-01 shipped (2026-05-29):** `cli/models.rs::run_pull` reads
`freedom.yaml::updater.allow_huggingface_downloads` (default `true`)
BEFORE any fetch and refuses the download when it's `false`
(air-gapped / bandwidth-controlled installs). A permitted download
emits `0xD7 MODEL_DOWNLOAD_START` before + `0xD8
MODEL_DOWNLOAD_COMPLETE` after, so exactly-what-was-fetched-when is
in the audit chain. The **implicit** first-use download (a
local-inference provider — `local_qwen` / `local_ouro` — that doesn't
find its weights in cache) ALSO honours the gate as of 2026-05-29:
`ensure_artifacts` reads `allow_huggingface_downloads` before any fetch
and bails with an actionable error when it's `false`, so an air-gapped
/ bandwidth-capped operator never triggers a silent ~3 GB download.
(Audit caveat: the implicit path does not yet emit `0xD7/0xD8` — it has
no WAL writer handle in scope; the explicit `neoth model pull` path
does. Wiring the implicit-path audit frame is a tracked follow-up.)

### 1.5 Cluster gossip

`cluster/*` only talks to peers the operator has explicitly
confirmed (Phase 5 design: `cluster.confirmed_peers` in
`freedom.yaml`). mTLS for the gossip channel, per-peer Bloom
filter for replay protection, `do_not_gossip` tag for
permanent-private events. Defer-mesh (Phase 6, Q4) lets a peer
queue gossip while offline; replay capped at 30 days. Not yet
shipped — gated behind `freedom.yaml::cluster.enabled = true`
which is off by default.

### 1.6 Obsidian sync

`obsidian/*` writes to the operator's local vault path only —
typically `~/Documents/NEOTH-Vault/` (or wherever the wizard
bootstrap chose). Pure local file IO via `tokio::fs`. NO network.
The integration is one-directional: NEOTH writes notes the
operator can then sync via whatever Obsidian sync service they
already use (Obsidian Sync, Syncthing, git, iCloud Drive).

### 1.7 Web search (`tools/web_search.rs`)

Brave (`api.search.brave.com`) / Tavily (`api.tavily.com`) — FIXED
provider endpoints, not operator-supplied URLs, so SSRF guarding is
N/A. Requires the operator's API key; autonomy-gated like any cloud
call. Read-only query API.

### 1.8 arXiv search (`tools/arxiv.rs`)

`http://export.arxiv.org/api/query` — a fixed, anonymous,
read-only public XML API (`ARXIV_API_URL` constant, no API key).
No operator-supplied URL, no credentials, no write path.

### 1.9 Cloud TTS (`tools/tts.rs`)

`https://api.elevenlabs.io/v1/text-to-speech/...` — fixed endpoint,
operator API key (`--api-key` / `NEOTH_TTS_KEY`), opt-in. Sends the
text to synthesise; returns audio bytes. No operator-supplied URL.

### 1.10 Self-updater (`updater/self_update.rs`)

`api.github.com` releases + the GitHub release CDN. Downloaded
artifacts are **SHA-256 integrity-checked** against the published
companion hash before any swap. **This is a corruption/integrity check,
NOT an authenticity control** — the hash and the binary come from the
same GitHub release, so an attacker who compromises the release (or the
account, or MITMs the CDN) controls both. There is no cryptographic
signature today (no minisign/cosign/Sigstore). Because of that, the
APPLY step is **operator-initiated only** (`neoth update --self --apply`,
emits `0xD2`) — the daemon does NOT auto-apply its own binary
unattended. A senior-dev panel (2026-05-29) blocked unattended
self-replace pending: (1) ✅ `Action::SelfBinaryReplace` permission gate
(Confirm even at Full) — SHIPPED; (2) signature verification before the
swap via `minisign-verify` (pure-Rust, fits the no-ring/no-openssl
posture; the `sigstore` crate was probed + rejected for pulling
native-tls/ring/prost) — wiring it into `apply_downloaded` + a minisign
signing step in CI is the open item; (3) a
daemon-path WAL emit that survives the single-writer guard — open
(lands with the unattended task); (4) a richer `0xD2` payload —
`archive_sha256` + `download_url` + `trigger_source` (manual/auto)
SHIPPED; extracted-binary SHA + signature-verification-result still
pending. The
check itself is read-only release-metadata.

### 1.11 Discord channel (`channels/discord.rs`)

`discord.com/api` — SEND-only outbound from the operator's bot
token. Inbound is gateway-driven, not an outbound surface. Every
send is audited via `CHANNEL_EGRESS` (`0x33`).

### 1.12 Pears bridge (`channels/pears_bridge.rs`)

Localhost-only by construction (`127.0.0.1`) — a per-session
bearer-token bridge to a co-located Pears/Keet process. No
public-network egress; same trust class as the n8n loopback.

### 1.13 Gmail (`email/gmail.rs`) — scaffold only

`accounts.google.com` OAuth + `imap.gmail.com:993`. **NOT
network-live** — the module is a scaffold (EM-01b); no live OAuth /
IMAP path ships today. A consent gate is planned before it goes
live. Listed here so the surface is mapped before it activates.

## 2. Consent gates per `AutonomyLevel`

`freedom.yaml::autonomy` sets the default trust level. The
permission engine (`permissions::evaluate(action, level)`)
consults this on every outbound surface.

| Action class | `strict` | `standard` | `elevated` | `full` |
|---|---|---|---|---|
| Read local files in `~/.neoth/` | ✅ | ✅ | ✅ | ✅ |
| Write local files in `~/.neoth/` | confirm | ✅ | ✅ | ✅ |
| Read local files outside `~/.neoth/` | confirm | confirm | ✅ | ✅ |
| Write local files outside `~/.neoth/` | confirm | confirm | confirm | ✅ |
| Shell command inside `~/.neoth/` | confirm | confirm | ✅ | ✅ |
| Shell command outside `~/.neoth/` | confirm | confirm | confirm | ✅ |
| `web_fetch` (public URL) | confirm | ✅ | ✅ | ✅ |
| Provider API call (cloud) | confirm | ✅ | ✅ | ✅ |
| Provider API call (local in-process) | ✅ | ✅ | ✅ | ✅ |
| n8n localhost call | ✅ | ✅ | ✅ | ✅ |
| Web search (Brave/Tavily) | confirm | ✅ | ✅ | ✅ |
| arXiv search (anonymous) | confirm | ✅ | ✅ | ✅ |
| Cloud TTS (ElevenLabs) | confirm | ✅ | ✅ | ✅ |
| Discord send | confirm | ✅ | ✅ | ✅ |
| Self-update apply | confirm | confirm | confirm | confirm |
| HF model download | gated by `updater.allow_huggingface_downloads` (HF-01 shipped) — config boolean, not per-autonomy | | | |
| Cluster gossip emit | per-peer confirm | per-peer confirm | per-peer confirm | per-peer confirm |
| Profile-claim apply | confirm | confirm | confirm | ✅ |

**`custom`** defers to per-action rules in
`~/.neoth/policy.yaml`. Operators who need a column not covered
above pick `custom` and write the policy explicitly.

"confirm" means NEOTH prompts the operator via the active
channel (CLI, GUI, Telegram inline buttons) and refuses the
action on timeout / decline.

## 3. Audit trail coverage

Every outbound surface emits a typed WAL frame. Operators verify
with `neoth wal show --type <name>` or via the typed event-code
constants in `wal::events`:

| Surface | WAL event | Code | How to inspect |
|---|---|---|---|
| `web_fetch` (success) | `PROVIDER_REQUEST` + `PROVIDER_RESPONSE` | `0x20`, `0x21` | `neoth wal show --type provider_request` |
| `web_fetch` (SSRF reject) | `PROVIDER_ERROR` + `tracing::warn!` | `0x22` | `NEOTH_LOG_LEVEL=warn neoth serve` |
| Provider call (success) | `PROVIDER_REQUEST` + `PROVIDER_RESPONSE` | `0x20`, `0x21` | as above |
| Provider call (circuit open) | `PROVIDER_ERROR` | `0x22` | as above |
| Provider call (429 quota) | `PROVIDER_QUOTA_EXCEEDED` | `0x24` | `neoth wal show --type provider_quota_exceeded` |
| HF model download (start/done) | `MODEL_DOWNLOAD_START` / `MODEL_DOWNLOAD_COMPLETE` | `0xD7`, `0xD8` | `neoth wal show --type model_download_start` (HF-01) |
| Channel inbound (Telegram, etc.) | `CHANNEL_INGRESS` | `0x32` | `neoth wal show --type channel_ingress` |
| Channel outbound | `CHANNEL_EGRESS` | `0x33` | as above |
| Inbound sanitised | `INGRESS_SANITIZED` | `0x36` | `neoth wal show --type ingress_sanitized` |
| Inbound quarantined | `INGRESS_QUARANTINED` | `0x35` | as above |
| WAL crash recovery (torn) | `RECOVERY_TRUNCATED` | `0x50` | `neoth wal show --type recovery_truncated` |
| WAL `.cpt` auth failure | `COMPACTION_AUTH_FAILED` | `0x51` | `neoth wal show --type compaction_auth_failed` (ADV-01) |
| Plugin hostcall | `PLUGIN_HOSTCALL` | `0xC4` | `neoth wal show --type plugin_hostcall` |
| Permission grant | `PERMISSION_GRANTED` | `0xA0` | `neoth wal show --type permission_granted` |
| Permission deny | `PERMISSION_DENIED` | `0xA1` | as above |
| Pre-mutation snapshot | `PRE_MUTATION_SNAPSHOT` | `0xF2` | `neoth wal show --type pre_mutation_snapshot` |
| Tombstone request | `TOMBSTONE_REQUESTED` | `0xF1` | as above |

For the full event taxonomy see
`SRC/neothd/src/wal/events.rs`. Operators reading the audit
trail with `neoth wal show --tail N` see every outbound action in
chronological order with the per-event payload.

## 4. Known limitations

### 4.1 `chrome-devtools-mcp` telemetry

The optional `chrome-devtools-mcp` MCP server (operator opt-in
via `freedom.yaml::mcp.chrome_devtools.enabled`) phones home to
Google for usage telemetry by default. NEOTH refuses to launch
it without `CHROME_TELEMETRY_DISABLED=1` set in the operator's
environment. Workaround: the wizard sets the env var
automatically when the operator opts in.

### 4.2 Windows DPAPI master-key disaster recovery

On Windows, the WAL HMAC key (`~/.neoth/wal/hmac.key`) is wrapped
with DPAPI bound to the current Windows user account
(K-Sec-4). If the operator's Windows user account is destroyed
(disk failure + no profile backup, malicious uninstall), the
wrapped key cannot be decrypted on the new account — the
existing WAL audit chain becomes unreadable.

Workaround: operators on Windows should back up
`~/.neoth/wal/hmac.key` to a USB stick or other off-machine
medium AFTER the first daemon launch generates it. Disaster-
recovery export tooling (`neoth keys export-recovery-bundle`) is
tracked as HIGH-02 in the v1.0 SC-09 lane.

### 4.3 Streaming providers + circuit breaker

`Provider::stream` calls for `claude_cli`, `local_qwen`, and
`ouro/adapter` are NOT wrapped by the v0.2.1 GR-04 circuit
breaker. A streaming permit-holder needs a different RAII design
(the permit must outlive the stream's lazy iteration). Tracked
as a v0.3 enhancement. Synchronous `Provider::complete` is
covered for every provider.

### 4.4 Profile-extraction prompt-injection corpus

The v0.2.1 ADV-03 hotfix wraps profile claims in
`<profile_claim>` XML with an instruction header AND
short-circuits extraction when the input contains quoted-reply
markers (`>`, `>>>`, ``` ``` ```, `</`, `wrote:`, `From:`,
`-----BEGIN`). Both defences are unit-tested. The 30+ JSON
fixture corpus at `eval/prompt_injection_corpus/profile_block_b/`
(multilingual / role-hijack / recursive-prompt / encoded
payloads) is regression coverage that bolts on top of the
defence — tracked as a v0.3 follow-up. The actual defence ships
today.

### 4.5 Cross-binary parallel-test env-mutation race

Internal note for contributors: tests in `cli/init.rs`,
`cli/qwen_weights.rs`, `cli/models.rs`, `cli/slack.rs`,
`cli/cloud.rs`, and `cli/code_map.rs` mutate the global `HOME`
and `USERPROFILE` env vars. The within-`init.rs` race is fixed
by a static `Mutex<()>` in the test module (commit `396c065`).
The cross-binary race (when two cargo-test binaries that touch
env vars run concurrently) is tracked as a v0.3 test-isolation
cleanup. Not a runtime safety issue — only affects the test
suite when run in parallel.

## 5. Reporting a vulnerability

See [`SECURITY.md`](../../SECURITY.md) in the repository root for
the disclosure flow. Tl;dr: **do not open a public GitHub
issue**; send a private report via GitHub Security Advisories
(`https://github.com/The-Geek-Freaks/NEOTH/security/advisories/new`).

A 90-day disclosure window applies. Critical issues (RCE,
arbitrary file read, credential exfiltration) get a 14-day
embargo + a coordinated v0.X.Y hotfix.

## Appendix A — v0.2.1 hotfix audit findings closed

This document reflects the surface after these v0.2.1 commits
landed:

| Commit | Item | Finding closed |
|---|---|---|
| `bc6c796` | SX-04 | CI `cargo audit` silently swallowing CVEs (`|| true`) |
| `20bcfa9` | SX-05 + SX-05b | cargo-deny gate silent-red; openssl-sys eliminated via hf-hub 0.5 rustls-tls |
| `9cf1473` | SX-01 | `web_fetch` SSRF — string-prefix scheme check + no DNS pre-resolve |
| `2211374` | SX-02 | `wal::snapshot::ChannelSend` not redacted; pasted credentials persisted in WAL |
| `72a87c3` | SX-03 | `wasm_plugin/hostcalls.rs` raw plugin bytes to `tracing::info!` |
| `03ee232` | ADV-01 | `.cpt` crash-recovery had no HMAC auth; built per SPEC §4.3 |
| `6c035c9` | ADV-02 + ADV-11 | ADV-02 already shipped (writer never adopted MmapMut); ADV-11 MSVC enforcement in CI |
| `33b97fa` | ADV-03 | Profile Block-B injection — XML boundary + quoted-content extract filter |
| `5d4b44c` | GR-13 | Verified `write_config` mode-before-open + SecretString mlock |
| `2e8b030` | GR-12 H-2 | Autonomy ComboBox visual-state desync on wizard re-entry |
| `e1e9620` | GR-04 | Circuit breaker wired into all 7 `Provider::complete` sites |

## Appendix B — out-of-scope (operator-blocked or v0.3+)

| Item | Reason | Lane |
|---|---|---|
| GR-01 (WhatsApp `LIVE` label) | Operator pick A (rename) vs B (webhook send) | v0.2.1 blocked on operator decision |
| GR-02 (channel flapping) | Operator pick A vs B | v0.2.1 blocked on operator decision |
| ADV-03 item 4 (`require_approval` flip) | Field does not exist; full approval workflow is a v0.3 net-new feature | v0.3 |
| ADV-03 item 5 (30-fixture eval corpus) | Regression coverage; the defence ships now | v0.3 |
| `Provider::stream` circuit breaker | RAII permit-holder design needed | v0.3 |
| Cross-binary env-mutation lock | Test-isolation cleanup | v0.3 |
| HNSW search ranking determinism | Sort-tie nondeterminism | v0.3 |
