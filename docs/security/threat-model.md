# NEOTH Threat Model

**Last updated:** 2026-07-14 (release, channel, IMAP, cluster, and TTS live-path correction)
**Audience:** operators running NEOTH on a personal machine,
security reviewers, and anyone reasoning about what NEOTH can and
cannot do over the network or with local files.

This document is the operator-readable counterpart to
[`SECURITY.md`](../../SECURITY.md). It maps core high-risk NEOTH I/O and
network surfaces, names the gate that protects each mapped path, and
shows the available audit trail. Integration-specific egress is also
documented in the corresponding channel and integration guides; this
is not a claim that the table below inventories every optional adapter.
If you find a gap that contradicts what is
written here, report it via the [SECURITY.md disclosure
flow](../../SECURITY.md).

## TL;DR

This document enumerates **twelve core I/O and network-surface groups**. Their controls are
not identical: operator-supplied HTTP URLs use the SSRF guard, policy-gated
actions use the permission engine, and explicitly configured background
integrations use their own default-off switches. WAL coverage and exceptions
are stated per surface below. Beyond the original six (web_fetch,
provider APIs, n8n loopback, HuggingFace downloads, cluster gossip,
Obsidian sync) the map now also covers the search APIs (web_search,
arXiv), cloud TTS, the self-updater, the Discord channel, and the
(build-feature-gated, default-off) IMAP email surface. The mapped services
primarily persist under `~/.neoth/`, an opted-in Obsidian vault, and the WAL +
SQLite views database. Operator-directed file, coding, backup, export, ingest,
and TTS commands can also read or write the explicit paths supplied to those
commands, under their documented command-specific gates.

## 1. The 12 mapped I/O and network surfaces

| # | Surface | Code module | Where it goes | Status |
|---|---|---|---|---|
| 1 | `web_fetch` | `tools/web_fetch.rs`, `cli/fetch.rs` | Any operator-supplied public HTTP(S) URL | SX-01 SSRF-guarded and no-redirect; explicit CLI/tool invocation; rejection is log-only and the fetch has no dedicated WAL event today |
| 2 | Provider API calls | `providers/*.rs` plus caller orchestration | Cloud LLM endpoints (OpenAI, Anthropic via CLI, Gemini, Azure, AWS Bedrock) | Governed callers apply consent/cost/autonomy authorization; adapters are circuit-broken; request/result WAL coverage is caller-specific |
| 3 | n8n localhost ingress API | `n8n_api/server.rs`, `n8n_api/handlers.rs` | Listens on `127.0.0.1:9744` by default | Default off; loopback-only bind + peer check; bearer-token scopes; bounded bodies; best-effort pre-dispatch `0x39` request audit |
| 4 | Hugging Face downloads | `providers/local_qwen.rs`, `clip_engine.rs`, `whisper.rs`, `ouro/adapter.rs`, `cli/models.rs` | `huggingface.co` model weights | **HF-01 config gate shipped** (`updater.allow_huggingface_downloads`); durable `0xD7/0xD8` transaction on explicit pull, best-effort audit on implicit Qwen/Ouro pull |
| 5 | Cluster gossip | `cluster/*` | Authenticated members of the operator's private cluster | Default peeroxide Noise transport or opt-in iroh QUIC; shared-cluster-key proof, default-deny event ACL, bounded replay/dedup, foreign-event persistence, consent-gated restore |
| 6 | Obsidian sync | `obsidian/*` | Local filesystem ONLY (operator's vault path) | No network |
| 7 | Web search | `tools/web_search.rs`, `cli/search.rs` | Fixed Brave/Tavily APIs or trusted operator-configured SearXNG | Explicit command; Brave/Tavily need an API key; no dedicated autonomy action or typed WAL event |
| 8 | arXiv search | `tools/arxiv.rs`, `cli/arxiv.rs` | `export.arxiv.org/api/query` | Explicit anonymous read-only command; current constant starts with HTTP and follows the service redirect to HTTPS; no dedicated autonomy action or typed WAL event |
| 9 | Text-to-speech | `media/tts_dispatch.rs`, `media/tts_cloud.rs`, `media/tts_provider.rs`, `cli/tts.rs` | Offline system/Piper engines; Microsoft Edge speech, ElevenLabs, Azure Speech, or an operator-configured ViitorVoice sidecar | Local by default; every non-local provider requires `media.cloud_tts_enabled`; credential requirements are provider-specific; metadata-only `0xCD` audit when a WAL sink is available |
| 10 | Self-updater | `updater/self_update.rs` | `api.github.com` releases + GitHub CDN | Bounded download/extraction + SHA-256 + **minisign signature and signed asset-name binding** (`updater/sig_verify.rs`, compile-time pinned pubkey) + stage-path confinement + transactional bundle rollback; explicit manual `--allow-unsigned` recovery only |
| 11 | Discord channel | `channels/discord.rs` | `discord.com/api` | REST send and read-only bot-identity probe; Gateway receive is a separate inbound path; operator bot token; CHANNEL_EGRESS audit on sends |
| 12 | Email / Gmail IMAP ingest | `email/imap_fetch.rs`, `cli/email.rs`, `daemon/email_ingest_cron.rs` | Configured IMAP/TLS server (Gmail default); `oauth2.googleapis.com` only when refreshing XOAUTH2 credentials | Network-live only in builds with `imap_fetch`; daemon poll default OFF; non-destructive fetch, local triage, fail-closed quarantine; no SMTP |

### 1.1 `web_fetch` (SX-01 guarded)

`tools/web_fetch.rs::fetch(url)` is the general-purpose path that takes an
operator-supplied fetch URL and opens an HTTP connection. Other deliberately
configured integrations can own fixed or trusted operator-configured endpoint
URLs; their narrower boundaries are documented separately. After the
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

The central external-HTTP chokepoint validates the URL, applies the
`ExternalHttpRequest` autonomy action for non-local destinations, writes a
mandatory intent frame before opening the network closure, and closes it with a
matching result frame. The URL/body are represented in audit by bindings rather
than plaintext. Public fetches remain SSRF-guarded and redirect-disabled.

### 1.2 Provider API calls

Each cloud provider lives in its own adapter under `providers/*.rs`. HTTP
adapters use `providers/http_client.rs`, which honours `NEOTH_HTTP_PROXY` for
Hysteria egress; the Claude CLI bridge is a governed subprocess path instead.
After
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

The providers with native streaming (`claude_cli`, `local_qwen`, and
`local_ouro`) route through `circuit_breaker_stream::run_stream_with_breaker`.
Its owned RAII permit spans lazy stream iteration: a terminal `done` chunk
records success, while construction errors, error chunks, exhaustion without
`done`, and premature consumer drop record failure. An open breaker fails
before the provider stream is constructed.

Provider transport adapters do not own a WAL writer. Request/response audit is
therefore caller-scoped: the main chat and n8n provider-call paths emit
`0x20/0x21/0x22`, while not every explicit CLI/tool caller emits those frames.
The permission/cost authorizer and circuit breaker do not by themselves imply
a provider request/result frame. Audit queries must be interpreted against the
calling surface, not as a complete count of every adapter invocation.

### 1.3 n8n localhost ingress API

This surface is an inbound NEOTH HTTP server, not an outbound client to n8n.
When `n8n_api.enabled: true`, `n8n_api/server.rs` binds only
`127.0.0.1:<port>` (default `9744`) and independently rejects non-loopback
peers. Every request requires either the operator master bearer token or a
PBKDF2-verified token carrying the exact endpoint scope; five consecutive auth
failures enter a 60-second cooldown. Bodies are capped at 256 KiB and an
`N8N_REQUEST` (`0x39`) frame is attempted before auth or business logic.

The provider-call endpoint additionally refuses cloud providers under Strict,
requires a recorded provider consent at every other autonomy level, resolves
and authorises the effective cost model, and fails closed if its pre-call WAL
intent cannot be persisted. This API can still trigger downstream outbound
provider/channel work, so loopback reachability alone is not its authorization
boundary.

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
(Audit caveat: the implicit Qwen/Ouro path currently emits best-effort
`0xD7/0xD8` frames through `daemon/model_download_audit.rs`, but skips them
when a live daemon owns the segment and does not abort the download when the
append fails. The explicit `neoth model pull` path instead uses the durable,
replayable `ModelDownloadAttempt` transaction and fails closed until `0xD7`
authorises network access. These guarantees are not yet equivalent.)

### 1.5 Cluster gossip

The cluster transport is dark unless all three activation inputs exist:
`cluster.enabled: true`, a public rendezvous name, and the secret cluster
passphrase. The default peeroxide/Hyperswarm carrier uses its authenticated
Noise static keys; the optional `cluster-iroh` carrier uses QUIC endpoint keys.
Both then require an asymmetric HMAC-SHA256 proof over the two transport
identities using the derived cluster key. A reachable peer that cannot prove
membership is rejected before its gossip frame is evaluated.

Gossip applies the same acceptance stack on both carriers:

1. A default-deny `(event_type, event_subtype)` ACL permits only reviewed
   non-secret event families. Raw text, provider, and channel frames require
   the explicit `cluster.gossip.replicate_raw_ingress` opt-in; permissions,
   profile, consent, topology, WAL-structure, unknown, and other sensitive
   families never gossip.
2. Vector-clock sequence checks, a per-origin high-water mark, and the bounded
   replay window reject duplicates, stale frames, and invalid ordering. The
   default replay budget is 30 days and is hard-capped at 90.
3. Accepted frames are persisted idempotently to `idx_foreign_events` before
   the receiver's in-memory dedup state advances. Both peeroxide and the live
   iroh daemon path use this persist-then-commit contract; after a persistence
   failure the receiver can still accept a later retransmission. The current
   sender ticks are best-effort and do not yet keep durable per-peer delivery
   cursors or acknowledgements, so that later retransmission is not guaranteed.
4. `neoth cluster events` / `export-foreign` expose the backup-at-rest without
   silently mixing it into local recall. `neoth cluster restore` can apply the
   supported same-origin frames with conflict checks, durable idempotency,
   `--dry-run`, and operator consent; cross-origin rows remain skipped.

Peer confirmation and capability leases additionally govern delegated cluster
tasks. Possession of the cluster key authenticates gossip membership; it does
not by itself grant arbitrary task execution.

### 1.6 Obsidian sync

`obsidian/*` writes to the operator's local vault path only —
typically `~/Documents/NEOTH-Vault/` (or wherever the wizard
bootstrap chose). Pure local file IO via `tokio::fs`. NO network.
The integration is one-directional: NEOTH writes notes the
operator can then sync via whatever Obsidian sync service they
already use (Obsidian Sync, Syncthing, git, iCloud Drive).

### 1.7 Web search (`tools/web_search.rs`)

Brave (`api.search.brave.com`) and Tavily (`api.tavily.com`) use fixed HTTPS
provider endpoints and require an operator API key. SearXNG is the keyless,
self-hosted option; its trusted base URL comes from `NEOTH_SEARXNG_URL` and
defaults to `http://127.0.0.1:8888`. The SearXNG client disables redirects but
does not run the configured base through the public-URL SSRF guard because
loopback/private deployment is intentional.

`neoth search` is an explicit operator command. Non-local Brave, Tavily, and
SearXNG requests use the same `ExternalHttpRequest` permission plus mandatory
intent/result audit boundary. A SearXNG endpoint whose resolved addresses are
all loopback/private/link-local is treated as local after DNS classification.

### 1.8 arXiv search (`tools/arxiv.rs`)

`tools::arxiv::ARXIV_API_URL` currently names
`http://export.arxiv.org/api/query`, a fixed anonymous read-only XML API with
no credentials or write path. The service redirects that URL to HTTPS and the
shared client follows it, but the initial query is still sent over cleartext
HTTP; direct HTTPS is supported and should replace the constant. Like search,
the explicit CLI command currently has no dedicated permission action or typed
WAL event.

### 1.9 Text-to-speech (`media/tts_*`, `cli/tts.rs`)

`neoth tts speak` and the deprecated `tools::tts` compatibility facade both
delegate to `media::tts_cloud::synthesize_to_file_at`. The clean-install
default is offline `system_native`; local Piper is also available and never
downloads model bytes from this path. Four providers are non-local and all
refuse before dispatch unless `media.cloud_tts_enabled: true`:

- `edge_tts` runs the local `edge-tts` executable, which sends text to
  Microsoft's online speech service. It needs no API key.
- `eleven_labs` posts text to the fixed ElevenLabs API and requires an
  ElevenLabs key.
- `azure_tts` posts SSML to the configured Azure region's fixed Speech endpoint
  and requires an Azure key plus region.
- `viitor_voice` posts the text and an operator-selected reference-audio file
  to `media.tts.viitor_endpoint`. This URL is an explicitly trusted,
  operator-configured self-hosted sidecar boundary; it is not run through the
  public-URL SSRF guard and may intentionally be loopback or private-LAN.

The first gate is the explicit default-off `media.cloud_tts_enabled` config
switch. Every non-local synthesis also evaluates `ExternalTtsSynthesis` and
requires an available permission-audit WAL before provider dispatch. Successful
synthesis emits metadata-only `0xCD TTS_SYNTHESIZED`: provider, input hash, and
byte counts, never spoken text. With `media.required_audit_for_cloud_media: true`, a non-local call
fails before dispatch when no WAL sink can be opened; an append failure after a
completed provider call is still logged rather than rolling back the remote
side effect.

### 1.10 Self-updater (`updater/self_update.rs`)

`api.github.com` releases + the GitHub release CDN. Each downloaded artifact
passes a bounded, version-bound verification pipeline before any binary swap:

1. **SHA-256 integrity** against the `<asset>.sha256` companion. A
   corruption/transport-tamper guard — necessary but not sufficient on
   its own (hash and binary share a release origin; an attacker who
   compromises the release controls both).

2. **minisign signature verification** (`updater/sig_verify.rs`) against
   a compile-time pinned ed25519 pubkey (`NEOTH_RELEASE_MINISIGN_PUBKEY`,
   `option_env!`-baked at release build). Reads a `<asset>.minisig`
   companion. Pure-Rust (`minisign-verify`), no `ring`/no-openssl/no
   native-tls — fits NEOTH's rustls-only posture. The `sigstore` crate
   was empirically probed + rejected for pulling tokio-native-tls /
   ring / prost.

3. **Signed asset identity** — the release tag, binary prefix, target triple,
   archive extension, and minisign trusted comment must all name the exact same
   `neoth-<tag>-<target>.<ext>` asset. This rejects replay of an older validly
   signed archive through a forged staged-version record.

4. **Resource and path confinement** — archive/checksum/signature downloads and
   extracted members are size-capped. Offline staged paths must be regular,
   non-symlink files in their exact stage slots; an untrusted `pending.json`
   cannot redirect reads or cleanup outside the stage directory.

5. **Bundle preflight + rollback** — every companion installed beside `neoth`
   must be present in the verified archive before mutation. Companions replace
   first, the public core last; any intermediate error restores prior binaries
   in reverse order.

`require_signature` rule:
- **Manual path** (`neoth update --self --apply`, `require=true` by default) —
  requires `Verified`. The explicit `--allow-unsigned` trusted-recovery flag
  sets `require=false`; a *present-but-invalid* signature **always bails**.
- **Unattended path** (`daemon/auto_update::spawn_self_stage`,
  `require=true`) — hard-bails any non-`Verified` status. Combined with
  the `Action::SelfBinaryReplace` Confirm-at-every-level gate, this
  means daemon-initiated self-replace requires BOTH a verified signature
  AND a TTY confirm — the daemon has no TTY, so the unattended path
  stage-only stages + drops a notification sidecar; the operator runs
  the manual apply to confirm + swap.

Public-download **provenance** (separate from self-update verify) is
provided by **cosign keyless** (Sigstore OIDC) — every release publishes
a `<asset>.cosign.bundle` next to the `.minisig`, anchored to the
GitHub Actions workflow identity. Operators downloading manually verify
provenance with `cosign verify-blob`; the daemon's self-update path
verifies authenticity with minisign.

**CI release contract:** the MAR-02 keypair must be provisioned as
`NEOTH_RELEASE_MINISIGN_SECRET` plus `NEOTH_RELEASE_MINISIGN_PUBKEY`. The
workflow fails before the build matrix when the public key is absent and fails
before publication when the secret is absent or mismatched. Every archive ships
a `.minisig`, checksum, cosign bundle, and public-key text file; the just-built
binary verifies each signature before release creation.

Other senior-dev-panel items are shipped: `Action::SelfBinaryReplace` is
Confirm-at-every-level; minisign verification covers apply, stage, and offline
re-apply; the daemon-owned staging path emits through its existing WAL writer;
and the `0xD2` payload carries archive SHA-256, download URL, trigger source,
and the actual re-verified signature result.

**Asset naming alignment:** the locator exactly matches the workflow's artifact
scheme (`neoth-<version>-<target>.<ext>`, `.tar.gz` Unix / `.zip` Windows) via
`find_matching_asset`; it is intentionally not prefix/version tolerant.

### 1.11 Discord channel (`channels/discord.rs`)

`discord.com/api` — outbound sends plus the explicit read-only
`GET /users/@me` probe used by `neoth channel test discord`. The probe validates
the configured bot identity without sending a message. Inbound delivery is
Gateway-WebSocket-driven and is therefore not an outbound REST surface. Every
send is audited via `CHANNEL_EGRESS` (`0x33`).

### 1.12 Email / Gmail IMAP ingest

The IMAP path is implemented and network-live when `neothd` is compiled with
the `imap_fetch` feature. That feature is source-build opt-in and is not part of
the current named release bundles. Transport is IMAP over rustls TLS; the
configured host/port defaults to `imap.gmail.com:993`. Authentication resolves
an operator-provided app password or exchanges configured Google OAuth refresh
credentials for XOAUTH2. The live refresh request goes to
`oauth2.googleapis.com/token`. `accounts.google.com` is only the authorization
URL produced by the separate OAuth setup primitive; the ingest loop does not
contact it.

`neoth email fetch` retrieves bounded UNSEEN messages with non-destructive
`BODY.PEEK[]`, deduplicates completed messages, parses MIME, and sends the body
through the sanitizer, prompt-injection gate, phishing triage, and optional
borderline tie-breaker. The CLI path emits `EMAIL_INGRESS_TRIAGED` (`0x3D`),
`EMAIL_INGRESS_QUARANTINED` (`0x30`) when applicable, and
`EMAIL_TIEBREAK_APPLIED` (`0x31`) when the second opinion runs.

The daemon poller is separately controlled by
`freedom.yaml::email_ingest_cron.enabled` and defaults to `false` (five-minute
default interval, clamped to at least 30 seconds). Each tick uses the same IMAP
fetch and triage path. Quarantine/dropped mail is persisted under
`~/.neoth/paperless_quarantine/`; review-queue mail is withheld for operator
review; only sanitized deliverable content proceeds to configured Obsidian and
Paperless sinks. Scanner and quarantine-write failures fail closed. The cron
currently logs its outcome but does not emit WAL frames, so operators must not
infer CLI audit coverage for the daemon path.

There is no SMTP client and no email-send path in this feature.

## 2. Consent gates per `AutonomyLevel`

`freedom.yaml::autonomy` selects an immutable policy snapshot. The
permission engine (`permissions::evaluate(action, &snapshot)`)
protects the action classes represented in that engine. Some mapped surfaces
instead use a dedicated explicit opt-in because they are operator-configured
integrations; those exceptions are named in the table rather than being
presented as permission prompts.

| Action class | `strict` | `standard` | `elevated` | `full` |
|---|---|---|---|---|
| Read local files in `~/.neoth/` | ✅ | ✅ | ✅ | ✅ |
| Write local files in `~/.neoth/` | confirm | ✅ | ✅ | ✅ |
| Read local files outside `~/.neoth/` | confirm | confirm | ✅ | ✅ |
| Write local files outside `~/.neoth/` | confirm | confirm | confirm | ✅ |
| Shell command inside `~/.neoth/` | confirm | confirm | ✅ | ✅ |
| Shell command outside `~/.neoth/` | confirm | confirm | confirm | ✅ |
| `web_fetch` / non-local HTTP | confirm | confirm | ✅ | ✅ |
| Provider API call (cloud) | confirm | ✅ | ✅ | ✅ |
| Provider API call (local in-process) | ✅ | ✅ | ✅ | ✅ |
| n8n localhost ingress API | config opt-in + endpoint auth/gates | config opt-in + endpoint auth/gates | config opt-in + endpoint auth/gates | config opt-in + endpoint auth/gates |
| Web search / arXiv (non-local HTTP) | confirm | confirm | ✅ | ✅ |
| Non-local TTS (Edge, ElevenLabs, Azure, ViitorVoice) | config opt-in + confirm | config opt-in + confirm | config opt-in + ✅ | config opt-in + ✅ |
| Discord send | confirm | ✅ | ✅ | ✅ |
| IMAP fetch / daemon poll | requires `imap_fetch`; daemon additionally requires explicit `email_ingest_cron.enabled: true` | | | |
| Self-update apply | confirm | confirm | confirm | confirm |
| HF model download | gated by `updater.allow_huggingface_downloads` (HF-01 shipped) — config boolean, not per-autonomy | | | |
| Cluster gossip emit | per-peer confirm | per-peer confirm | per-peer confirm | per-peer confirm |
| Profile-claim apply | confirm | confirm | confirm | ✅ |

**`custom`** starts from the `standard` decision for every action without an
override. `freedom.yaml::custom_autonomy.overrides` maps the stable exhaustive
action names to `allow`, `confirm`, or `deny`. An override may tighten policy,
but cannot weaken a `full` confirm/deny decision; malformed paid-call estimates
also clamp an attempted allow to confirm. Unattended cron and automatic update
application remain blocked explicitly regardless of overrides. The runtime
uses immutable snapshots and reload-aware daemon leaves, so a successful config
reload affects the next decision without mutating one already in flight.
`~/.neoth/policy.yaml` remains a separate dangerous-target/pattern and startup
credential-scan file; it is not an autonomy decision table.

`config opt-in` means `media.cloud_tts_enabled: true` is required regardless
of autonomy. It is not equivalent to a one-shot confirmation and does not
consult `policy.yaml` today.

For n8n, `config opt-in` means `n8n_api.enabled: true`; bearer-token scope and
endpoint-specific cloud/provider gates remain mandatory after the listener is
enabled.

"confirm" means NEOTH prompts the operator via the active
channel (CLI, GUI, Telegram inline buttons) and refuses the
action on timeout / decline.

## 3. Audit trail coverage

Where a surface emits typed WAL frames, operators verify them with `neoth wal
show --type <name>` or via the event-code constants in `wal::events`.
`web_fetch` currently has structured rejection logs but no dedicated typed
fetch event. The default-off email-ingest cron likewise uses structured logs
and durable quarantine/seen state rather than WAL frames.

| Surface | WAL event | Code | How to inspect |
|---|---|---|---|
| `web_fetch` success | none (known gap) | — | command output only |
| `web_fetch` SSRF reject | none; structured warning | — | `NEOTH_LOG_LEVEL=warn neoth serve` for daemon callers; CLI error for direct calls |
| Web/arXiv search | none (known gap) | — | command output; local search analytics for web search only |
| n8n API request attempt | `N8N_REQUEST` | `0x39` | `neoth wal show --type n8n_request` |
| Main chat / n8n provider call (success) | `PROVIDER_REQUEST` + `PROVIDER_RESPONSE` | `0x20`, `0x21` | `neoth wal show --type provider_request` |
| Main chat / n8n provider call (error, including an open breaker where the caller records it) | `PROVIDER_ERROR` | `0x22` | `neoth wal show --type provider_error` |
| Main chat 429 quota handling | `PROVIDER_QUOTA_EXCEEDED` (best-effort append) | `0x24` | `neoth wal show --type provider_quota_exceeded` |
| HF model download (start/done) | `MODEL_DOWNLOAD_START` / `MODEL_DOWNLOAD_COMPLETE` | `0xD7`, `0xD8` | `neoth wal show --type model_download_start` (HF-01) |
| TTS synthesis (when a WAL sink is available) | `TTS_SYNTHESIZED` | `0xCD` | `neoth wal show --type tts_synthesized` |
| Channel inbound (Telegram, etc.) | `CHANNEL_INGRESS` | `0x32` | `neoth wal show --type channel_ingress` |
| Channel outbound | `CHANNEL_EGRESS` | `0x33` | as above |
| Inbound sanitised | `INGRESS_SANITIZED` | `0x36` | `neoth wal show --type ingress_sanitized` |
| Inbound quarantined | `INGRESS_QUARANTINED` | `0x35` | as above |
| Email CLI triage | `EMAIL_INGRESS_TRIAGED` / `EMAIL_INGRESS_QUARANTINED` / `EMAIL_TIEBREAK_APPLIED` | `0x3D`, `0x30`, `0x31` | `neoth wal show --type email_ingress_triaged` |
| Email daemon cron | none (known gap) | — | structured daemon logs + `~/.neoth/paperless_quarantine/` |
| WAL crash recovery (torn) | `RECOVERY_TRUNCATED` | `0x50` | `neoth wal show --type recovery_truncated` |
| WAL `.cpt` auth failure | `COMPACTION_AUTH_FAILED` | `0x51` | `neoth wal show --type compaction_auth_failed` (ADV-01) |
| Plugin hostcall | `PLUGIN_HOSTCALL` | `0xC4` | `neoth wal show --type plugin_hostcall` |
| Permission grant | `PERMISSION_GRANTED` | `0xA0` | `neoth wal show --type permission_granted` |
| Permission deny | `PERMISSION_DENIED` | `0xA1` | as above |
| Pre-mutation snapshot | `PRE_MUTATION_SNAPSHOT` | `0xF2` | `neoth wal show --type pre_mutation_snapshot` |
| Tombstone request | `TOMBSTONE_REQUESTED` | `0xF1` | as above |

For the full event taxonomy see
`SRC/neothd/src/wal/events.rs`. Operators reading the audit
trail with `neoth wal show --limit N` see the most recent matching frames,
newest first. The table above is authoritative about which mapped paths emit a
frame and which remain log-only or best-effort; the WAL is not claimed to cover
every outbound action.

## 4. Known limitations

### 4.1 `chrome-devtools-mcp` telemetry

The optional `chrome-devtools-mcp` entry in `mcp_servers.yaml` is
disabled by default, exact-pinned to `chrome-devtools-mcp@1.5.0`,
and forces both `CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS=1` and
`DO_NOT_TRACK=1` in the child. Its read/navigate allowlist excludes
interaction and JavaScript-evaluation tools, and the whole server
requires Elevated autonomy. Operators must explicitly enable it.

The exact top-level npm pin prevents silent tag/version drift; it is
not a transitive lockfile. npm and the package's transitive dependency
graph remain an upstream trust boundary. The central MCP launcher
validator rejects unpinned/tag/range launchers before process creation.

### 4.2 Windows DPAPI master-key disaster recovery

On Windows, the WAL HMAC key (`~/.neoth/wal/hmac.key`) is wrapped
with DPAPI bound to the current Windows user account
(K-Sec-4). If the operator's Windows user account is destroyed
(disk failure + no profile backup, malicious uninstall), the
wrapped key cannot be decrypted on the new account — the
existing WAL audit chain becomes unreadable.

The v1.0 recovery path is shipped. After first launch, operators export the
unwrapped key with `neoth security backup-hmac-key --output <path>` and keep
that mode-0600 plaintext file on encrypted off-machine media. After a machine,
Windows account, or DPAPI identity change, with the daemon stopped,
`neoth security rewrap-hmac-key --source <path>` binds the same bytes to the
new account and restores historical compaction-marker verification. The
wizard offers the backup step, and both commands fail closed on missing,
invalid, or unsafe inputs. See `PLAN/RUNBOOK_dpapi_hmac_recovery.md`.

### 4.3 Streaming providers + circuit breaker

`Provider::stream` calls for `claude_cli`, `local_qwen`, and
`ouro/adapter` use an owned RAII breaker permit that outlives the stream's
lazy iteration. The wrapper records success only on an explicit terminal
`done` chunk and records failure on construction failure, an error chunk,
exhaustion without `done`, or premature drop. Synchronous
`Provider::complete` remains covered for every provider.

### 4.4 Profile-extraction prompt-injection corpus

The v0.2.1 ADV-03 hotfix wraps profile claims in
`<profile_claim>` XML with an instruction header AND
short-circuits extraction when the input contains quoted-reply
markers (`>`, `>>>`, ``` ``` ```, `</`, `wrote:`, `From:`,
`-----BEGIN`). Both defences are unit-tested. The 30+ JSON
fixture corpus at `eval/prompt_injection_corpus/profile_block_b/`
(multilingual / role-hijack / recursive-prompt / encoded
payloads) ships as regression coverage in
`tests/prompt_injection_corpus_profile_block_b.rs`; every fixture is loaded and
checked against the profile-extraction boundary in the test suite.

### 4.5 Parallel-test environment isolation

Tests that mutate process-global environment variables (`HOME`,
`USERPROFILE`, `NEOTH_HOME`, provider flags, and similar) serialise through the
crate-wide poison-tolerant `crate::test_env::lock()`. This replaces the former
file-local mutexes that could race within the library test binary. Separate
Cargo test binaries are separate processes and therefore do not share a
process environment. Guards restore prior values before releasing the lock;
this is test-harness isolation, not a runtime security boundary.

### 4.6 Cluster delivery durability

Peeroxide and optional Iroh carriers use the same durable synchronization state
machine. Every destination has its own persisted cursor and exact pending wire
frame. Queue, send, disconnect, missing-ACK, WAL reconstruction, and database
errors leave that state unchanged; restart replays the identical bytes. The
receiver validates authenticated origin, protocol version, contiguous sequence,
WAL CRC, event ACL, content kind, and digest before transactionally committing
the receipt, foreign ledger, canonical materialization, conflicts, and inbound
high-water mark. Only then can it return an ACK bound to that peer, origin,
sequence, and content digest. Duplicate frames and ACKs are idempotent, gaps and
old protocol versions fail closed, and one peer cannot advance another peer's
cursor. Canonical memory and ground-truth snapshots exclude credentials,
permissions, consent, operator profiles, and provider secrets; raw/private event
replication remains an explicit opt-in. The complete operational and conflict
contract is documented in [Durable mesh synchronization](../mesh-sync.md).

### 4.7 ViitorVoice endpoint trust boundary

`media.tts.viitor_endpoint` is a trusted operator configuration value for a
self-hosted voice-cloning sidecar. Plain HTTP is accepted only on an explicit
loopback address. Private-LAN, mesh, and public endpoints must use HTTPS.
Loopback calls bypass proxy configuration and no ViitorVoice request follows a
redirect, so the selected reference-audio file and spoken text cannot be
bounced to another origin. The non-local TTS opt-in still applies.

### 4.8 Credential-bearing adapter transport

Signal, WhatsApp Graph, and CalDAV parse endpoints before constructing a
request. Remote endpoints require HTTPS. Signal and CalDAV accept HTTP only for
an exact loopback service; WhatsApp's HTTP loopback seam is compiled only into
unit tests and production Graph traffic is HTTPS-only. URL userinfo, base
queries, fragments, and identifier path injection are rejected. Remote HTTPS
uses the configured egress proxy without following redirects. Loopback traffic
uses a direct no-proxy, no-redirect client. Signal binds the validated origin
and that client in one typed value; WhatsApp and CalDAV construct the client
only after the same validation. This keeps bearer tokens, Basic credentials,
messages, calendar bodies, and task data off cleartext remote transports.

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

## Appendix B — v0.2.1 triage history

This table preserves the decisions made during the v0.2.1 audit; it is not the
current backlog. WhatsApp's governed webhook round-trip and the hash-bound WASM
approval workflow have since shipped and are marked accordingly.

| Item | Reason | Lane |
|---|---|---|
| GR-01 (WhatsApp `LIVE` label) | Closed after v0.2.1: signed inbound webhook, governed Graph API reply, dedup, and shutdown drain are wired in `serve_tasks` / `webhook_listener` | shipped |
| GR-02 (channel flapping) | Operator pick A vs B | v0.2.1 blocked on operator decision |
| ADV-03 item 4 (`require_approval` flip) | Closed after v0.2.1 without adding a boolean: activation is bound to exact permission, canonical manifest hash, and WASM hash; every hostcall enforces the derived grant | shipped |
| ADV-03 item 5 (30-fixture eval corpus) | Shipped as the profile Block-B and Paperless/OCR prompt-injection corpora | shipped |
| `Provider::stream` circuit breaker | Shipped with an owned RAII permit spanning lazy stream iteration | shipped |
| Cross-module env-mutation lock | Shipped as the crate-wide `test_env` guard; separate test binaries already have process-isolated environments | shipped |
| HNSW search ranking determinism | Shipped: similarity, timestamp, then stable row-id tie-break in brute-force and HNSW paths | shipped |
