# Configuration

NEOTH's normal path is the GUI/CLI wizard. Advanced users can edit config files directly.

## File overview

| File | Purpose |
| :-- | :-- |
| `~/.neoth/freedom.yaml` | Main provider, inference, autonomy, channel, media, memory, council, and runtime configuration. |
| `~/.neoth/credentials.yaml` | File-backed secrets when `secrets_backend: file` is selected. |
| `~/.neoth/policy.yaml` | Dangerous targets/patterns and optional startup credential-scan paths. |
| `~/.neoth/mcp_servers.yaml` | External MCP launchers, tool allowlists, and per-server autonomy floors. |
| `~/.neoth/tweaks.toml` | Optional UI/statusline/model/persona customisation. |
| `~/.neoth/plugins/` | Installed WASM plugins. |
| `~/.neoth/skills/` | Installed skills. |
| `~/.neoth/profile/communication.json` | Local, typed communication-preference state. It contains evidence hashes and estimates, not raw messages. |
| `~/.neoth/wal/` | Event log. Do not edit manually. |
| `~/.neoth/models/` | Local model cache. |

### Custom instance homes

`neoth serve --config /path/to/instance/freedom.yaml` treats the config file's
parent directory as that daemon instance's home. Its PID lock, rollback clock,
credentials and policy, `views.db`, WAL segments and HMAC/master keys, reload
sentinel, sidecars, plugins, skills, journals, and background-task state all
remain under `/path/to/instance/`. That includes cron's `jobs.yaml`, `hooks/`,
and `proactive_queue.json`: scheduled jobs cannot read hook policy from, or
queue delivery into, another instance. The daemon does not mix those files
with `~/.neoth`; a malformed persisted policy or recovery state stops startup
instead of silently falling back to the default instance.

## Wizard first

```bash
neoth gui
```

or:

```bash
neoth init
```

The wizard should be enough for normal users. Manual editing is for operators.
On a fresh CLI onboarding (including an Express preset), the wizard writes
`audit_rpc.enabled: true` so one-shot permission events can reach the
daemon-owned WAL. The stricter
`audit_rpc.required_for_oneshot_permission_events` switch remains `false`
unless the operator enables compliance fail-closed behavior. `neoth init
--force` preserves the existing `audit_rpc` block instead of resetting either
choice.

## `freedom.yaml`

Example:

```yaml
operator_id: alex
language_primary: en
language_code: en
role: developer

provider_kind: claude_cli
provider_model: claude-opus-4-7

autonomy: standard

profile:
  communication:
    enabled: true
    auto_apply_low_risk: true
    min_observations: 5
    min_distinct_sessions: 3
    min_confidence: 0.75
    passive_half_life_days: 30
    feedback_half_life_days: 90
    correction_half_life_days: 180
    full_auto_min_observations: 10
    full_auto_min_distinct_sessions: 5
    full_auto_min_confidence: 0.85
    max_evidence_per_dimension: 32
    prompt_export: accommodations_only
    cluster_sync: false

  learn_enabled: false
  learn_provider: local_qwen
  allow_cloud_fallback: false
  require_approval: true

inference:
  mode: single
  embedding_provider: local_qwen
  max_new_tokens: 256

media:
  cloud_stt_enabled: false
  cloud_tts_enabled: false
  cloud_vision_enabled: false
```

These keys match the deserialized schema. Channel credentials belong in the
credential store and should normally be written through `neoth channel add`,
not invented as nested `channels.*.enabled` booleans.

### Communication adaptation

`profile.communication` is separate from the optional LLM-backed fact
extractor controlled by `profile.learn_enabled`. Communication adaptation is
default-on, deterministic and local: it classifies an authenticated human turn
in memory, discards the text, and persists only bounded typed evidence,
content/event hashes and estimates. It never emits a medical diagnosis.

The eight dimensions are `directness`, `structure`, `ambiguity`,
`processing_load`, `context_amount`, `pace`, `clarification`, and
`correction_style`. Explicit settings outrank explicit corrections, response
feedback and passive observations. Passive preferences become active only
after the configured observation, distinct-session and confidence floors;
their weight decays according to the half-life settings. At the exact `full`
autonomy level, the stricter `full_auto_*` floors may make a stable low-risk
accommodation durable until the operator resets it. Other autonomy levels do
not get that promotion.

Provider disclosure is controlled by `prompt_export`:

| Value | Provider prompt content |
| :-- | :-- |
| `none` | No communication-profile prompt layer. Local learning may still continue. |
| `accommodations_only` | Default. Export concrete presentation instructions, never a neuro-context label. |
| `label_and_accommodations` | Permit a label only when the operator also declared that context with `--prompt-use label-and-accommodations`. Both switches are required. |

NEOTH does not infer autism, ADHD, neurodivergence, or another health label.
The only supported neuro-context is an explicit typed operator declaration:

```bash
neoth profile communication context declare neurodivergent
neoth profile communication context declare autistic
neoth profile communication context declare adhd
```

These commands default to accommodations-only use. A label can enter a
provider prompt only after the two independent opt-ins described above. Use
`neoth profile communication context clear` to revoke future use while retaining
the local declaration history. Use
`neoth memory erase-communication-profile` for a dry-run inventory and add
`--confirm` to erase the complete local operator communication subject with an
audited privacy operation. `neoth profile communication reset` remains the
lower-level profile control for the same subject.

Shared channel workspaces can contain additional pseudonymous subjects. Run
`neoth export --list-subjects` to inventory their exact handles, then use
`--subject <handle>` on export or erasure. Unknown/case-mismatched handles fail
closed. A selected-subject export contains only `communication_profile.json` in
an empty destination; it never copies operator memory or archives.

Inspect and control the effective state through the CLI:

```bash
neoth profile communication status
neoth profile communication show
neoth profile communication why directness
neoth profile communication set structure numbered-steps
neoth profile communication reset structure
neoth profile communication prompt-export accommodations-only
neoth profile communication disable
neoth profile communication enable
```

`neoth chat --incognito` short-circuits communication-profile compilation and
recording before the state file is opened, so that turn performs zero
communication-profile reads and writes. Normal CLI chat and authenticated
inbound channel dispatch compile the same presentation-only layer; GUI and
Buddy conversations that invoke `neoth chat` inherit it. Doctor validates the
communication state, typed evidence, subject isolation and private permissions
without exposing profile content. GUI/Buddy controls, channel-side Incognito
controls, cluster synchronization and a general `idx_profile` claim export are
still open Gold gaps. Communication state has its own explicit preview/confirm
erasure command, an operator-scoped default export, and an exact single-subject
DSAR export; channel subjects are never bulk-exported. Topic forget
intentionally reports that typed communication evidence is not
topic-addressable. Authenticated direct n8n `/api/provider/call` requests use
the fixed local operator subject and accept `incognito: true` for zero profile
reads.
`cluster_sync` therefore remains `false`; enabling it does not currently create
a production synchronization path.

### Swarm resource dashboard

Cluster-enabled builds can persist local CPU/RAM/VRAM samples and display the
fresh local/peer set with `neoth cluster swarm`:

```yaml
swarm:
  enabled: true
  interval_secs: 30
  stale_after_secs: 300
```

`interval_secs` controls the daemon sampler; `stale_after_secs` controls the
dashboard's default prune window. Both must be greater than zero or config load
fails. `neoth cluster swarm --stale-secs N` overrides the prune window for one
invocation without changing the daemon cadence.

### Cluster configuration and activation

Use the GUI Cluster panel or `neoth cluster configure`; do not script a series
of direct YAML edits. The command replaces the complete public `cluster:`
snapshot in one locked update and, when `--passphrase-stdin` is present, commits
the matching `credentials.yaml` secret in the same rollback-safe transaction.
The secret is write-only in the GUI and is never returned in the receipt.
Before either file is replaced, NEOTH durably writes an owner-only PREPARED
journal containing checksummed before/after images. Every public config or
credential load resolves that journal first: a known partial publication rolls
back, an exact completed pair commits, and unexpected bytes stop fail-closed
with the forensic journal retained.

```bash
# Safe disabled snapshot; no cluster identity is required yet.
neoth cluster configure \
  --enabled false \
  --transport peeroxide \
  --peers-json '[]' \
  --mdns-enabled true \
  --announce-on-untrusted-wifi false \
  --trusted-ssids-json '["Home Wi-Fi"]' \
  --replicate-raw-ingress false \
  --replay-budget-days 30 \
  --listen-port 49737
```

This is a full-snapshot interface, not an incremental update. Lists are JSON
string arrays so a peer ID or SSID containing commas or intentional edge spaces
round-trips exactly. `cluster.peers` seeds outbound Iroh Node IDs; leave it
empty for Peeroxide discovery. Enabling additionally requires a non-empty
`cluster.name` and a usable existing or stdin-supplied shared passphrase.

Native desktop releases include both `peeroxide` and `iroh`. The static
headless musl release and ordinary default source builds include Peeroxide but
not Iroh; unsupported Iroh selection fails before any file is changed. Build
from source with `--features release-desktop` or `--features cluster-iroh` when
Iroh is required.

The JSON/JSONL acknowledgement contains the exact persisted public snapshot,
whether a passphrase exists, any reload-request error and
`restart_required`. An enabled carrier change, or a change while a running
daemon still owns the prior state, is saved with `restart_required: true`: the
daemon rejects transport, mDNS and carrier-lifecycle changes before ArcSwap
instead of partially applying them. `cluster.gossip.replicate_raw_ingress` and
`cluster.gossip.replay_budget_days` are the deliberate live exception: every
carrier resolves them from the current snapshot at each operation. A disabled cluster with no running daemon
is already inert and returns `restart_required: false`. An identical retry
cannot clear a real pending state. Restart the supervised daemon when the
receipt requires it; only that daemon may acknowledge the exact public snapshot
and its owner-private, non-reversible identity binding after the selected
carrier starts. A `reload_requested: true` value means the request was queued,
not that the new carrier became live. `neoth cluster status` reports
`transport_active: true` only from that daemon-written carrier acknowledgement.
Scripts request the strict receipt with
`neoth --output json cluster configure …` (or `--output jsonl`).

## Autonomy

| Level | Behavior |
| :-- | :-- |
| `strict` | Permission-engine actions take the strict confirm/deny path; unattended cron is disabled. Dedicated integration switches still apply independently. |
| `standard` | Auto-allow low-risk actions represented in the permission engine; retain action-specific confirms and explicit integration opt-ins. |
| `elevated` | Allow more routine local actions; retain hard safety floors and dedicated opt-ins. |
| `full` | Execute within explicit policy scope; hard safety floors and path-specific audit semantics remain. |
| `custom` | Standard baseline plus typed per-action `allow`, `confirm`, or `deny` overrides. Missing entries inherit Standard. Full's confirm/deny decisions are an irreducible floor; unattended cron and auto-update remain explicitly fail-closed. |

Custom policy lives in the main config, not in a second policy file:

```yaml
autonomy: custom
custom_autonomy:
  overrides:
    exec_arbitrary: deny
    external_http_request: confirm
    channel_send: allow
```

Use `neoth permissions show` to inspect all stable action names and effective
decisions, `neoth permissions check <action>` to probe the active policy, and
`neoth permissions set <action> <allow|confirm|deny>` / `clear <action>` for an
atomic config update. Invalid action names or decision values fail config
deserialization. A successful daemon reload publishes a new immutable policy
snapshot; an in-flight decision keeps the snapshot with which it started.

Autonomy is not a universal network switch. Non-local HTTP and TTS pass their
typed permission actions, while cloud TTS additionally requires the separate
default-off `media.cloud_tts_enabled` switch. Other integrations retain their
own allowlists, consent records, endpoint validation, and audit requirements. The
[threat model](security/threat-model.md) is the authoritative per-surface map.

## Inference

Inference routing is an `inference:` block in `~/.neoth/freedom.yaml`; NEOTH
does not load a separate `inference.toml`:

```yaml
provider_kind: openai_compat
provider_endpoint: http://127.0.0.1:1234/v1
provider_model: local-model-id

inference:
  mode: single
  accelerator_override: cuda  # optional; omit for auto-detection
  embedding_provider: local_qwen
  profile_provider: local_qwen
  utility_provider: local_qwen
  max_new_tokens: 256

profile:
  learn_provider: local_qwen
  allow_cloud_fallback: false
```

`profile.learn_provider` controls the post-reply extraction path used today.
`profile.allow_cloud_fallback` is the explicit fail-open switch for that path;
it does not live under `inference`.

See [providers.md](providers.md) and [local-models.md](local-models.md).

## Council

Council settings also live in `~/.neoth/freedom.yaml`:

```yaml
council:
  max_calls_per_user_message: 15
  daily_usd_cap: 2.0
  max_recursion_depth: 2
  self_reflect_enabled: false

inference:
  hemisphere_council_depth: 1
```

See [council.md](council.md).

## External MCP servers

`mcp_servers.yaml` is spawned through one central fail-closed launcher contract.
Use a directly installed executable, or an exact top-level npm pin:

```yaml
servers:
  - id: hex-graph
    command: npx
    args: ["-y", "@levnikolaevich/hex-graph-mcp@0.21.1"]
    enabled: true
    allow_tools:
      - index_project
      - find_symbols
      - find_references
      - analyze_architecture
    trust_all_tools: false
```

Tags (`@latest`), ranges, unversioned npx packages, shell/script wrappers, and
alternate runtime fetchers are rejected before process creation. Node injection
and npm registry/userconfig overrides are also rejected. `neoth doctor` reports
invalid enabled launchers as failures; `neoth mcp list` shows each static launcher
posture. Server arguments may follow the exact package spec.

The optional `neoth init --force` hex-graph offer writes the full canonical
13-tool allowlist and checks Node >=20.19.0 plus npx. Its first use can still
download through npm: the exact top-level pin prevents tag drift, but transitive
dependencies remain in npm's upstream trust boundary.

### Council depth and the `3^depth` cost curve

`freedom.yaml`'s `inference.hemisphere_council_depth` controls how deeply the council
recurses. **Each level fans every prompt out to 3 hemispheres**, so the per-prompt
provider-call count grows as `3^depth`:

| `hemisphere_council_depth` | Provider calls / prompt | Notes |
| :-- | :-- | :-- |
| `0` or `1` (default) | 3 | Flat — one council, no recursion (the v0.1 behaviour). |
| `2` | 9 | Each hemisphere convenes a sub-council. |
| `3` | 27 | |
| `4` (hard cap) | 81 | `MAX_HEMISPHERE_COUNCIL_DEPTH`; higher values clamp to 4 with a warn-log. |

Anything **above 1 multiplies cost**: on a metered provider it multiplies the per-prompt
bill in lockstep; on a flat-rate subscription or a local model it multiplies latency and
rate-limit budget instead. NEOTH surfaces this as a one-line warning — interactively in
the wizard and the GUI Config tab, and as a stderr line in non-interactive runs — so a
deep tree is a deliberate choice. Lower `hemisphere_council_depth` to bring it back down.

### WASM plugin approvals

Plugin activation state lives under `freedom.yaml::plugins.wasm.activations`, but
Active entries are CLI-managed approval records, not plain booleans:

```yaml
plugins:
  wasm:
    activations:
      example:
        state: active
        approval:
          approved_permission: read_only
          manifest_sha256: "<canonical-plugin.toml-digest>"
          wasm_sha256: "<plugin.wasm-digest>"
```

Use `neoth plugin enable <id>` to create or refresh the record. Startup and every
live invocation fail closed if the persisted approval is missing or changes. A
semantic manifest change, any requested-permission change, or different WASM bytes
cannot load on the next daemon start without explicit re-enable; the current daemon
continues only its already-validated immutable module snapshot. Old scalar entries
such as `example: active` are accepted for safe migration but never auto-grant
authority. `neoth plugin list` reports these as `reconsent_required` with the exact
reason.

## Policy

`policy.yaml` is a small dangerous-target and startup credential-audit layer.
It is not the schema for `security`, filesystem roots, channel allowlists, or
Custom autonomy. Custom overrides live at
`freedom.yaml::custom_autonomy.overrides`; other controls live in their typed
`freedom.yaml` sections or dedicated registries.

```yaml
dangerous_targets:
  - 192.168.1.100
  - gateway.internal
dangerous_patterns:
  - "rm -rf"
  - "kill -9"
startup_audit_scan_paths:
  - ~/.config/git/config
  - ~/work/project/.env
forbid_inline_tokens_in_remotes: true
```

### Tool risk gate & SmartApprove (`security:`)

The `security:` block governs how the MCP tool-loop reacts to risky LLM-issued
tool calls (GOLD-ADOPT-23/22):

```yaml
security:
  dangerous_commands: deny      # deny (default) | confirm | warn
  confirm_high: false           # also confirm HIGH findings (git push --force, curl|sh)
  egress:
    mode: allow                 # allow (default) | confirm_unknown | deny_unknown
    allowlist: ["github.com"]   # IP literals match EXACTLY; hostnames match on a dot boundary
  smart_approve: false          # opt-in confirm-bypass for read-only tools
```

- A blocked call is auditable per outcome: `neoth wal show --type risk_gate_denied`
  / `risk_gate_confirm_required`. Lift a `confirm` for a TTL window with
  `neoth risk-confirm --ttl 10m` (audited `risk_confirm_granted` →
  `risk_confirm_used` / `risk_confirm_expired`).
- **`smart_approve` (default off)** auto-approves a Confirm-gated tool call ONLY
  when the tool's server-DECLARED effect metadata (`readOnlyHint`, never its
  name) marks it read-only — never lifts a `deny`, never bypasses the
  `allow_tools` allowlist, and every auto-approval is audited
  (`risk_gate_allowed_by_readonly_cache`). **Trust assumption:** it trusts the
  configured server's self-declared annotations for the session — a compromised
  server can lie. Enable it only for servers under your operational control,
  ideally with a minimal `allow_tools` list, and never with `trust_all_tools: true`.

## Credentials

Credential setup should normally happen through:

```bash
neoth credential import --file creds.yaml   # merge a credentials.yaml-shaped file
neoth connect telegram                       # show how to wire a channel
neoth provider list                          # inspect supported/configured providers
neoth init --force                           # change provider configuration
```

Secrets should not be pasted into docs, tickets, logs, or profile memory.

The optional WhatsApp Web/Baileys bridge has a dedicated credential namespace;
none of these fields are interchangeable with the Meta Cloud fields:

| Field | Purpose |
| :-- | :-- |
| `whatsapp_baileys_url` | Repository sidecar base URL. HTTP is loopback-only; remote bridges require HTTPS. |
| `whatsapp_baileys_token` | Dedicated bridge bearer token, at least 32 characters. |
| `whatsapp_baileys_allowed_senders` | Required comma-separated E.164 numbers or exact WhatsApp JIDs. |
| `whatsapp_baileys_allowed_groups` | Optional exact `@g.us` JIDs; absent means all groups denied. |

Use `neoth channel add whatsapp_baileys` so URL, token, sender, and group policy
are validated atomically. Configure its proactive destination separately with
`neoth proactive route --channel whatsapp_baileys --dest <E.164-or-JID>`.

Inbound identity policy is mandatory for adapters whose vendor transport does
not already bind one closed operator identity. NEOTH refuses to start the
adapter when these fields are absent or blank:

| Channel | Required identity policy |
| :-- | :-- |
| IRC | `irc_allowed_account` (authenticated IRCv3 services account; an optional `irc_allowed_nick` is only a secondary check) |
| iMessage / BlueBubbles | `imessage_allowed_sender` |
| Mattermost | `mattermost_allowed_user_id` |
| Google Chat | `gchat_allowed_sender` |
| Matrix | At least one of `matrix_allowed_user_id` or `matrix_allowed_room_ids`; when both are set, both must match |
| Nostr | `nostr_allowed_pubkey` |

`neoth channel add` and the GUI collect these policies through their shared
channel setup contract. Five advanced settings still require a direct,
owner-private `credentials.yaml` edit: `line_webhook_port` (default `8444`),
`irc_port` (default `6697`), `irc_tls` (default `true`), `irc_allowed_nick`,
and `matrix_store_path` (default `~/.neoth/matrix_store/`). Their missing
first-class CLI/GUI controls remain v1.0 surface-parity work.

OMI uses dedicated credential fields rather than provider/channel tokens:
`omi_developer_api_key` for official Developer API import/export and
`omi_ingest_token` for the authenticated native listener. Keep them in
`credentials.yaml` or the configured keychain. See
[runbook_omi_privacy.md](runbook_omi_privacy.md) for the full mode and consent
contract.

Common environment variables:

| Variable | Purpose |
| :-- | :-- |
| `OPENAI_API_KEY` | OpenAI-compatible provider. |
| `ANTHROPIC_API_KEY` | Anthropic/Claude provider where API mode is used. |
| `GEMINI_API_KEY` | Gemini provider. |
| `TELEGRAM_BOT_TOKEN` | Telegram bot. |
| `SLACK_BOT_TOKEN` | Slack bot user token. |
| `SLACK_APP_TOKEN` | Slack Socket Mode token. |
| `WHATSAPP_TOKEN` | WhatsApp Business Cloud API. |
| `WHATSAPP_PHONE_ID` | WhatsApp Business phone number ID. |
| `NEOTH_WA_BRIDGE_TOKEN` | Repository Baileys sidecar bearer token; copy it into the dedicated CLI channel config. |

## Reload behavior

| Change | Reload |
| :-- | :-- |
| Skills | Hot-reloaded automatically (file watcher); `neoth reload` re-reads tunable config. |
| Provider config | Daemon reload or restart depending on provider. |
| Channels | The running daemon watches effective file/keychain credentials, validates the new generation, and stop-then-starts only the changed adapter. A malformed credential store stops the channel fleet fail-closed instead of retaining stale secrets. If a mutation reports that its reload request failed, run `neoth reload`; a full daemon restart is not the normal path. |
| OMI | `neoth reload` validates effective file/keychain credentials and restarts only the OMI workers; an invalid reload preserves the last valid runtime. |
| Cluster | `neoth cluster configure` saves one complete typed snapshot. Enabled lifecycle changes, and changes while a daemon owns the prior state, return `restart_required: true`; restart the supervised daemon to activate transport, mDNS or carrier changes. Gossip privacy/replay policy is hot-reloadable on Peeroxide and Iroh. Disabled plus stopped is already inert and returns `false`. |
| Plugins | Restart after enabling/disabling code plugins. |
| Policy | Reload where supported; restart for safest behavior. |

## Validate config

```bash
neoth doctor
neoth doctor --explain freedom.yaml
neoth privacy audit --last 24h
```
