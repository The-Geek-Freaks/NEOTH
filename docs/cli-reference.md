# CLI Reference

The CLI is the operator cockpit for NEOTH. GUI users can ignore most of this; pros can script almost everything.

> This page is the curated **guide** (workflows + the commands you reach for most).
> For the exhaustive, always-current list of **every** command, subcommand, alias, and
> flag — generated straight from the CLI so it can never drift — see
> [cli-commands.md](cli-commands.md) (or run `neoth completions --reference`).

## First run

```bash
neoth
neoth init --cli
neoth gui
neoth interface show
neoth interface set gui
neoth interface set cli
neoth doctor
neoth status
```

| Command | Purpose |
| :-- | :-- |
| `neoth` | First launch: choose GUI or CLI once; later launches open the persisted surface. Headless sessions use CLI without a popup. |
| `neoth init --cli` | Run CLI onboarding explicitly. |
| `neoth gui` | Start the GUI wizard/chat/control surface. |
| `neoth interface show/set` | Inspect or switch the instance-wide default surface. |
| `neoth doctor` | Diagnose setup, providers, channels, local models, WAL, policy. |
| `neoth status` | Show daemon, memory, provider, channel, cluster, and model status. |

## Chat and recall

```bash
neoth chat "hello"
neoth chat --temperature 0.7 --top-p 0.9 --sampling-seed 42 "replayable draft"
neoth recall "the router issue from last month"
neoth ingest ./document.pdf
```

Per-call sampling controls are strict: unsupported controls and invalid ranges
fail before provider authorization or transport. The exact provider matrix and
portable limits are in [providers.md](providers.md#per-call-controls).

| Command | Purpose |
| :-- | :-- |
| `neoth chat <prompt>` | Ask NEOTH from the terminal. |
| `neoth recall <query>` | Search memory and indexed context. |
| `neoth ingest <path>` | Ingest a file, folder, document, image, audio, or video. |
| `neoth search <query>` | Search local indexed material where configured. |

## Recipes

Recipe YAML may set `settings.model`, `settings.temperature`, `settings.top_p`,
and `settings.sampling_seed`. `neoth recipe validate` and `neoth recipe run
--dry-run` reject malformed portable ranges without dispatch. A real run checks
provider/model-specific support at the same strict leaf boundary as the matching
`neoth chat` flags, before authorization and transport.

## Profile

```bash
neoth profile show
neoth profile pending
neoth profile approve <id>
neoth profile decline <id> --reason "wrong"
neoth profile redact identity.location --reason "remove this field"
neoth profile redactions
neoth profile communication status
neoth profile communication why directness
neoth profile communication set directness direct
neoth export --list-subjects
neoth memory erase-communication-profile
neoth memory erase-communication-profile --subject <pseudonymous-handle>
neoth memory erase-communication-profile --confirm
```

| Command | Purpose |
| :-- | :-- |
| `profile show [--field <field>]` | Show materialised active profile claims. |
| `profile pending` | List pending memory proposals. |
| `profile approve <id>` | Approve a pending profile claim. |
| `profile decline <id>` | Decline a pending profile claim. |
| `profile redact <field>` | Add a durable `never_recreate` redaction for one field. |
| `profile redactions` / `unredact --id <id>` | Inspect or revoke redaction records. |
| `profile communication status/show/why` | Inspect the default-on typed local communication profile without exposing raw messages. |
| `profile communication set/reset` | Pin one presentation preference, remove one dimension, or remove the complete communication subject. |
| `profile communication context ...` | Manage explicit-only neuro-context and its separate prompt-use opt-in. |
| `export --list-subjects` | Strictly inventory exact pseudonymous communication-profile subject handles; no bundle is written. |
| `memory erase-communication-profile [--subject <handle>] [--confirm]` | Preview or confirm complete erasure of exactly one typed communication subject; omission preserves the operator default. |

There is no `profile pause`, `profile resume`, or `profile export` command in
the current CLI. Normal `neoth export` includes only the typed operator
communication state as `communication_profile.json`. An explicit `--subject
<handle>` creates a communication-only DSAR bundle for that one exact subject;
it never adds every channel subject. General `idx_profile` fact claims remain
excluded; see [profile.md](profile.md) for the exact privacy and export boundary.

## Privacy and audit

```bash
neoth privacy audit            # config posture
neoth privacy audit --last 30d # + what actually left the device recently
neoth verify
neoth wal show --type provider_request --last 50
neoth wal proof-key rotate --dry-run
neoth plugin ledger
```

| Command | Purpose |
| :-- | :-- |
| `privacy audit` | Show destinations, sensitive events, provider calls, plugin activity. |
| `verify` | Verify the local WAL event chain (HMAC audit-chain integrity). |
| `wal show` | Inspect recent WAL events. |
| `wal proof-key rotate [--dry-run]` | Rotate an existing proof key only after a dual-signed `proof_key_rotated` transition is durably audited; `--dry-run` writes nothing. |
| `plugin ledger` | Inspect plugin capabilities and activity. |

## Autonomy policy

```bash
neoth permissions show
neoth permissions check external_http_request
neoth permissions set external_http_request confirm
neoth permissions clear external_http_request
```

| Command | Purpose |
| :-- | :-- |
| `permissions show [--level <level>]` | Show the active policy, Custom overrides, and all stable action decisions. |
| `permissions check <action>` | Evaluate one payload-safe representative against the active immutable policy; payload-bearing checks accept `--eur` or `--target`. |
| `permissions set <action> <allow\|confirm\|deny>` | Atomically persist a typed Custom override in `freedom.yaml`. It becomes active when autonomy is `custom`. |
| `permissions clear <action>` | Atomically remove an override so the action inherits Standard again. |

Custom can tighten any action, but cannot weaken Full's irreducible
confirm/deny floor. Cron registration and automatic update application remain
disabled under Custom regardless of overrides.

## OMI private ingest

```bash
# First-run/non-interactive onboarding (secrets never enter argv)
NEOTH_OMI_DEVELOPER_API_KEY='omi_dev_...' \
  neoth init --non-interactive --accept-license --omi \
  --omi-mode developer_api --omi-retention-days 30

# Native media remains separately opted in
NEOTH_OMI_INGEST_TOKEN='<at-least-32-characters>' \
  neoth init --non-interactive --accept-license --omi \
  --omi-mode native_ingest --omi-audio true --omi-images false --omi-video false

neoth omi status --output json
neoth omi probe
# Complete surfaced OMI reconfiguration (32 KiB maximum, strict JSON schema)
neoth --output json omi configure <<'JSON'
{
  "settings": {
    "enabled": false,
    "mode": "developer_api",
    "endpoint": "http://127.0.0.1:8002",
    "listen_addr": "127.0.0.1:8003",
    "retention_days": 30,
    "retain_transcripts": false,
    "audio_enabled": false,
    "visual_enabled": false,
    "video_enabled": false,
    "allow_cloud_api": false,
    "allow_cloud_summary": false,
    "create_actions": false,
    "seed_groundtruth": false,
    "summary_enabled": false
  },
  "credentials": {}
}
JSON
# Credential-only automation remains available for existing scripts
printf '%s' '{"developer_api_key":"omi_dev_..."}' | neoth omi set-credentials
neoth omi enforce-retention
neoth omi purge <conversation-id> --yes
```

| Command | Purpose |
| :-- | :-- |
| `init --omi ...` | Configure OMI during first-run/reconfigure with the same mode, endpoint/listener, retention, transcript, audio, image, video, summary, action, and ground-truth controls as the desktop wizard. Use `NEOTH_OMI_DEVELOPER_API_KEY` / `NEOTH_OMI_INGEST_TOKEN`; OMI secrets have no init argv flags and are omitted from crash-resume checkpoints. |
| `omi status` | Show mode, consent controls, credential presence, ledger counts, pending reconciliation, and PID-verified runtime health without exposing secrets or transcript content. |
| `omi probe` | Probe only the configured local endpoint/native listener; authenticated public Developer APIs are not contacted. |
| `omi configure` | Read one strict, complete surfaced settings snapshot plus optional credential replacements from at most 32 KiB of JSON on standard input. The config/credential generation uses the crash-recovery journal protocol, is read back and validated, and is bound to a reload request before a success receipt is emitted; advanced unsurfaced bounds remain preserved. |
| `omi set-credentials` | Credential-only compatibility path for automation and desktop onboarding: read at most 8 KiB of JSON from standard input and preserve encryption, keychain selection, and unrelated credentials. It is not the Settings-card save path. |
| `omi resume --review-note <note>` | Resume an SC-18-halted stream after a durable operator review intent. |
| `omi enforce-retention` | Apply `omi.retention_days` immediately. |
| `omi purge <id> --yes` | Permanently delete one conversation and local derivatives, remove its native receipt, and retain an anti-reimport tombstone. |
| `omi allow-reimport <id> --yes` | Explicitly remove the tombstone and stale reconciliation state so the remote source may restore the conversation. |

`omi configure` rejects unknown fields at the request, `settings`, and
`credentials` levels. `settings` must contain every field shown above;
`credentials` may be empty or may replace `developer_api_key`,
`native_ingest_token`, or both. Omit a credential field to preserve its current
value. A Developer key must be a trimmed, non-empty `omi_dev_*` value, and a
native token must be trimmed and at least 32 bytes. Secrets travel only through
stdin and are absent from argv and the success receipt. The receipt includes the
operation and request identity, config path, complete surfaced settings,
selected backend, updated field names, credential-presence booleans, exact
settings/configuration hashes, and reload-request state/timestamp.

A success receipt proves the persisted effective config/credential generation
was read back and validated and that a reload was requested; it does not claim
that an asynchronous daemon reload has already completed. If the commit and
readback succeeded but requesting reload failed, the command says so and asks
the operator to run `neoth reload`. On keychain-finalization failure, trust the
specific error: it distinguishes failure before a complete keychain generation
was staged, a restored prior generation, a new generation retained because the
file target may already be committed, and a rollback that also failed. Do not
infer rollback merely from a non-zero exit; inspect
`neoth omi status --output json` before retrying.

OMI and every media type are off by default. Audio, images, video frames, raw
transcript retention, public API access, cloud summaries, actions, and
ground-truth seeding have independent controls. See the
[OMI privacy runbook](runbook_omi_privacy.md) for modes, native event headers,
limits, retention, and incident handling.

## Providers and models

```bash
neoth provider list
neoth provider known
neoth provider show openai_api
neoth provider test openai_api
neoth models list
neoth models catalog
neoth models pull clip
neoth models pull whisper
neoth ouro list
neoth ouro fetch --checkpoint ByteDance/Ouro-1.4B-Thinking
```

| Command | Purpose |
| :-- | :-- |
| `provider list` | Show configured providers. |
| `provider known` | Show well-known OpenAI-compatible endpoint presets. |
| `provider show <id>` | Show one provider's requirements and configuration status. |
| `provider test <id>` | Show where that provider is wired into the inference topology. |
| `init --force` | Re-run onboarding to change provider configuration. |
| `models list` | Show managed CLIP/Whisper/Piper cache state. |
| `models catalog` | Return the live provider-model catalog as JSON for CLI automation and the GUI retry picker; stale or unavailable catalogs expose their error instead of inventing model IDs. |
| `models pull <name>` | Download managed CLIP or Whisper artifacts. |
| `ouro list/fetch/status` | Inspect, download, and inspect Ouro checkpoints. |
| `init --provider local_qwen` | Select Qwen through hardware-aware onboarding. |

## Channels

```bash
neoth channel list                 # which channels are configured
neoth channel add telegram         # prompt for token + exact numeric sender ID
neoth channel test telegram        # live read-only credential check
neoth channel remove telegram      # clear token + sender policy
neoth serve
```

| Command | Purpose |
| :-- | :-- |
| `channel list` | Show every channel + whether it is configured. |
| `channel add <name>` | Connect a supported channel (telegram/slack/whatsapp/keet/...). Every inbound adapter collects its sender policy in the same transaction: Telegram uses `--telegram-user-id`; Discord, Slack, WhatsApp Business, Signal and LINE use `--allowed-sender`; Keet uses `--url --token --server --allowed-sender`. Interactive equivalents use secret-safe prompts. |
| `channel test <name>` | Protocol-specific read-only credential/reachability check. Sends no chat and consumes no inbound queue. Exit 0=`ok`, 1=`fail`, 2=`skipped`/`unavailable`; JSON always carries the typed verdict. |
| `channel remove <name>` | Clear a channel's durable adoption state; Telegram removes both token and sender policy. |
| `serve` | Run daemon/channel server. |

Discord stores `discord_bot_token` and the mandatory immutable-user policy
`discord_allowed_user_id` in `credentials.yaml`; `channel test discord`
performs a read-only `GET /users/@me` identity probe and `serve` owns the live
Gateway receive loop. Inbound stays disabled unless both fields are valid.
Slack, WhatsApp Business, Signal and LINE likewise store mandatory exact
inbound policies as `slack_allowed_user_id`, `whatsapp_allowed_sender`,
`signal_allowed_sender`, and `line_allowed_sender`. Workspace membership or a
valid webhook signature authenticates the transport, not the operator. The
daemon keeps the adapter off when policy is missing and WAL-audits mismatches
without message content.
Email IMAP ingest is a source-build `imap_fetch` opt-in,
configured through IMAP environment/OAuth credentials rather than
`channel add`. Calendar reads its CalDAV URL and credentials from
`freedom.yaml` / `credentials.yaml`.

`neoth channel test keet` performs a read-only authenticated handshake with the
repository-owned `neoth-keet-bridge`, verifies the exact protocol/version,
full-duplex capabilities and joined topic, and returns its high-water cursor.
The companion creates a private Keet-identity Pear/Hyperswarm topic; it cannot
read or write existing Keet application rooms.

Signal, LINE, BlueBubbles, Mattermost, Google Chat, token-authenticated Matrix,
Twitch, and Nostr have live read-only probes as well. IRC is explicitly
`unavailable` because a second registration is stateful; Matrix password-only
probing is `unavailable` because login creates device/session state. While the
daemon runs, credential/keychain changes are fingerprinted per channel and only
the affected adapter is stop-then-started. Corrupt credential state stops the
fleet fail-closed instead of retaining stale secrets.

## Coding buddy

```bash
neoth code "map this repo and propose a plan" --canvas
neoth code "implement the accepted migration with tests" --dispatch
neoth code review --promote-findings
neoth kanban watch
```

| Command | Purpose |
| :-- | :-- |
| `code <task>` | Run coding workflow. |
| `code --canvas` | Build a planning canvas. |
| `code --dispatch` | Split and dispatch bounded work. |
| `code review` | Review current changes. |
| `kanban watch` | Show live task board. |

## Council

```bash
neoth council ask "review this plan"
neoth council status
neoth council history
neoth council show <id>
```

| Command | Purpose |
| :-- | :-- |
| `council ask` | Force a multi-role review. |
| `council status` | Show budget and trigger state. |
| `council history` | List prior debates. |
| `council show <id>` | Inspect a debate. |

## Skills and plugins

```bash
neoth skills --list
neoth skills --install ./skill
neoth skills --test rust-review
# Skills hot-reload automatically (file watcher) — no reload command needed.

neoth plugin list
# Install a WASM plugin by dropping it under ~/.neoth/plugins/<id>/, then:
neoth plugin verify ./plugins/my-plugin   # check integrity before enabling
neoth plugin enable my-plugin
neoth plugin ledger my-plugin
```

| Command | Purpose |
| :-- | :-- |
| `skills ...` | Manage data-only skills (`--list` / `--install` / `--test`). |
| `plugin ...` | Manage sandboxed WASM plugins (`list` / `verify` / `enable` / `ledger`). |

## Automation

```bash
neoth cron create --id morning-brief --name "Morning brief" \
  --cron "0 7 * * *" --tz Europe/Berlin --prompt "Prepare my brief" \
  --channel telegram
neoth cron pause morning-brief
neoth cron resume morning-brief
neoth cron deliveries --job morning-brief
neoth cron run morning-brief   # manual fire; refused while the daemon owns the WAL
```

| Command | Purpose |
| :-- | :-- |
| `cron add|create` | Atomically create a cron, fixed-interval, or one-shot job with per-job provider/model/profile/thinking/fallback, exact MCP scope, dependencies, and announce/webhook/none delivery. |
| `cron edit|update <id>` | Validate and atomically replace supplied fields; `--clear-timezone`, `--clear-delivery`, `--clear-execution`, and `--clear-dependencies` remove optional state explicitly. The daemon live-reloads only a complete valid generation. |
| `cron pause|resume <id>` | Disable or enable a job without deleting it. |
| `cron list` / `cron status` | Inspect full schedule/execution/delivery policy or aggregate role state. |
| `cron deliveries` | Inspect durable delivery correlation, attempts, terminal status, and diagnostics. |
| `cron run <id>` | Fire one job with the same authorized provider/MCP/delivery boundary as scheduled execution. |
| `jobs --list` / `jobs --preview <id>` | Read-only schedule and cost/policy preview. |
| `webhook serve` | Loopback HTTP server that n8n + MCP plugins POST to (the n8n integration surface). |

Strict and Custom autonomy disable scheduled Cron execution fail-closed. Channel
recipients must resolve to operator-owned routing before provider spend. Keet's
secret topic capability remains in `credentials.yaml` and is live-probed through
the authenticated full-duplex companion before a Cron call can spend.

## Mesh and cluster

```bash
neoth cluster discover
neoth buddy cluster invite --stable-node-id <stable-node-id> \
  --signing-public-key <ed25519-public-key> --carrier <peeroxide|iroh> \
  --transport-identity <carrier-id> --endpoint <endpoint> --label <label>
neoth buddy cluster confirm --invite-id <invite-id> \
  --attestation <endpoint-attestation-json> --carrier <peeroxide|iroh> \
  --transport-identity <carrier-id> --endpoint <endpoint>
neoth cluster configure --enabled false --transport peeroxide \
  --peers-json '[]' --mdns-enabled true \
  --announce-on-untrusted-wifi false --trusted-ssids-json '[]' \
  --replicate-raw-ingress false --replay-budget-days 30 \
  --listen-port 49737
neoth cluster status
neoth cluster list
neoth cluster sync-state
neoth cluster conflicts
neoth cluster conflicts resolve <content-id> --prefer <peer>
neoth cluster export-foreign --peer <peer> --out backup.jsonl
neoth cluster restore backup.jsonl
neoth hardware
```

| Command | Purpose |
| :-- | :-- |
| `cluster discover` | Find candidate-only mDNS v2 records: HMAC filters the rendezvous domain and a signed `EndpointAttestation` authenticates the advertised stable identity/binding, but discovery grants no membership. |
| `cluster confirm <peer>` | Legacy manual/Tailscale intake only; records an unattested `Pending` candidate. Signed mDNS candidates use authority invite/attestation confirmation. |
| `buddy cluster invite` / `buddy cluster confirm` | Issue the one-time authority invite, then activate only the peer's exact carrier-bound signed `EndpointAttestation`. JSON keeps the invite's `issued_at_membership_epoch`, the attestation's `proof_membership_epoch`, and the receipt's `committed_membership_epoch` separate. |
| `cluster revoke <stable-node-id>` / `buddy cluster revoke` | Commit a durable membership tombstone/outbox and tear down live carrier state. |
| `cluster configure` | Atomically replace the complete cluster configuration and return an exact receipt (`neoth --output json cluster configure …` for machine-readable output). |
| `cluster status` | Show mesh health, live gossip posture and unresolved conflict count. |
| `cluster topology` | Show connected surfaces/nodes. |
| `cluster sync-state` | Inspect per-peer ACK cursors, pending replay, and contiguous inbound sequence. |
| `cluster conflicts` | Inspect typed same-content divergence with both origins and digests. |
| `cluster conflicts resolve` | Persist a preferred-origin decision while retaining forensic history. |
| `cluster export-foreign` | Export original WAL frames plus canonical v5 content envelopes with exact `stable_node_id`, `auth_epoch`, `membership_epoch`, and `fence_state` provenance. |
| `cluster restore` | Restore canonical memory/ground-truth through durable local-ID mapping scoped to `(stable_node_id, auth_epoch)`; legacy canonical rows without an authority fence fail closed. |
| `local resources` | Show GPU/CPU/RAM/model usage. |

`cluster configure` is a **complete-snapshot** command, not a field patch. Every
invocation supplies the desired master switch, name, carrier, peer list, mDNS
switch, announce policy, trusted SSIDs, raw-ingress privacy policy, replay
window and listen port; omitted options take
their documented defaults. Prefer the GUI Cluster panel for an interactive
first setup. For CLI automation, pass peer and SSID lists as JSON arrays and
pipe a new shared secret through `--passphrase-stdin`; never place the secret
on the command line. Enabling is rejected unless the resulting snapshot has a
non-empty cluster name and an existing or newly supplied shared passphrase.
That passphrase derives the rendezvous `ClusterKey`; its HMAC proves
shared-secret possession only and never grants node or task authority.

Stable node identity is persisted separately in
`~/.neoth/cluster-node-identity.json`. The admission source is
`~/.neoth/cluster-membership.db`, whose active, unexpired, epoch-current exact
carrier bindings issue runtime membership grants. Legacy `cluster.yaml` rows
are imported once as unattested `Pending` candidates. Use `cluster status`,
`list`, or `topology` to inspect the authority snapshot.

Revocation commits a versioned tombstone and durable
membership/audit/teardown outbox before it is acknowledged. A live daemon
tears down Peeroxide and Iroh sessions and routes immediately; any undelivered
outbox work is replayed before carrier startup. This blocks future admission
and effects but cannot retract plaintext disclosed before revocation.

The success receipt distinguishes **saved** from **active**. Enabled lifecycle
changes, and changes while a running daemon owns the prior state, return
`restart_required: true`. Disabled plus stopped is already inert and returns
`false`. The daemon deliberately rejects cluster lifecycle changes before its
live configuration swap, so transport and mDNS do not hot-switch even if
`reload_requested` is true. Gossip privacy/replay policy is resolved live by
both carriers after reload. An identical retry stays pending; disk equality
is not runtime proof. Restart the supervised daemon when the receipt requires
it. Only the daemon may acknowledge the exact public snapshot and owner-private
identity binding after successful carrier construction, and `cluster status`
uses that acknowledgement before returning `transport_active: true`; the GUI
reports the same state instead of inferring liveness from configuration.
The Mesh panel and `cluster status` never silently flatten canonical-content
divergence. Inspect the full ledger with `cluster conflicts`; resolve a stable
content ID by choosing an origin. That choice is durable for the observed
digest pairs, while a new pair reopens the operator-visible conflict.
Use the global `--output json` or `--output jsonl` option before `cluster` when a
script needs the strict receipt rather than the human-readable table.

Signed native desktop releases for GNU Linux, macOS and Windows contain both
Peeroxide and Iroh. The static headless musl server contains Peeroxide only and
rejects `--transport iroh` before writing configuration. Source builds need
`--features release-desktop` (or `cluster-iroh`) for Iroh.

## Maintenance

```bash
neoth backup
neoth backup --include-credentials   # explicit plaintext-secret opt-in
neoth rollback list
neoth update check
neoth update apply
neoth export --out ~/neoth-export
neoth export --list-subjects
neoth export --subject <pseudonymous-handle> --out ~/subject-export
```

| Command | Purpose |
| :-- | :-- |
| `backup` | Create a state backup; `credentials.yaml` is excluded by default. |
| `backup --include-credentials` | Include plaintext credentials explicitly; store the resulting archive only on encrypted media. |
| `rollback list` | Show rollback points. |
| `update check/apply` | Self-update where configured. |
| `export` | Export memory/profile/vault data. |
| `export --subject <handle>` | Export only one exact communication-profile subject; output directory must be empty. |

### Release signing (maintainers)

```bash
neoth release setup --repo owner/name
neoth release setup --repo owner/name --force
neoth release pubkey
neoth release sign <artifact> --comment "file:<release-asset-name>"
neoth release verify <artifact>
```

Plain `release setup` bootstraps a genuinely empty trust root, reuses a fully
matching local/Actions/source key, or completes provisioning for an existing
local key when the published state is empty/matching and the source pin is
missing. Any mismatch fails closed. When source synchronization is needed it
requires checkout `origin == --repo`, writes a crash-recovery marker, and
updates `NEOTH_RELEASE_MINISIGN_PUBKEY.txt` plus both installer pins before
provisioning Actions. `--force` is the explicit rotation path and also resumes
the exact pending key after an interrupted bootstrap/rotation. If source pins
changed, review, commit, and push them before tagging; only a fully matching
state has no repository edit. See the
[release-signing runbook](runbook_release_signing.md).
