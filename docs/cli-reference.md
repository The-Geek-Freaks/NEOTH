# CLI Reference

The CLI is the operator cockpit for NEOTH. GUI users can ignore most of this; pros can script almost everything.

> This page is the curated **guide** (workflows + the commands you reach for most).
> For the exhaustive, always-current list of **every** command, subcommand, alias, and
> flag — generated straight from the CLI so it can never drift — see
> [cli-commands.md](cli-commands.md) (or run `neoth completions --reference`).

## First run

```bash
neoth init
neoth gui
neoth doctor
neoth status
```

| Command | Purpose |
| :-- | :-- |
| `neoth init` | Run CLI onboarding wizard. |
| `neoth gui` | Start the GUI wizard/chat/control surface. |
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
neoth profile show --evidence
neoth profile pending
neoth profile approve <id>
neoth profile decline <id> --reason "wrong"
neoth profile redact identity.location
neoth profile pause
neoth profile resume
```

| Command | Purpose |
| :-- | :-- |
| `profile show` | Show active profile facts. |
| `profile show --evidence` | Include evidence, confidence, and source. |
| `profile pending` | List pending memory proposals. |
| `profile approve <id>` | Approve a pending profile claim. |
| `profile decline <id>` | Decline a pending profile claim. |
| `profile redact <field>` | Remove and optionally block relearning. |
| `profile export` | Export profile as JSON/Markdown. |
| `profile pause/resume` | Control learning. |

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
printf '%s' '{"developer_api_key":"omi_dev_..."}' | neoth omi set-credentials
neoth omi enforce-retention
neoth omi purge <conversation-id> --yes
```

| Command | Purpose |
| :-- | :-- |
| `init --omi ...` | Configure OMI during first-run/reconfigure with the same mode, endpoint/listener, retention, transcript, audio, image, video, summary, action, and ground-truth controls as the desktop wizard. Use `NEOTH_OMI_DEVELOPER_API_KEY` / `NEOTH_OMI_INGEST_TOKEN`; OMI secrets have no init argv flags and are omitted from crash-resume checkpoints. |
| `omi status` | Show mode, consent controls, credential presence, ledger counts, pending reconciliation, and PID-verified runtime health without exposing secrets or transcript content. |
| `omi probe` | Probe only the configured local endpoint/native listener; authenticated public Developer APIs are not contacted. |
| `omi set-credentials` | Read a bounded JSON update from standard input and preserve encryption, keychain selection, and unrelated credentials. Secret values never enter argv. |
| `omi resume --review-note <note>` | Resume an SC-18-halted stream after a durable operator review intent. |
| `omi enforce-retention` | Apply `omi.retention_days` immediately. |
| `omi purge <id> --yes` | Permanently delete one conversation and local derivatives, remove its native receipt, and retain an anti-reimport tombstone. |
| `omi allow-reimport <id> --yes` | Explicitly remove the tombstone and stale reconciliation state so the remote source may restore the conversation. |

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
| `channel add <name>` | Connect a supported channel (telegram/slack/whatsapp/keet/...). Telegram requires `--token --telegram-user-id` and commits secret + exact sender policy through a locked rollback-safe `credentials.yaml`/`freedom.yaml` update. Keet requires `--url --token --server --allowed-sender`. Interactive equivalents use secret-safe prompts. |
| `channel test <name>` | Protocol-specific read-only credential/reachability check. Sends no chat and consumes no inbound queue. Exit 0=`ok`, 1=`fail`, 2=`skipped`/`unavailable`; JSON always carries the typed verdict. |
| `channel remove <name>` | Clear a channel's durable adoption state; Telegram removes both token and sender policy. |
| `serve` | Run daemon/channel server. |

Discord stores `discord_bot_token` in `credentials.yaml`; `channel test discord`
performs a read-only `GET /users/@me` identity probe and `serve` owns the live
Gateway receive loop. Email IMAP ingest is a source-build `imap_fetch` opt-in,
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
neoth cluster confirm <peer>
neoth cluster status
neoth cluster list
neoth cluster sync-state
neoth cluster export-foreign --peer <peer> --out backup.jsonl
neoth cluster restore backup.jsonl
neoth hardware
```

| Command | Purpose |
| :-- | :-- |
| `cluster discover` | Find candidate nodes. |
| `cluster confirm <peer>` | Approve a peer. |
| `cluster status` | Show mesh health. |
| `cluster topology` | Show connected surfaces/nodes. |
| `cluster sync-state` | Inspect per-peer ACK cursors, pending replay, and contiguous inbound sequence. |
| `cluster export-foreign` | Export original WAL frames plus canonical v5 content envelopes. |
| `cluster restore` | Restore canonical memory/ground-truth through durable local-ID mapping. |
| `local resources` | Show GPU/CPU/RAM/model usage. |

## Maintenance

```bash
neoth backup
neoth backup --include-credentials   # explicit plaintext-secret opt-in
neoth rollback list
neoth update check
neoth update apply
neoth export --out ~/neoth-export
```

| Command | Purpose |
| :-- | :-- |
| `backup` | Create a state backup; `credentials.yaml` is excluded by default. |
| `backup --include-credentials` | Include plaintext credentials explicitly; store the resulting archive only on encrypted media. |
| `rollback list` | Show rollback points. |
| `update check/apply` | Self-update where configured. |
| `export` | Export memory/profile/vault data. |

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
