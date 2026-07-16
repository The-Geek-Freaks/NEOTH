# OpenClaw channel, account, and lossless migration parity

**Plan ID:** `001-openclaw-channel-migration-parity`

**Status:** In progress; canonical registry and complete-source inspection
foundations exist, but account/runtime/apply parity remains release-blocking

**Created:** 2026-07-15

**NEOTH baseline:** exact Git HEAD `19f74b228cc6d43fc2542922bbc28e324ba52ac6`

**OpenClaw baseline:** clean exact Git HEAD `4c667aac8859114bd8f0a589ac6cd1de8bfe1474`

**Primary release gate:** `GOLD-R4-07`

**Related gates:** `GOLD-R4-04`, `GOLD-R4-05`, `GOLD-R4-06`, `GOLD-R4-08`, `GOLD-R4-10`

## Objective

Make an OpenClaw-to-NEOTH channel migration field-, account-, state-, and behavior-lossless. A migration is complete only when every effective source leaf and every configured account is either:

1. mapped to an equivalent, active NEOTH contract;
2. staged for an explicit secret prompt, OAuth/QR relink, managed runtime install, or transport conversion;
3. blocked at the exact source path with an actionable reason; or
4. covered by an evidence-backed skip that the operator sees and accepts.

No configured account, policy, binding, topic, pairing record, delivery behavior, or capability may disappear silently. “A NEOTH adapter with the same vendor name exists” is not parity.

This plan implements the current Road-to-Gold correction in `PLAN/ROAD_TO_1_0_GOLD.md:107-120`, especially `GOLD-R4-07` at line 117. The old “15/15 channels shipped” conclusion is historical and is expressly superseded by the current release gate.

## Why now

- OpenClaw's current public channel index names 29 surfaces (`OpenClaw: docs/channels/index.md:17-47`). ClickClack is also a real manifest-backed channel even though that index omits it (`OpenClaw: docs/channels/clickclack.md:9-19`). The QA channel is deliberately synthetic and excluded from release packages (`OpenClaw: docs/channels/qa-channel.md:10-20`).
- NEOTH exposes 15 channel kinds (`SRC/neothd/src/channels/probe.rs:218-234`). Thirteen semantically overlap OpenClaw; WhatsApp Business and Keet are NEOTH-specific additions.
- OpenClaw's channel contract is account-aware and includes setup, pairing, security, group policy, outbound behavior, status, gateway lifecycle, auth, commands, secret refs, allowlists, doctor checks, bindings, streaming, threading, directory/resolution, actions, and heartbeat (`OpenClaw: src/channels/plugins/types.plugin.ts:59-103`). Its capability vocabulary includes chat topology, polls, reactions, edit/unsend/reply, effects, group management, threads, media, TTS, native commands, and block streaming (`OpenClaw: src/channels/plugins/types.core.ts:307-323`).
- NEOTH's normalized inbound envelope has no `account_id` (`SRC/neothd/src/channels/mod.rs:331-384`), its identity uniqueness key is only `(channel, sender_id, chat_id)` (`SRC/neothd/src/channels/identity.rs:37-90`), and its adapter trait exposes only name, run, text, media, edit, and proactive send (`SRC/neothd/src/channels/mod.rs:409-497`).
- The channel importer is intentionally read-only (`SRC/neoth-migrate/src/openclaw_channels.rs:581-613`), explicitly rejects every account-scoped leaf (`SRC/neoth-migrate/src/openclaw_channels.rs:986-998`), and the CLI only prints a report (`SRC/neoth-migrate/src/main.rs:695-717`).

## Non-goals

- Do not copy secret values, QR sessions, device keys, cookies, refresh tokens, or vendor auth stores from OpenClaw. Import references and non-secret configuration; relink through NEOTH's credential flow.
- Do not preserve implementation-specific bugs or undocumented incidental behavior. Preserve the audited schema and observable contract at the pinned OpenClaw commit.
- Do not force Voice Call or WebChat into `ChannelKind` if a dedicated first-class surface is a cleaner model. They still need the same account, permission, audit, status, onboarding, and migration guarantees.
- Do not activate an external plugin from documentation alone. WeChat, Yuanbao, and Zalo ClawBot require an exact source/version/license/integrity audit first.
- Do not remove NEOTH-only WhatsApp Business or Keet. Bring both under the same account/capability/onboarding contract.
- Do not require a developer toolchain or a user-installed verifier/runtime. Vendor login, QR approval, cloud app registration, phone numbers, and platform hardware are unavoidable user-owned prerequisites; binaries, sidecars, verification, progress, and repair must be managed by NEOTH.

## Audit boundary and source of truth

The OpenClaw audit used the clean checkout at `C:\Users\Shadow-PC\CascadeProjects\AGENTER\QUELLEN\openclaw`, exact HEAD `4c667aac8859114bd8f0a589ac6cd1de8bfe1474`. All `OpenClaw:` references below are relative to that root. OpenClaw schemas, manifests, source tests, and current docs are authoritative in that order.

The original NEOTH audit used exact committed HEAD `19f74b228cc6d43fc2542922bbc28e324ba52ac6`. Dirty concurrent work was treated as uncommitted work-in-progress and was not used to claim the original audit complete.

**Original audit boundary:** no source, roadmap, progress, or documentation file
was changed by that audit; this file was its only output. The execution
checkpoints below are later implementation evidence and intentionally update
the Road/Progress documents in the same integration wave.

### Current execution checkpoint (2026-07-15; plan acceptance remains open)

- The independent provider-only `import-config` path is removed. Both public
  OpenClaw names now require a complete `openclaw.json` source and enter the
  same read-only, secret-redacted inspector. The report binds the exact audited
  OpenClaw commit, pinned 26-key channel-manifest inventory digest and every
  primary/include path, byte length and SHA-256; it explicitly reports
  `apply_available=false`.
- Core now has one typed 15-channel registry. Core owns and consumes canonical
  IDs, aliases, setup keys, secret markers, Required/Optional/OneOf rules,
  capabilities, transport, lifecycle and target availability. GUI currently
  validates registry identity, aliases, setup fields, secret markers and
  requirements, while retaining checked static form bindings. Drift at those
  implemented boundaries is rejected instead of silently tolerated.
- GUI credential writes now use a bounded private stdin envelope, preserve
  exact secret bytes, never place secrets in argv, and require a channel-bound
  JSON acknowledgement before reporting remove success. `/connect` prepares
  the complete replacement candidate in memory, probes it before publication,
  rejects failed/skipped probes, then performs a file-state CAS with
  compensating keychain snapshot/rollback. Disconnect clears effective
  backend secrets. Required inbound identity policies for IRC, BlueBubbles,
  Mattermost, Google Chat, Matrix and Nostr now fail closed.
- This checkpoint does not provide account-scoped persistence, identities,
  sessions, queues, routing, credentials or runtime adapter instances. All
  current descriptors therefore state the honest legacy-default-only account
  mode. A typed `ChannelRef` is a foundation type, not proof that the message
  pipeline carries it.
- Apply/status/rollback, target-state source binding, descriptor-generated
  edit/test/remove/Buddy forms, account-aware runtime behavior, OpenClaw field
  and migration-alias parity, missing adapters and authenticated per-account
  readiness remain open. CLI operator aliases now canonicalize across
  add/remove/test/connect and required-flag planning. The five optional runtime
  fields `line_webhook_port`, `irc_port`, `irc_tls`, `irc_allowed_nick` and
  `matrix_store_path` still lack complete CLI/GUI configuration surfaces. A
  durable intent/recovery journal is also still required to recover a process
  crash between OS-keychain mutation and file publication; the current CAS
  plus compensation handles ordinary errors, not that crash window. Frozen-
  source evidence is Channel **67/67**, probes **14/14**, slash **56/56**,
  registry **6/6** and GUI **372/372**. Slack, WhatsApp Business, Discord,
  Signal, LINE and Twitch still start from transport credentials without a
  mandatory operator/sender policy; those account-scoped allow/pairing gates
  remain release work. No broad R4 box closes here.

## Required target contract

Every adopted or upgraded channel row in the ledger inherits all requirements below. A row may add stricter vendor behavior; it may not opt out silently.

### Identity and account scope

- Stable canonical `ChannelId`, accepted source aliases, and a validated `ChannelAccountId` with an explicit `default` account.
- `ChannelRef { channel_id, account_id }` is carried through inbound messages, outbound targets, identities, sessions, route bindings, pairing state, delivery queues, dedupe keys, WAL/audit records, health, and UI actions.
- Legacy NEOTH flat credentials migrate deterministically into the `default` account. Conflicting legacy and account-scoped values fail closed instead of choosing one.
- Human identity aliases become unique on `(channel_id, account_id, sender_id, chat_id)`; existing rows migrate to account `default` transactionally.

### Secrets and authentication

- Configuration stores typed secret references, never copied secret material. File, environment, OS keychain, and encrypted NEOTH credential backends remain explicit.
- QR/OAuth/device sessions use guided relink. Non-portable auth state is classified `needs_relink`, never presented as migrated.
- Every account independently reports `unconfigured`, `needs_secret`, `needs_relink`, `installing`, `connecting`, `healthy`, `degraded`, `blocked`, or `disabled` with a path-specific reason.

### Policy, sessions, and routing

- Per-account DM policy, group/channel policy, topic/thread policy, pairing, allow/block lists, mention rules, context visibility, sender-specific tool restrictions, and bot-loop protection.
- Durable session scope supports `main`, `per-peer`, `per-channel-peer`, and `per-account-channel-peer`, matching OpenClaw's explicit account-isolated form (`OpenClaw: src/routing/session-key.ts:195-223`; `OpenClaw: docs/concepts/session.md:38-50`).
- Deterministic route precedence: exact peer, parent thread, peer wildcard, guild+role, guild, team, account, then channel (`OpenClaw: docs/channels/channel-routing.md:84-94`; `OpenClaw: src/routing/resolve-route.ts:614-795`).
- Pairing allowlists are account-scoped and durable; OpenClaw stores them as `<channel>-<accountId>-allowFrom.json` (`OpenClaw: docs/channels/pairing.md:95`).
- Unknown policy combinations fail closed; OpenClaw does this for supplemental context (`OpenClaw: docs/channels/groups.md:110-120`).

### Messaging and reliability

- Typed capability declaration covers supported chat topology, media kinds, reply, reaction, edit/unsend, poll, thread/topic, native command, TTS/effect/group action, and streaming mode.
- Unsupported actions are disabled before dispatch with a reason; they do not fail after a user clicks a visible control.
- Account-aware reconnect, retry/backoff, durable outbound queue where required, idempotency/deduplication, cursor persistence, rate limiting, loop protection, startup probe, live health, and repair action.
- Delivery permits remain bound to the resolved account, destination, message body/media digest, capability, policy snapshot, and audit event.

### Product surfaces

- The registry generates CLI and GUI add/edit/probe/test/remove/status controls and Buddy quick actions. No second hardcoded channel list is allowed.
- Long installs, model/runtime downloads, QR pairing, OAuth, history synchronization, and reconnect show progress, cancel/retry, final state, and logs in CLI and GUI.
- Buddy may surface status, pairing approval, reconnect, retry, and handoff, but it cannot bypass the same policy, cost, permission, and WAL gates.

### Lossless importer

- Every JSON5/`$include` source leaf and account is ledgered with source path, effective value hash, classification, target path/action, and reason. Secret values are redacted before any report or audit write.
- Apply is bound to the exact reviewed source-set hash and importer/schema version. Source mutation invalidates approval.
- Apply stages all non-secret target state and required secret/relink/runtime actions, validates the complete target graph, then commits atomically. No channel is activated while any required leaf for that account is unresolved.
- Unknown root/channel/field/account state remains a hard blocker. `--skip` is not a valid migration-success path.

## Findings

### F-01 — Account identity is missing end-to-end

- **Priority:** P0
- **Evidence:** `InboundMessage` has channel/chat/thread/sender but no account (`SRC/neothd/src/channels/mod.rs:338-383`); identity lookup and uniqueness use only channel/sender/chat (`SRC/neothd/src/channels/identity.rs:37-90`, schema assertion at `SRC/neothd/src/channels/identity.rs:214-216`); routing is one flat destination per channel (`SRC/neothd/src/channels/routing.rs:35-143`). OpenClaw resolves account-scoped sessions and routes (`OpenClaw: src/routing/session-key.ts:195-223`; `OpenClaw: src/routing/resolve-route.ts:614-795`).
- **Impact:** Two OpenClaw accounts with the same native sender/chat identifiers can collide in identity, session, route, pairing, queue, and audit state. A lossless multi-account import is structurally impossible.
- **Effort:** XL
- **Risk:** High; persistent-key migration touches security and message delivery.
- **Confidence:** High

### F-02 — Apply remains absent; the legacy bypass and known-channel drift are closed

- **Priority:** P0
- **Current evidence (2026-07-15):** both public names now enter one `neoth-openclaw-inspect-v1` complete-source inspector. Provider-only legacy flags fail closed; the independent lossy converter is gone. The report binds every primary/include file and a deterministic source-set SHA-256, and the manifest-evidenced known-channel inventory is pinned at 26 keys including Raft, Reef and SMS. The locked `neoth-migrate` suite is 125/125 and the OpenClaw slice is 21/21. Reports still state `dry_run_only=true` and `apply_available=false`; account leaves and missing runtime semantics remain blockers.
- **Impact:** The silent-success bypass and immediate vocabulary drift are closed, but the current command is still an inspector rather than a migration. Manual re-entry remains necessary until F-01 plus Slice 7 implement source-revalidated atomic apply, status, activation and rollback.
- **Effort:** L after F-01; impossible before it.
- **Risk:** High if apply is added without source binding and atomicity.
- **Confidence:** High

### F-03 — Existing-name parity is credential-only, not behavioral

- **Priority:** P0
- **Evidence:** only selected credential fields map (`SRC/neoth-migrate/src/openclaw_channels.rs:1035-1153`); every other known field is unsupported (`SRC/neoth-migrate/src/openclaw_channels.rs:1112-1116`). NEOTH's trait lacks reactions, polls, commands, threading, policy, lifecycle, directory, bindings, status, and account contracts (`SRC/neothd/src/channels/mod.rs:409-497`), while OpenClaw types them (`OpenClaw: src/channels/plugins/types.plugin.ts:59-103`).
- **Impact:** Import can appear close to ready while silently losing policy, routing, rich messaging, lifecycle, or reliability behavior.
- **Effort:** XL across adapters, ordered after F-01/F-04.
- **Risk:** High; false parity is worse than an explicit blocker.
- **Confidence:** High

### F-04 — Canonical registry foundation exists; complete generated surfaces remain open

- **Priority:** P0
- **Current evidence (2026-07-15):** `SRC/neothd/src/channels/registry.rs`
  now owns the typed descriptor inventory, aliases, setup schema and lifecycle/
  capability metadata. Core probes/list/status and GUI status/add projection
  consume it, with enum/descriptor, setup, secret, requirement, order and total
  drift tests. The old standalone GUI status-ID constant is gone; a checked
  per-channel form/flag map remains. Credential create/remove and slash
  reconfiguration now use the private-stdin, strict-ack, pre-probe and
  compensating-rollback contracts described above. The five named optional
  runtime fields, Slint form bodies, Buddy actions and account-scoped runtime
  state are not yet generated from the descriptor contract; keychain/file
  crash recovery still needs a durable intent journal.
- **Impact:** The recurring ID/setup-list drift is closed at the current
  registry boundary. A new field/action/account capability can still be wired
  incompletely until every surface and runtime consumer is descriptor-driven.
- **Effort:** L
- **Risk:** Medium; broad UI blast radius, but it removes recurring drift.
- **Confidence:** High

### F-05 — Twelve official channels plus two first-class surfaces are absent

- **Priority:** P1, release-blocking under `GOLD-R4-07`
- **Evidence:** NEOTH's 15 registry rows are listed at `SRC/neothd/src/channels/probe.rs:218-234`; OpenClaw's public source contract additionally includes Feishu, Teams, Nextcloud Talk, QQ Bot, Reef, Raft, SMS, Synology Chat, Tlon, Voice Call, WebChat, Zalo, and Zalo Personal (`OpenClaw: docs/channels/index.md:20-47`), plus manifest-backed ClickClack (`OpenClaw: docs/channels/clickclack.md:9-19`).
- **Impact:** OpenClaw users cannot migrate these configured surfaces without dropping service or rebuilding it by hand.
- **Effort:** XL, split into bounded channel slices below.
- **Risk:** Medium-to-high by vendor; reduced by a common contract and fixtures.
- **Confidence:** High

### F-06 — Three external channels are documentation-evidenced, not source-verified

- **Priority:** P1/STOP
- **Evidence:** WeChat, Yuanbao, and Zalo ClawBot are marked external in the public index (`OpenClaw: docs/channels/index.md:42-46`). Zalo ClawBot docs explicitly do not verify behavior beyond the page (`OpenClaw: docs/channels/zaloclawbot.md:63-77`).
- **Impact:** Claiming parity or auto-installing them from docs alone would create a supply-chain and truth-in-advertising failure.
- **Effort:** M audit before implementation; implementation unknown until source review.
- **Risk:** High until exact packages are pinned and audited.
- **Confidence:** High

### F-07 — Current routing cannot express OpenClaw bindings or account defaults

- **Priority:** P1
- **Evidence:** NEOTH resolves a source/failure/default channel and then one per-channel destination (`SRC/neothd/src/channels/routing.rs:189-226`); IRC, Nostr, and Twitch destinations are explicitly stored/sidecar-only in places (`SRC/neothd/src/channels/routing.rs:73-84`). OpenClaw supports default accounts, peer/parent/guild/team/role/account/channel precedence, and broadcast fanout (`OpenClaw: docs/channels/channel-routing.md:18-20,84-100`; `OpenClaw: docs/channels/broadcast-groups.md:27-131`).
- **Impact:** Agent/persona routing, thread inheritance, broadcast behavior, and multi-account defaults cannot migrate faithfully.
- **Effort:** L after F-01.
- **Risk:** High; misrouting can disclose content to the wrong account or group.
- **Confidence:** High

### F-08 — Current GUI migration entry is discovery-only

- **Priority:** P1
- **Evidence:** GUI detects prior AI state but has no OpenClaw channel plan/apply/relink workflow (`SRC/neothd-gui/src/main.rs:14407-14450`; screen declaration `SRC/neothd-gui/ui/main.slint:1249-1259`). The importer reports blockers but performs no apply (`SRC/neoth-migrate/src/main.rs:695-717`).
- **Impact:** A non-technical user is sent from GUI discovery into manual config editing, directly contradicting zero-friction onboarding.
- **Effort:** L after importer engine exists.
- **Risk:** Medium.
- **Confidence:** High

## Exhaustive source/adoption ledger

### Legend

- **Decision:** `U` upgrade an existing NEOTH adapter; `A` adopt an official missing adapter; `S` implement as a first-class special surface; `G` guided external-plugin adoption behind a source/integrity STOP; `E` evidence-based runtime skip.
- **Topology:** `D` direct, `G` group, `C` channel/room, `T` thread/topic, `V` voice call.
- **Messaging:** `M` media, `Rp` reply, `Rx` reactions/effects, `Ed` edit/unsend, `Pl` polls, `Str` streaming/block-streaming, `Cmd` native commands, `Grp` group management.
- **Accounts:** `M` multi-account/default-account contract; `1` deliberately single/default; `Srf` a surface scoped by session/provider/number rather than a normal channel account.
- Every `U`, `A`, `S`, and eventual `G` row inherits the full target contract above: identifiers/aliases, SecretRefs, account-scoped sessions, DM/group/topic policy, pairing/lists, deterministic routing, capability-gated rich messaging, reconnect/dedup/queue/loop protection, health/status, CLI+GUI+Buddy onboarding, and fail-closed importer plan/apply. The row records vendor-specific deltas, not permission to omit that baseline.

| # | OpenClaw ID / aliases | Source shape and behavior | Account/auth evidence | NEOTH target | Decision and required delta | Primary evidence |
|---:|---|---|---|---|---|---|
| 1 | `discord` | D/C/T; M, Rx, Pl, Cmd | M; bot token, guild/role routing | `discord` | U — account scope, guild/channel/role policy, polls/reactions/threads/native actions, resume/heartbeat and loop guard | `OpenClaw: extensions/discord/src/shared.ts:120-131` |
| 2 | `feishu` (`lark`) | D/C/T; M, Rp, Rx, Ed, Str | M; app credentials; WebSocket/webhook | new `feishu` | A — preserve alias, tenant/account boundaries, thread/reply/edit/reaction/streaming and per-chat policy | `OpenClaw: extensions/feishu/src/channel.ts:173,948-961`; `extensions/feishu/src/config-schema.ts:184-273` |
| 3 | `googlechat` (`gchat`, `google-chat`) | D/G/T; M, Str | M; service account; webhook source | `gchat` via Pub/Sub | U — guided webhook-to-Pub/Sub transport relink, account policy/defaults, threads and block streaming; never copy webhook state as working | `OpenClaw: extensions/googlechat/src/channel-base.ts:30-106`; `SRC/neoth-migrate/src/openclaw_channels.rs:1083-1093` |
| 4 | `imessage` | D/G; M, Rp, Rx/effects, Grp | M; `imsg`, signed-in Mac/SSH | `imessage_bluebubbles` | U — explicit `imsg` to BlueBubbles relink, preserve chat/allow/group intent, expose Mac prerequisite and managed bridge progress | `OpenClaw: extensions/imessage/src/channel.ts:126-149,383`; `docs/channels/index.md:22` |
| 5 | `irc` | D/G; M/links, Str | M; server/TLS/SASL/password | `irc` | U — account-tag/SASL identity, channel and DM policy, reconnect/join replay, per-account routes, block streaming | `OpenClaw: extensions/irc/src/channel.ts:103-178,315` |
| 6 | `line` | D/G; M, Str | M; access token + webhook secret | `line` | U — per-account webhook signature routing, group policy, media and block streaming, replay/dedup | `OpenClaw: extensions/line/src/channel-shared.ts:25-30`; `extensions/line/src/types.ts:38-39` |
| 7 | `matrix` | D/G/T; M, Rp, Rx, Pl | M; token/password + durable E2EE store | `matrix` | U — account-scoped crypto/session stores, room/thread/poll/reaction policy, sync cursor and deterministic default-account failure | `OpenClaw: extensions/matrix/src/channel.ts:427-431,651`; `extensions/matrix/src/matrix/client/config.ts:536` |
| 8 | `mattermost` | D/G/C/T; M, Rx, Cmd, Str | M; server + bot token + WebSocket | `mattermost` | U — account scope, teams/channels/threads, reactions/native commands/streaming, reconnect and cursor/dedup | `OpenClaw: extensions/mattermost/src/channel.ts:779-785,912`; `extensions/mattermost/src/types.ts:114-116` |
| 9 | `msteams` (`teams`) | D/C/T; M, Pl, Str | M; Bot Framework secret or federated/delegated auth | new `msteams` | A — aliases, tenant/team/channel/thread routing, polls, media, SSO/delegated auth, streaming, welcome/feedback and health | `OpenClaw: extensions/msteams/src/channel.ts:83,533-542,1310`; `src/config/types.msteams.ts:81-205` |
| 10 | `nextcloud-talk` | D/G/C; M/T | M; bot/API secret + webhook | new `nextcloud_talk` | A — rooms, DM/group policies, webhook verification, reply/thread semantics, account status and setup | `OpenClaw: extensions/nextcloud-talk/src/channel.ts:47,81-86`; `extensions/nextcloud-talk/src/config-schema.ts:35-71` |
| 11 | `nostr` | D only; text | M; private key + relays | `nostr` | U — account-scoped key/relay pools, encrypted session/cursor state, pairing/allowlist and reconnect/dedup | `OpenClaw: extensions/nostr/src/channel.ts:61-108,172` |
| 12 | `qqbot` | D/G; rich M/audio, Str | M; app/client credentials | new `qqbot` | A — rich media/audio types, group policy, account-scoped secrets, commands/approval capability if evidenced, reconnect and block streaming | `OpenClaw: extensions/qqbot/src/channel.ts:255-260`; `extensions/qqbot/src/config-schema.ts:58-98`; `extensions/qqbot/src/types.ts:94-147` |
| 13 | `reef` | D/T; guarded E2EE | 1; relay/handle/guard state | new `reef` | A — retain deliberate single-account contract, E2EE guard/friend/request state, pairing, bot-loop rules and state recovery | `OpenClaw: extensions/reef/src/channel.ts:44-84`; `extensions/reef/src/config-schema.ts:21-39` |
| 14 | `raft` | D wake bridge | M; CLI account/default | new `raft` | A — human/agent wake semantics, command authorization, idempotent delivery, status and managed CLI runtime | `OpenClaw: extensions/raft/src/channel.ts:26-49`; `extensions/raft/src/config-schema.ts:7-19` |
| 15 | `signal` | D/G; M, Rp | M; `signal-cli` account/runtime | `signal` | U — installer-managed runtime, account stores, group/reply/media behavior, receive cursor, reconnect/rate limit and pairing | `OpenClaw: extensions/signal/src/channel.ts:200-217,596`; `SRC/neoth-migrate/src/openclaw_channels.rs:1065-1081` |
| 16 | `slack` | D/G/C/T; M, Rx, Cmd | M; bot/app tokens, Socket Mode/webhook | `slack` | U — workspaces/accounts, channels/threads/reactions/native commands, reconnect/resume, bot loop and team routing | `OpenClaw: extensions/slack/src/shared.ts:73-78`; `extensions/slack/src/channel.setup.ts:33-36` |
| 17 | `sms` | D; text only | M; Twilio secret + signed webhook | new `sms` | A — E.164 normalization, signature policy, sender allowlist, account/number routing, dedup, rate/queue/status | `OpenClaw: extensions/sms/src/channel.ts:46-48,230-238,313`; `extensions/sms/src/config-schema.ts:16-43` |
| 18 | `synology-chat` | D; M | M; token + incoming/outgoing webhooks | new `synology_chat` | A — webhook verification, account status, allowlist, rate limit, TLS policy, media and delivery dedup | `OpenClaw: extensions/synology-chat/src/channel.ts:87-89,317-325,420`; `extensions/synology-chat/src/types.ts:6-24` |
| 19 | `telegram` | D/G/C/T; M, Rx, Pl, Cmd, Str | M; bot token | `telegram` | U — account scope, topic/thread sessions, polls/reactions/native commands, block streaming, retry/spool/durable queue and dedup | `OpenClaw: extensions/telegram/src/shared.ts:160-172`; `extensions/telegram/src/bot-core.ts:161-218`; `extensions/telegram/src/action-runtime.test.ts:699-806` |
| 20 | `tlon` (`urbit`) | D/G/T; M, Rp | M; ship/url/code | new `tlon` | A — alias, room/invite/DM lists, auto-discovery, thread/reply semantics, session recovery and status | `OpenClaw: extensions/tlon/src/channel.ts:55-108`; `extensions/tlon/src/config-schema.ts:25-52` |
| 21 | `twitch` (`twitch-chat`) | G only; text | M; OAuth identity/channel joins | `twitch` | U — alias, explicit group-only capability, account joins, mention/allow policy, IRC reconnect and dedup | `OpenClaw: extensions/twitch/src/plugin.ts:92-97`; `extensions/twitch/src/config-schema.ts:22-74` |
| 22 | Voice Call | V; full duplex, realtime, transcription | Srf; provider + number routing, SecretRefs | first-class `voice_call` surface | S — inbound/outbound call policy, per-number route/session, realtime lifecycle, transcript/media audit, reconnect, GUI/CLI/Buddy call controls | `OpenClaw: docs/plugins/voice-call.md:11-13,50-95,168-186,232-244,584-620,682-688` |
| 23 | WebChat | D web session; live delivery + durable transcript | Srf; gateway auth/session | first-class NEOTH WebChat | S — account/session identity, reconnect by session ID, idempotency-key dedup, transcript/live-state distinction, GUI/Buddy handoff | `OpenClaw: docs/web/webchat.md:10-45,62-77` |
| 24 | `wechat` / package `openclaw-weixin` | D only; M | M; QR + persisted tokens | quarantined external adapter | G — exact package source/license/integrity audit, then signed managed install, QR relink, per-account monitor/session/pairing; no activation from docs alone | `OpenClaw: docs/channels/wechat.md:11-16,24-45,70-98` |
| 25 | `whatsapp` | D/G/C; M, Rx, Pl | M; Baileys QR/auth state | `whatsapp_baileys` | U — never map to Meta Business, account-scoped QR relink, group/mention policy, broadcasts, connection-state persistence, reconnect/dedup/queue | `OpenClaw: extensions/whatsapp/src/shared.ts:167-171`; `extensions/whatsapp/src/channel.ts:98-106,220-320`; `SRC/neoth-migrate/src/openclaw_channels.rs:1040-1045` |
| 26 | `yuanbao` | D/G; M, Cmd, Str | M; external package credentials | quarantined external adapter | G — exact package/source/integrity audit, then bindings, accounts/default, policies, media/streaming/native commands and guided install | `OpenClaw: docs/channels/yuanbao.md:9-11,40-64,128-139,170-205,279-350` |
| 27 | `zalo` (`zl`) | D/G; M, Str | M; bot token/file + webhook secret | new `zalo` | A — alias, webhook policy, DM/group policy, proxy/media, account scope, pairing and block streaming | `OpenClaw: extensions/zalo/src/channel.ts:133-199,275`; `extensions/zalo/src/config-schema.ts:13-27` |
| 28 | `zaloclawbot` | owner-bound personal Zalo; behavior not source-verified | unknown; QR + long poll | quarantined external adapter | G/STOP — audit exact package first; only then owner binding, credential state, long-poll cursor/reconnect, policy and managed QR setup | `OpenClaw: docs/channels/zaloclawbot.md:9-29,63-77` |
| 29 | `zalouser` | personal Zalo; D/G; M | M; QR/session state | new `zalo_personal` | A — account-scoped QR relink, pairing/allowlists, group/media behavior, session persistence and reconnect | `OpenClaw: extensions/zalouser/src/channel.adapters.ts:216-224`; `extensions/zalouser/src/channel.ts:218`; `extensions/zalouser/src/types.ts:103-121` |
| 30 | `clickclack` | D/G/T; Str | M; token/ref/file, workspace, model/agent mode | new `clickclack` | A — index omission is not a skip; account/default, workspace/mode, reconnect, activity, command menu, durable idempotent send | `OpenClaw: docs/channels/clickclack.md:9-19,67-123,209-228`; `extensions/clickclack/src/channel.ts:118-128` |
| 31 | `qa-channel` | synthetic deterministic fixtures | M in tests only | no runtime channel | E — explicit evidence skip because it is package-excluded; adopt its multi-account fixture/harness patterns into NEOTH tests | `OpenClaw: docs/channels/qa-channel.md:10-20,60-63`; `extensions/qa-channel/src/channel-base.ts:17-22` |

### NEOTH-only additive rows

These do not reduce the OpenClaw ledger count and must not be removed:

- `whatsapp_business`: keep the Meta Cloud transport separate from `whatsapp_baileys`; both receive account-scoped descriptors, policies, routing, health, onboarding, and migration-safe names. Existing code already keeps their credentials and route destinations separate (`SRC/neothd/src/config/credentials.rs:163-189`; `SRC/neothd/src/channels/routing.rs:48-53,92-104`).
- `keet`: retain the repository-owned Keet/Pears companion and bring it under the same account, lifecycle, capability, GUI/CLI/Buddy, artifact, and clean-machine gates. OpenClaw parity must not demote this NEOTH differentiator.

## Ordered implementation slices

No later slice may claim closure while an earlier dependency is incomplete. Small per-channel commits are required; do not land all adapters in one release-sized change.

### Slice 0 — Freeze a generated OpenClaw contract fixture

**Goal:** replace the handwritten, drifting source vocabulary with a reproducible, pinned input.

**Changes:**

1. Add a repository script that accepts an OpenClaw checkout and required commit, refuses a dirty/mismatched checkout, and extracts:
   - channel manifests and canonical IDs;
   - aliases and setup visibility;
   - account/default-account schema paths;
   - credential/SecretRef paths without values;
   - capabilities, policy fields, routing/binding fields, lifecycle/status hooks;
   - the special Voice Call/WebChat docs-backed surfaces;
   - external plugin references as quarantined entries;
   - ClickClack as manifest-backed even though the public index omits it;
   - QA Channel as `test_only=true`.
2. Commit the normalized fixture under `SRC/neoth-migrate/fixtures/openclaw/4c667aac8859114bd8f0a589ac6cd1de8bfe1474/` with source commit, extractor version, file hashes, and the 31-row classification.
3. Generate `KNOWN_CHANNEL_KEYS`, aliases, common fields, and per-channel field vocabulary for the importer from that fixture. Hand-edited duplicates become a test failure.
4. Add a drift test: an added manifest/schema leaf without a disposition fails with its exact source path.

**Acceptance:** 29 public surfaces + ClickClack + QA are accounted for; 26 channel manifests are recognized; Voice Call/WebChat/external docs rows are explicit; `raft`, `reef`, and `sms` can no longer drift out of the importer unnoticed.

### Slice 1 — Introduce account-scoped channel primitives and migrate persistence

**Goal:** make multi-account behavior representable before importing or adding channels.

**Changes:**

1. Add validated `ChannelId`, `ChannelAccountId`, and `ChannelRef` types. Canonicalize aliases at the boundary; never store aliases internally.
2. Add `account_id` to `InboundMessage`, outbound/proactive targets, delivery permits, channel WAL bodies, dedupe keys, queue entries, health rows, and runtime handles.
3. Replace flat channel credential fields with account-scoped public configuration plus account-scoped secret records. Preserve a one-way, transactional legacy migration into `default`; do not dual-write forever.
4. Migrate `idx_human_identity_aliases` to `(channel, account_id, sender_id, chat_id)` uniqueness. Copy legacy rows with `account_id='default'`, validate counts/digests, swap tables transactionally, and retain rollback backup until startup verification succeeds.
5. Include account ID in session keys, pairing/list state, cursor/reconnect state, outbound queue/idempotency state, channel metrics, audit/WAL, and proactive routes.
6. Reject configurations with multiple enabled accounts and no deterministic default instead of selecting first map order.

**Acceptance:** two accounts on the same channel can use identical sender/chat IDs without identity, session, route, queue, or audit collision. Legacy single-account installations produce byte-equivalent observable behavior under `default`.

### Slice 2 — Build one typed channel registry and capability schema

**Goal:** remove the fixed parallel lists and give every surface one production truth.

**Changes:**

1. Define a `ChannelDescriptor` containing canonical ID, aliases, transport, account mode, credential/setup schema, policy capabilities, messaging capabilities, runtime dependencies, health/probe/repair actions, migration aliases, and provenance.
2. Extend the adapter boundary with typed capability/policy/lifecycle/status interfaces. Keep unsupported operations unrepresentable or return a pre-dispatch capability error.
3. Generate Core inventory, CLI names/help/completion, GUI rows/forms/action availability, Buddy actions, importer target vocabulary, docs tables, and release asset requirements from the same registry.
4. Make duplicate IDs/aliases, missing setup consumers, missing probe/status hooks, and descriptor/adapter disagreement startup and CI failures.

**Acceptance:** deleting or adding one descriptor produces a deterministic diff in every generated consumer; no GUI/Core 15-ID arrays remain.

### Slice 3 — Implement common policy, session, routing, and reliability engines

**Goal:** centralize behavior that should not be reimplemented inconsistently in every adapter.

**Changes:**

1. Add typed per-account DM policy (`pairing`, `allowlist`, `open`, `disabled`), group/channel policy, thread/topic policy, mention rules, context visibility, sender tool rules, and pairing/allow/block stores.
2. Implement account-scoped DM session modes and group/channel/thread session keys with parent-thread inheritance.
3. Replace flat proactive destinations with typed route bindings and deterministic peer/parent/guild+role/guild/team/account/channel precedence. Add explicit broadcast groups with isolated agent sessions.
4. Add shared reconnect/backoff, bounded queue, retry classification, idempotency/dedupe, cursor checkpoint, rate limit, loop protection, health, and repair interfaces. Vendor adapters supply protocol details; the state machine and audit contract stay common.
5. Preserve OpenClaw's safe loop-guard limitation: only auto-enable identity-based bot-loop protection where a protocol exposes reliable bot identity; otherwise fail closed or require explicit operator identifiers (`OpenClaw: docs/channels/bot-loop-protection.md:10-25,47-55,109-116`).

**Acceptance:** policy/session/route/reliability conformance tests run against every descriptor, including disabled and partial-config cases.

### Slice 4 — Upgrade the 13 overlapping OpenClaw adapters

Implement and verify one bounded sub-slice per adapter: Telegram, Slack, WhatsApp Baileys, Discord, Signal, iMessage/BlueBubbles, Matrix, LINE, IRC, Mattermost, Twitch, Nostr, and Google Chat.

For each sub-slice:

1. Fill the descriptor and account-scoped config/secret schema.
2. Wire add/edit/probe/test/remove, inbound/outbound, policy/session/routing, capability actions, reconnect/dedup/queue/status/repair, and CLI/GUI/Buddy.
3. Import every pinned source field or classify it path-specifically.
4. Run the shared conformance suite plus vendor fixtures.
5. Prove no legacy default-account regression.

Mandatory transport conversions:

- OpenClaw `whatsapp` always targets NEOTH `whatsapp_baileys`, never Meta Business. QR auth is relinked.
- OpenClaw `imessage` uses `imsg`; NEOTH uses BlueBubbles. Preserve intent and routing, but block activation until BlueBubbles is configured and probed.
- OpenClaw Google Chat uses a webhook; NEOTH uses Pub/Sub. Preserve policies/account/bindings, but require a guided GCP relink and successful probe.
- Signal runtime lifecycle becomes installer-managed; a configured phone number without a healthy runtime remains blocked, not “configured.”

### Slice 5 — Adopt the 12 missing official channel adapters

Build these in dependency-ordered batches, with one commit and one fixture set per channel:

1. **Webhook/API batch:** Feishu/Lark, Microsoft Teams, Nextcloud Talk, QQ Bot, SMS, Synology Chat, Zalo Bot.
2. **Connection/decentralized batch:** Reef, Raft, Tlon/Urbit, ClickClack, Zalo Personal.

Each adapter must meet the complete target contract, not only text send/receive. Runtime helpers and SDKs are bundled in the release or fetched by a signed, version-bound NEOTH installer with visible progress and rollback. A user must never be told to install Node, Python, Rust, `signal-cli`, or a verifier manually.

### Slice 6 — Implement special surfaces and resolve external-plugin STOPs

1. Implement Voice Call as a first-class permissioned surface with provider/number routing, inbound and outbound policy, realtime/full-duplex lifecycle, transcripts, reconnect, status, and GUI/CLI/Buddy controls.
2. Implement WebChat as a first-class session surface using the same routing, identity, permission, transcript, reconnect, and idempotency contracts as channel traffic.
3. For WeChat, Yuanbao, and Zalo ClawBot:
   - resolve the exact package name/version/source commit/license;
   - verify package-to-source integrity and dependency/runtime requirements;
   - threat-model QR/session credentials and update behavior;
   - decide native port versus bundled signed plugin;
   - only then add a descriptor and managed onboarding.
4. Until that audit passes, importer rows remain quarantined and activation-blocking. The product may show “detected; source audit required,” but may not claim support.

### Slice 7 — Turn the inspector into atomic plan/apply migration

**CLI contract:**

```text
neoth-migrate import-openclaw plan  --config <openclaw.json> --output <plan.json>
neoth-migrate import-openclaw apply --plan <plan.json> --confirm
neoth-migrate import-openclaw status --migration-id <id>
neoth-migrate import-openclaw rollback --migration-id <id> --confirm
```

**Engine changes:**

0. [x] Retire `import-config` as an independent lossy conversion engine. During compatibility, make it a deprecated front end to the same canonical plan ledger: sensitive source paths become path-specific `needs_secret`/`needs_relink` actions, unknown provider kinds block, and no leaf is silently dropped or counted as a successful skip. **Closed 2026-07-15:** both names use the one complete-source inspector; provider-only flags fail closed.
1. [x] Parse JSON5 and `$include` with existing byte/count/depth limits; record canonical source paths and hashes for every included file. **Closed 2026-07-15:** lossless relative path, byte length and SHA-256 per primary/include file plus deterministic contract-bound source-set hash.
2. Inspect channel config plus channel-coupled non-secret state: default accounts, bindings, broadcast groups, pairing/allow/block IDs, routing, portable session metadata, and runtime requirements. Auth stores, tokens, cookies, device keys, and QR sessions are never copied.
3. Produce a complete per-leaf/per-account ledger with `mapped`, `needs_secret`, `needs_relink`, `needs_runtime`, `explicit_skip`, `unsupported`, or `unknown`. `unsupported`, `unknown`, unaccepted skip, or unresolved required action blocks apply/activation.
4. [ ] Bind the reviewed plan to source-set digest, pinned OpenClaw schema commit, NEOTH target version, registry digest, and importer version. **Partial 2026-07-15:** the read-only report and its source-set hash now bind the audited source commit, migrator/target version and the 26-key known-channel inventory digest. The future generated target-registry digest and apply-time revalidation remain open.
5. Stage target public config, secret-reference placeholders, route/policy/session state, pairing IDs, and required action queue under one migration ID. Validate the full target graph before publication.
6. Publish config/database changes transactionally with backups and a commit marker. Crash before marker resumes or rolls back deterministically; rerun is idempotent.
7. Execute secret prompts, OAuth/QR relinks, managed runtime installs, and transport conversions through the normal channel onboarding engine. Activate each account only after its probe and capability conformance check pass.
8. Emit a secret-redacted before/after report and durable WAL audit. Reports include every source path and never print sensitive values.

**Acceptance:** a source mutation after review blocks apply; injected unknown fields block at their exact paths; a failure at any staging/publication point leaves the previous NEOTH state active; two accounts remain distinct; no secret appears in stdout, plan, backups, WAL, or GUI logs.

### Slice 8 — Wire zero-friction CLI, GUI, Buddy, and managed dependencies

1. Add a single onboarding engine consumed by CLI and GUI. It handles account selection/naming, secret refs, QR/OAuth, policies, default account, routes, capabilities, test message, and activation.
2. GUI and CLI expose the same account list and add/edit/probe/test/disable/remove/repair actions. Remove is transactional and offers data/session retention choices.
3. Add an OpenClaw migration screen: detection, source selection, complete preflight ledger, blockers, per-account actions, progress, cancel/resume, apply, verification, and rollback.
4. Buddy exposes safe quick actions: channel/account health, reconnect, retry, pairing approval, migration progress, and open-full-GUI/CLI handoff. It never handles raw secrets in notifications.
5. Install-on-demand dependencies use versioned signed manifests, resumable downloads, content hashes, disk-space checks, progress, cancellation, rollback, and offline explanation. Required release components are prebundled where licensing/size permits.
6. Presets and preloads may recommend/configure integrations only through real descriptors. A preset cannot mark a channel ready until credentials/runtime/probe are complete.

### Slice 9 — Release, docs, and exact-head proof

1. Generate the channel matrix, configuration reference, CLI docs, GUI labels, migration support table, and runtime asset list from the registry/fixture.
2. Update README, getting-started, install, migration, architecture, security, release notes, wiki, Obsidian baseline, and SVGs only after the generated/runtime gates pass. Claims distinguish native, bundled, managed-download, external-quarantined, platform-limited, and test-only surfaces.
3. Package all native adapters and permitted required sidecars; ship the signed managed-download catalog for size-heavy optional runtimes. Test archive and installed layouts.
4. Run clean-machine install → first run → OpenClaw migration → interface switch → send/receive/probe → repair → update → rollback → uninstall on supported Windows, macOS, and Linux targets.
5. Require exact-head CI, Security, CodeQL, artifact-content tests, installer smoke tests, and channel-contract drift tests before the v1.0.0 tag.

## Verification gates

Commands are run from `SRC/` unless stated otherwise. Local environment limitations do not weaken CI/release requirements.

### Fast structural gates

```powershell
cargo +1.91 fmt --all -- --check
cargo metadata --no-deps --format-version 1
cargo +1.91 test -p neoth-migrate --locked openclaw
cargo +1.91 test -p neoth --locked --lib channels
cargo +1.91 test -p neothd-gui --locked channel
git -C .. diff --check
```

### Required new focused suites

- `openclaw_contract_fixture`: exact source commit, clean checkout, manifest/docs inventory, 31 classified rows, 26 manifest-backed channel plugins, no unclassified schema leaf.
- `channel_account_migration`: legacy-to-default, multi-account collision isolation, conflict fail-closed, rollback, crash-resume, idempotency.
- `channel_registry_conformance`: unique IDs/aliases, descriptor/adapter match, generated Core/CLI/GUI/Buddy/importer/docs parity, no orphan setup action.
- `channel_policy_conformance`: DM/group/topic/pairing/list/context/tool/loop default and override behavior for every descriptor.
- `channel_session_routing`: all four DM scopes, thread inheritance, guild/team/role/account precedence, broadcast isolation, wrong-account disclosure regression.
- `channel_reliability_conformance`: reconnect/backoff, cursor, duplicate inbound, duplicate outbound idempotency key, queue crash recovery, bounded retries, health transition and repair.
- `openclaw_migration_plan_apply`: JSON5/includes, source mutation, unknown leaf/provider kind, duplicate key, SecretRef redaction, QR/OAuth relink, managed runtime, atomic publication, rollback, two-account end-to-end, and a regression proving legacy `import-config` cannot bypass the ledger or silently drop a source leaf.
- Per-channel recorded protocol fixtures for every `U` and `A` row; real sandbox/vendor smoke tests where providers offer test tenants.
- GUI event-loop tests for add/edit/probe/remove, QR/OAuth, download progress/cancel/retry, migration blockers/apply/rollback, and Buddy handoff.

### Full release gates

```powershell
cargo +1.91 test --workspace --locked
cargo +1.91 clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo +1.91 fmt --all -- --check
```

Additionally:

- Windows installer, macOS package/app, Linux package, and portable archives contain all registry-required assets for their advertised feature set.
- Clean machines require no preinstalled verifier, language runtime, compiler, or package manager.
- Exact artifact binaries pass `neoth channel contract verify --registry-digest <digest>` and migration fixture replay.
- Generated docs and Wiki/Obsidian self-knowledge carry the same registry digest as the release.
- An offline run never claims a runtime was installed; a failed download leaves the prior version intact and is resumable.

## Dependencies and STOP conditions

| Dependency / condition | Required before | STOP behavior |
|---|---|---|
| Clean OpenClaw checkout at exact audited commit | Fixture regeneration | Refuse generation; print expected/actual commit and dirty paths |
| Slice 1 account/persistence migration green | Any multi-account import or new account UI | No flattening fallback; keep migration plan blocked |
| Canonical descriptor and generated consumers | Adapter adoption | Do not add another hardcoded Core/GUI/importer list |
| Complete source-leaf classification | Migration apply | Block at every unknown/unsupported path; no `--skip` success |
| Secret/relink/runtime action unresolved | Account activation | Stage disabled account; show exact action and preserve old active state |
| External plugin exact source/license/integrity unresolved | WeChat/Yuanbao/Zalo ClawBot install | Quarantine only; no support claim or executable download |
| Runtime cannot be bundled or signed-managed | Channel “ready” state | Report unavailable with evidence; do not tell users to install a developer dependency manually |
| Platform/account prerequisite absent | Probe/activation | Guided actionable state; never fake readiness |
| Registry/docs/artifact digest mismatch | Release tag | Release job fails before build/publish matrix |
| Any required clean-machine or exact-head security gate red | v1.0.0 tag | Tag and publication remain blocked |

## Migration rollout and rollback

1. Ship the account model and legacy migration disabled behind a format-version gate; run read/validate rehearsal before first write.
2. On first compatible start, back up public config and affected database tables, migrate to `default`, validate row counts/digests, then publish the new format marker.
3. Keep existing adapters on the new descriptor/account engine before adding missing channels. This proves the foundation under current traffic.
4. Enable OpenClaw `plan` broadly while `apply` remains feature-gated. Collect only redacted disposition counts and explicit operator reports; no config contents.
5. Enable apply per channel after that channel's conformance and clean-machine migration fixture is green.
6. Rollback restores the pre-migration public config/database snapshot and disables newly created accounts/runtimes. It never attempts to reconstruct or copy OpenClaw auth secrets.
7. Once the target format is proven across one stable release, remove legacy dual-read code in a separately reviewed migration cleanup; keep import support for the documented prior NEOTH format.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Account key migration misroutes private content | Transactional schema swap, old/new digest checks, account in every permit/WAL key, adversarial wrong-account tests |
| Secret leakage through plans, logs, backups, or GUI | Parse/classify sensitivity before rendering, SecretRefs only, leak-canary tests over every artifact and log sink |
| “Parity” reduced to text messaging | Registry conformance requires policy, capability, reliability, health, setup, UI, and importer hooks per descriptor |
| One giant adapter wave becomes unreviewable | One channel/sub-slice per commit with shared conformance tests; batch only dependency plumbing |
| External plugin supply-chain compromise | Exact source/package checksum/license audit, signed version catalog, sandboxed permissions, quarantine until verified |
| Release size explodes | Prebundle small/common components; signed managed download for large optional runtimes with progress/offline/rollback |
| Vendor API tests are flaky or paid | Deterministic recorded fixtures for CI plus scheduled opt-in sandbox smoke; never replace real smoke entirely with mocks |
| Generated schema becomes stale | Pin source commit and input hashes; extractor drift gate; every unclassified manifest/schema leaf fails CI |
| Hardware/cloud prerequisites prevent literal one-click setup | Automate software and verification; clearly guide the unavoidable vendor login, QR, tenant approval, phone number, or Mac requirement |

## Definition of done

- [ ] The pinned fixture accounts for all 31 audited rows: 29 public, ClickClack, and QA test-only.
- [ ] Every source manifest/schema leaf has a path-specific migration disposition.
- [ ] `ChannelAccountId` reaches config, credentials, messages, identities, sessions, routing, pairing, queues, runtime state, health, permits, WAL, CLI, GUI, Buddy, and importer.
- [ ] Legacy flat NEOTH channel configuration migrates transactionally to `default` with no behavior regression.
- [ ] One canonical descriptor generates Core/CLI/GUI/Buddy/importer/docs/artifact consumers; no parallel hardcoded channel lists remain.
- [ ] All 13 overlapping adapters satisfy their pinned behavioral contracts.
- [ ] All 12 missing official adapters are implemented and clean-machine qualified.
- [ ] Voice Call and WebChat are first-class, fully gated surfaces.
- [ ] WeChat, Yuanbao, and Zalo ClawBot are either source-verified and fully managed or carry an explicit evidence-backed release decision; docs-only support claims are forbidden.
- [ ] QA Channel remains excluded from runtime while its deterministic multi-account harness patterns are adopted.
- [ ] WhatsApp Baileys and WhatsApp Business remain distinct; OpenClaw WhatsApp never maps to Business.
- [ ] iMessage and Google Chat transport conversions are guided relinks with blocked-until-probed activation.
- [ ] OpenClaw migration supports plan/apply/status/rollback, exact source binding, atomicity, crash resume, idempotency, and secret-redacted audit.
- [ ] CLI, GUI, and Buddy expose equivalent per-account onboarding, status, repair, migration, and progress states.
- [ ] Required runtimes are bundled or signed-managed; no compiler/runtime/verifier installation is delegated to the user.
- [ ] Clean-machine Windows/macOS/Linux installer and migration journeys pass from exact release artifacts.
- [ ] Generated README/docs/wiki/Obsidian/SVG claims match the release registry and artifact digest.
- [ ] Exact-head CI, Security, CodeQL, release artifact, channel-contract, and installer gates are green.
- [ ] Only after all boxes above are evidence-backed may `GOLD-R4-07` and dependent v1.0 release gates be closed.
