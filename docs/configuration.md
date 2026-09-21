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
| `~/.neoth/self_improve.yaml` | Operator switch and exact verifier-command allowlist for self-improvement. |
| `~/.neoth/self_improve_eval/v1/` | Fixed, operator-maintained evaluation corpora for self-improvement quality evidence. |

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

### Proactive delivery

Proactive delivery remains opt-in. Its `freedom.yaml::proactive` block controls
when a queued unsolicited message may enter the dispatcher; it does not bypass
the selected channel's route, account, sender, permission, or policy checks.

```yaml
proactive:
  enabled: false                     # default: no unsolicited delivery
  # quiet_hours_utc: [22, 7]         # optional UTC silence window
  idle_only: false                   # require an inactive operator when true
  idle_only_window_secs: 300         # inactivity threshold when idle_only
  delivery_attempt_timeout_secs: 60  # one-attempt deadline; valid: 1..300
```

`delivery_attempt_timeout_secs` is the absolute wall-clock budget for one
proactive channel-delivery attempt. It defaults to 60 seconds and is validated
inclusively between 1 and 300 seconds. When the deadline expires, NEOTH
cancels that attempt instead of leaving a channel operation unbounded; the
normal recovery and recorded outcome path then determines the queue state.
Changing this setting cannot turn on proactive messaging: `enabled: true` is a
separate, explicit opt-in.

### Code-map context

`code_map.auto_context_max_files` is an explicit opt-in for automatic repository
context. Its default is `0`, so normal `neoth chat` and Channel messages do not
read the code map or receive a `<repo-context>` prompt block. Set it above zero
only for bounded automatic context; valid values are `0..=200`.

One-shot `neoth code` uses separate bounds:

```yaml
code_map:
  auto_context_max_files: 0       # Chat/Channel auto-context; valid: 0..200
  coding_recall_max_files: 8      # recalled files per code invocation; 1..50
  coding_callers_per_symbol: 3    # depth-one callers per symbol; 0..20
  coding_summary_token_budget: 2048 # generic repo-map summary; 128..12000
  requested_context_max_bfs_depth: 20 # explicit MCP callers/callees only; 1..20
  outline_enrichment: false       # master switch for the configured ReadPath sidecar
  enrichment_selectors: []        # default: no MCP call is selected
  impact_policy:
    max_depth: 3                  # impact/default ceiling; 1..32
    max_nodes: 250                # impact/default ceiling; 1..10000
    allow_stale: false            # fixed false; stale graphs cannot authorize coding
```

`impact_policy` is loaded once by `neoth code-map impact`, `diff-impact`, and
`diff-test-gaps`; omitted limits use the policy values and explicit limits may
only tighten them. A daemon supplies the same accepted immutable limits only to
its exact generated `neoth-codegraph` child. Generic `neoth mcp codegraph-serve`
remains static-default and never reads `freedom.yaml`.
CodingService and CLI Apply also freeze this policy with their selected database
and physical root for the pre-apply advisory; they do not replace it with default
impact limits. The advisory cannot grant approval or alter risk-gate decisions.

`coding_callers_per_symbol: 0` disables only caller enrichment. It does
not disable targeted recall. `coding_summary_token_budget` is a local heuristic

Requested code-map context is separate from automatic Chat/Channel context.
The existing `coding_recall_max_files`, `coding_callers_per_symbol`, and
`coding_summary_token_budget` form one immutable per-command/per-turn snapshot.
`coding_callers_per_symbol` is a direct caller-row count used by `neoth code`;
it is not graph traversal depth. The explicit MCP callers/callees tools use
`requested_context_max_bfs_depth`, default 20, and their existing `depth`
argument may only tighten that ceiling. For the exact generated codegraph child,
the same snapshot also limits recall `limit` and the rendered success payload to
`min(coding_summary_token_budget * 4, 65536)` UTF-8 bytes. An oversized result
is returned as a typed MCP error rather than partial JSON. Raw `neoth mcp
codegraph-serve` retains its documented static defaults; it never reads
`freedom.yaml`. Automatic `auto_context_max_files` injection happens before a
provider tool request and neither receives nor implies requested-context authority.
for the generic repo-map summary, not a provider billing meter and not a cap on
the full combined coding context. The graph-memory caps and decomposer's 12k
input guard remain in force. The targeted selection and generic summary share
a 64-KiB rendered-context ceiling and bounded metadata storage; their receipt
reports source selection limits and later decomposer truncation separately.

`code_map.outline_enrichment` defaults to `false`, and
`code_map.enrichment_selectors` defaults to an empty list. The existing W53
built-in `neoth-codegraph`/`codegraph_outline` route remains governed by the
master switch. A W95 configured-provider call additionally requires one exact,
typed selector:

```yaml
code_map:
  outline_enrichment: true
  enrichment_selectors:
    - server_id: workspace-reader
      tool: read_path
      kind: ReadPath
      path_field: path
```

It pins the exact configured `(server_id, tool)` pair and accepts only one
strict `{ path: string }` projection. The example is a configured external
provider pair. A selector does not enable the server or tool, change its
allowlist, trust a provider input schema, or grant filesystem authority. The
generated local `neoth-codegraph` descriptor remains a separate requirement
from the same accepted MCP configuration snapshot as the selected provider
tool; remote MCP entries such as `hex-ssh` are never mapped to a local code-map
root merely because they also contain a `path` argument. `Grep`,
`Glob`, `Bash`, aliases, case-folded matching, and tool-name guessing are not
configured variants. After an accepted `neoth reload`, the next request uses
the accepted immutable snapshot; an invocation already in progress keeps its
own snapshot.

The Coding panel's **Check enrichment readiness** action and Buddy's
**Check codegraph enrichment readiness** action inspect this policy and the
managed-root evidence without changing either. They distinguish disabled,
ready and unavailable states for the NEOTH home, separately from selected-root
status. They do not invoke a selector or grant a tool permission; see
[enrichment readiness](code-map-lifecycle.md#check-enrichment-readiness).

After an accepted reload, each daemon Chat or Channel message resolves a fresh
configuration snapshot. A one-shot `neoth code` command resolves these limits
when its next invocation begins; an invocation already in progress keeps its
own snapshot. Inspect the retained selection, generation, redaction and
truncation evidence through the [coding code-map receipt contract](coding-code-map-receipts.md).

#### Managed code-map lifecycle

The daemon-managed lifecycle is separate from the Chat/Channel opt-in above and
is disabled by default. It needs an explicit list of existing, absolute
repository roots; the daemon never infers a root from its service working
directory. On validation, NEOTH canonicalizes every root to its physical
identity and rejects aliases, duplicate roots, parent/child overlap, more than
eight roots, or `enabled: true` without a root.

```yaml
code_map:
  lifecycle:
    enabled: false
    managed_roots:
      # - C:/work/my-repository
    debounce_millis: 500              # 50..60000
    reconciliation_interval_secs: 300 # 30..3600
```

`debounce_millis` coalesces a burst of filesystem changes into one refresh.
An event only marks its own managed root dirty; it never proves the snapshot is
fresh. `reconciliation_interval_secs` runs the bounded strong freshness check
so missed filesystem notifications cannot become a false-fresh result. At
startup, a managed root reconciles its durable in-flight refresh before its
watcher accepts events. Disabling the lifecycle or removing a root during an
accepted reload cancels and joins its active refresh before that watcher stops.
The daemon atomically publishes its observed ownership at
`<instance-home>/code_map_lifecycle_status.json`. That snapshot distinguishes
the requested configuration from active roots, records the reload generation
and recent reconciliation/failure state, and is accepted by readers only while
the matching daemon PID still owns the instance lock. A retained file after a
crash therefore is not evidence that a watcher remains active.
See the [code-map lifecycle runbook](code-map-lifecycle.md) for `status`,
manual refresh, and explicit corrupt-store repair.

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

Shared channel workspaces can contain additional pseudonymous subjects, but the
generic export CLI has no authenticated private-DSAR authority for them.
`neoth export --list-subjects` and `neoth export --subject <handle>` are kept
only for parser compatibility and fail closed before reading state, creating an
output directory, or printing a handle. No local or sovereignty-based shortcut
acts as DSAR authority.

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
erasure command and a redacted default export. The generic export contains only
active concrete accommodations plus non-sensitive schema/presence/redaction
metadata; it has no single-subject DSAR export until a separate authenticated
authority is implemented. Topic forget
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
The passphrase derives the `ClusterKey` used for rendezvous/bootstrap HMAC
proof; it is not a membership list or authorization source. Stable local
identity is persisted separately in owner-private
`cluster-node-identity.json`, and authoritative member state lives in
`cluster-membership.db`. Discovery produces candidates only. An `Active`
binding requires an authority-issued, short-lived, one-time invite followed by
confirmation of the peer's exact carrier-bound signed `EndpointAttestation`.
Legacy `cluster.yaml` rows import once as unattested `Pending` state.
For mDNS v2, the ClusterKey HMAC filters the rendezvous domain while a separate
`LocalNodeIdentity` signature authenticates the candidate's stable identity and
exact Peeroxide endpoint. Both checks remain pre-authority and grant no
membership.

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
  skill_overrides:
    web-research:
      level: standard
    repo-maintenance:
      level: custom
      overrides:
        exec_arbitrary: deny
        write_outside_home: confirm
```

### Per-skill autonomy caps

`custom_autonomy.skill_overrides` is an operator-owned map keyed by canonical
Skill IDs. Each entry is a cap for actions performed through that selected
Skill; it is evaluated per action together with the global autonomy policy.
The restrictive result wins: a skill cap can retain or reduce an `allow` to
`confirm` or `deny`, but it cannot loosen a global, channel, subject, tool, or
other existing restriction. A cap does not replace the full safety floor.

This policy is not part of a Skill manifest. An installed package cannot grant
itself a higher autonomy level or replace the operator's cap. Missing
`skill_overrides` remains compatible with existing configuration and means no
per-skill cap is configured.

Use the canonical CLI surface with the global output selector:

```text
neoth --output json autonomy skill show <skill-id>
neoth --output json autonomy skill set <skill-id> <strict|standard|elevated|full|custom> [--action <action-kind>=<allow|confirm|deny>]...
neoth --output json autonomy skill reset <skill-id>
```

`--action` is accepted only with `custom`. Action names use the stable
lower-snake-case permission names shown by `neoth permissions show`; every
argument must have exactly one `action-kind=allow|confirm|deny` pair and an
action may appear only once. `set` requires the named Skill to be present in
the locally authority-admitted inventory. `reset` intentionally accepts any
canonical Skill ID and removes only that map entry, even if the Skill is now
disabled, revoked, missing, or otherwise not admitted. This prevents an old
restriction from becoming unremovable while it does not reactivate the Skill.

JSON `show` reports the exact persisted `configured` entry and a nullable
`effective_cap`. `effective_cap` is populated only when the same local
authority-admitted inventory includes the Skill. It also reports `admitted`,
`origin`, and `inert_reason`. Its `config_epoch` is `null`: local config and
inventory readback do not prove that a running daemon has accepted or applied
the change. `set` and `reset` return the exact persisted `configured` and
`previous` entries plus `changed` and `reload_requested`. A reload request is a
request for later daemon handling, not a runtime-application acknowledgement.

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

## Self-improvement quality verification

Self-improvement stages a proposal; it does not treat SkillOpt output,
`--from` content, a proposal's `verification_command`, or a successful process
exit as quality proof. Every staged proposal starts with incomplete quality
evidence. It can become accept-capable only after the fixed corpus and an
operator-approved verifier produce the bound v1 result described below.

The configuration is `~/.neoth/self_improve.yaml`:

```yaml
enabled: false
auto: false
asked: false
allow_shell_verify: false
approved_verification_commands: []
```

`allow_shell_verify` and an exact byte-for-byte entry in
`approved_verification_commands` are both required. The CLI accepts the
selected text through `--verifier`, but the core rejects any value that is not
an exact configured entry; proposals, SkillOpt, GUI, Buddy, environment, and
verifier output cannot add or alter a command. There is no prefix, token, path,
whitespace-normalized, or shell-equivalent matching. Add only a command you
fully operate and trust.

The verifier runs in a fresh bounded workspace with a timeout, capped output,
scrubbed environment, and process-tree containment. It is **not** a filesystem
or network sandbox. The command's exact operator allowlist entry remains the
authority boundary.

### Fixed corpus layout

For a proposal whose canonical skill ID is `<skill>`, the only evaluation root
is:

```text
~/.neoth/self_improve_eval/v1/<skill>/
  manifest.json
  cases/<case-id>.json
```

`manifest.json` is strict JSON with exactly the v1 schema fields:

```json
{
  "schema_version": 1,
  "metric": "<metric-id>",
  "cases": [
    { "id": "<case-id>", "sha256": "<sha256 of cases/<case-id>.json>" }
  ]
}
```

`metric` and each case ID are single path components. The manifest must contain
one to 1,024 unique cases. NEOTH reads only this fixed root with bounded,
regular-file reads, rejects links and special files, hashes every listed case,
and derives the corpus manifest digest from the ordered metric, case IDs, and
case hashes. A missing, malformed, changed, or unreadable corpus has no
fallback and cannot certify a proposal.

### Verifier inputs and result v1

The evaluator runs with its current directory set to an empty `runner/`
directory. Core materializes a snapshot at these paths relative to that
directory; the verifier must read `../input/...`, never the live skill or live
corpus:

```text
../input/baseline.md
../input/candidate.md
../input/corpus/manifest.json
../input/corpus/cases/<case-id>.json
../input/evaluator_source_id.txt
../input/source_map_receipt.sha256
../input/corpus_manifest.sha256
```

The verifier's stdout must be one bounded, strict JSON object with
`kind: "self_improve_eval_result.v1"` and `schema_version: 1`. It must contain
`evaluator_source_id`, `corpus_manifest_sha256`, `before_sha256`,
`after_sha256`, `source_map_receipt_sha256`, `metric`, `score_before`,
`score_after`, and `regressions`. The identity fields must bind to the exact
selected allowlist command, supplied input digests, and manifest metric.
Scores must be finite with strict improvement. `regressions` must contain one
passing record for every and only fixed corpus case; each record contains its
case `id`, `passed: true`, and an evidence SHA-256. The core parses, validates,
hashes, and persists this evidence; the CLI never turns verifier stdout into
authority itself.

### Lifecycle, readback, and migration

Stage first with `neoth self-improve run` (or `--from`), then select the exact
configured verifier during execution:

```text
neoth self-improve execute <proposal-id> --verifier "<exact approved verifier command>"
neoth --output json self-improve review
neoth self-improve accept <proposal-id>
```

Execution refreshes the proposal's source-map receipt before quality evaluation.
The core then rechecks the evidence before provider QA/approval, and rechecks it
again immediately before the existing acceptance journal and skill write. A
review row is accept-ready only when its existing `status` is
`verified_approved` and its canonical `quality.state` is `current`; acceptance
still performs the final core check.

To bind acceptance to the exact evidence selected from that review, use:

```text
neoth self-improve accept <proposal-id> --expected-evidence-sha256 <review-quality-evidence-sha256>
```

The GUI uses this form. Core compares the selected digest inside its existing
proposal transaction before the skill write. A proposal re-evaluated since
review is rejected even if the replacement evidence is valid. The acceptance
receipt returns the digest and quality state from the accepted transaction;
the GUI also requires a matching fresh readback before displaying success.
Repeating acceptance with the same still-current evidence returns the accepted
receipt without another skill or ledger write. Revoked or changed evidence
requires a new review.

`quality.state: incomplete` means no typed evidence exists, including all
legacy proposals and proposals staged from untrusted claims. `stale` means
stored evidence no longer validates against its proposal, source-map receipt,
fixed corpus, metric/cases, or exact enabled command authority. Disabling
`allow_shell_verify`, removing or changing the selected allowlist command, or
changing the corpus revokes current evidence into `stale`. Re-stage legacy or
incomplete proposals and execute them against a configured fixed corpus; NEOTH
does not upgrade old score/rationale fields into evidence.

## Inference

Inference routing is an `inference:` block in `~/.neoth/freedom.yaml`; NEOTH
does not load a separate `inference.toml`:

```yaml
provider_kind: openai_compat
provider_endpoint: http://127.0.0.1:1234/v1
provider_model: local-model-id

inference:
  mode: single
  # Exact named wire profile for the legacy top-level compatible binding.
  # Arbitrary/local endpoints should remain `generic`.
  openai_compat_profile: generic
  accelerator_override: cuda  # optional; omit for auto-detection
  embedding_provider: local_qwen
  profile_provider: local_qwen
  utility_provider: local_qwen
  max_new_tokens: 256

profile:
  learn_provider: local_qwen
  allow_cloud_fallback: false
```

Custom topology slots can carry their own `openai_compat_profile`. Supported
Chat-Completions profiles are `generic`, `openrouter`, `deepseek`,
`moonshot_kimi`, and `qwen_chat`. Named profiles are accepted only with their
reviewed matching official endpoint; CLI, wizard, and GUI save paths auto-tag
an exact catalogue endpoint and clear stale profile metadata for arbitrary
URLs. Unsupported Qwen Responses/Anthropic-compatible/DashScope surfaces fail
closed instead of being silently sent through Chat Completions.

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
channel setup contract. The existing Matrix, LINE and IRC advanced settings
also have typed CLI/private-GUI inputs; exact-source native and visual
acceptance remains separate from their source implementation.

Matrix's `matrix_store_path` is available through `channel add matrix
--matrix-store-path` and the optional GUI **State store path** field. A supplied
nonblank value selects the crypto/session directory; an omitted or blank value
preserves the existing custom store during reconfiguration. With no configured
value, Matrix uses `matrix_store` beneath the selected NEOTH home. Setting this
field does not copy or migrate an existing encrypted store.

LINE's `line_webhook_port` is available through `channel add line
--line-webhook-port` and the optional GUI **Webhook port** field. Valid ports
are `1..=65535`. Omitting it, or leaving the GUI field blank, preserves the
existing custom port during reconfiguration; an initially unset value uses
`8444`. The listener remains loopback-only and reads the setting at startup.

IRC's `irc_port`, `irc_tls` and `irc_allowed_nick` are exposed through
`--irc-port`, `--irc-tls true|false`, `--irc-allowed-nick` and the corresponding
GUI fields. Valid ports are `1..=65535`; absent new configuration keeps port
`6697` and TLS enabled. During reconfiguration, omitted/blank optional values
retain existing settings; explicit `false` remains distinct from omission.
A nickname filter is additional and cannot replace the required authenticated
`irc_allowed_account` selected with `--allowed-sender`. Removing IRC clears
its complete configuration, including a record containing settings only.

OMI uses dedicated credential fields rather than provider/channel tokens:
`omi_developer_api_key` for official Developer API import/export and
`omi_ingest_token` for the authenticated native listener. Keep them in
`credentials.yaml` or the configured keychain. See
[runbook_omi_privacy.md](runbook_omi_privacy.md) for the full mode and consent
contract.

Use the Settings → Privacy OMI card or `neoth omi configure` for runtime OMI
changes. Both surfaces use the same complete surfaced settings snapshot:
`enabled`, `mode`, `endpoint`, `listen_addr`, `retention_days`, the
transcript/audio/image/video controls, the two cloud consents, and the
summary/action/ground-truth controls. Advanced unsurfaced OMI bounds remain
preserved.
The command accepts at most 32 KiB of strict JSON on stdin and can carry optional
`developer_api_key` and `native_ingest_token` replacements in the same request.
Unknown or missing settings fields are rejected; omitting one optional
credential preserves its existing value. The desktop does not call
`omi set-credentials` while saving settings and never puts a secret in argv or
reads an existing secret back into a widget.

The public settings and file-backed credential image use one checksummed,
owner-private recovery-journal protocol. With the keychain backend, new values
are first staged as file overrides, written to the OS keychain, and then cleared
from the file through a second credential-only pair transaction. A returned
error states whether finalization failed before a complete keychain generation
was staged, prior values were restored, the updated generation was retained
because the file target may already be committed, or rollback itself failed.
Never treat every non-zero exit as an automatic rollback.

Before success, `omi configure` reads back the persisted effective pair, validates
the submitted settings and required credential presence, hashes the exact
`freedom.yaml` generation, and writes a reload request. Its secret-free receipt
contains the operation ID, path, hashes, selected backend, updated field names,
presence booleans, and reload timestamp. The desktop verifies that receipt
against its submission and the file on disk, then performs a strict `omi status`
readback. A successful receipt means reload was requested, not that asynchronous
worker activation is already complete. If only that request fails after commit,
run `neoth reload` and refresh OMI status.

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
| Code-map context and lifecycle | Hot-reloadable. Each subsequent Chat/Channel message gets the accepted snapshot; the next one-shot `neoth code` invocation gets the new coding limits. Managed-root changes cancel and join removed/disabled watchers before applying replacements. An invalid YAML candidate is rejected before publication, leaving the prior snapshot and lifecycle owner active. |
| Recurring updater discovery | Reload-owned and fail-closed: enabling it arms the supervisor/status lane, but current v1 emits `SkippedByGate` before unattended GitHub/npm/Git network, process, staging, handoff, or replacement effects. `auto_apply` records future verified-staging intent only. Manual signed update commands are unaffected. |
| Provider config | Restart-bound. `neoth reload` rejects changes to the constructed provider runtime (kind, binary, key reference, endpoint, model/aliases, region/API version, inference and recursive-subslot topology, fallback chain, Claude CLI runtime, transport settings and provider decorators such as history compaction). The running provider graph remains on its previous generation until the supervised daemon restarts. |
| Channels | The running daemon watches effective file/keychain credentials, validates the new generation, and stop-then-starts only the changed adapter. A malformed credential store stops the channel fleet fail-closed instead of retaining stale secrets. If a mutation reports that its reload request failed, run `neoth reload`; a full daemon restart is not the normal path. |
| OMI | `neoth omi configure` verifies the persisted effective generation and requests reload. `neoth reload` validates effective file/keychain credentials and restarts only the OMI workers. Invalid changes that cross neither a privacy nor authentication boundary preserve the last valid runtime; after a credential/auth change or monotonic privacy reduction, the prior surface stays stopped rather than restoring stale authority or capture. A configure success receipt proves the request was written, not that asynchronous activation has completed. |
| Cluster | `neoth cluster configure` saves one complete typed snapshot. Enabled lifecycle changes, and changes while a daemon owns the prior state, return `restart_required: true`; restart the supervised daemon to activate transport, mDNS or carrier changes. Gossip privacy/replay policy is hot-reloadable on Peeroxide and Iroh. Disabled plus stopped is already inert and returns `false`. |
| Plugins | Restart after enabling/disabling code plugins. |
| Policy | Reload where supported; restart for safest behavior. |

The Skills row is bound to the exact config file passed to the daemon, not an
inferred default-home filename. Skill policy and routing publish only after the
shared reload controller accepts the complete config generation. A malformed
candidate keeps the previous validated routing snapshot; raw file-watcher
activity alone cannot change effective Skill policy.

## arXiv topic feed

The arXiv feed is disabled by default. To ingest papers for operator-selected
topics, configure the existing feed in `freedom.yaml`:

```yaml
arxiv:
  enabled: true
  topics:
    - "cat:cs.CL"
  max_per_topic: 10
  source_category: arxiv
```

The daemon uses its configured feed interval. To request one pass immediately:

```bash
neoth arxiv ingest --now
neoth --output jsonl arxiv ingest --now
```

The command reads the default NEOTH home's configuration, including a selected
`NEOTH_HOME`, and requires an enabled feed with at least one topic. It does not
enable or start the periodic worker. Existing outbound-request authorization
and provider-call audit rules still apply. When a summary provider is
unavailable, the pass retains the existing raw-abstract fallback.

The result reports topic-fetch and paper-indexing counters. A fetch or indexing
failure makes the immediate command fail visibly. Papers indexed earlier in
that pass remain in the context store; failure does not imply rollback. Paper
IDs remain the stable indexing keys, so a retry follows the existing re-index
behavior. JSONL emits one counter object without paper abstracts or prompts.

## Validate config

```bash
neoth doctor
neoth doctor --explain freedom.yaml
neoth privacy audit --last 24h
```
