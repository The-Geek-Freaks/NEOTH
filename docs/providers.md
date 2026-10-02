# Providers

Providers are the model backends NEOTH can route to. NEOTH separates provider choice from product behavior: the buddy, memory, policy, audit, coding workflow, and channels stay consistent while the model can change by role.

## Provider types

| Type | Examples | Best for |
| :-- | :-- | :-- |
| Cloud API | OpenAI, Gemini, Anthropic-compatible, Bedrock, Azure OpenAI. | High-end reasoning, large context, convenience. |
| CLI provider | Claude CLI, Codex/Gemini-style CLIs where configured. | Operator environments with existing authenticated tools. |
| OpenAI-compatible | Local gateways, vLLM, Ollama-compatible adapters where configured. | Flexible self-hosted or LAN model serving. |
| Local Qwen | Profile extraction, local memory learning, lightweight reasoning. | Private continuous learning. |
| Local Ouro | Local thinking/reasoning provider. | Operator-owned reasoning path. |
| CLIP | Image embeddings. | Visual recall. |
| Whisper | Audio/video transcription. | Voice notes, meetings, channel audio, video audio tracks. |

## Per-call controls

Sampling controls are enforced at the concrete provider leaf. Unsupported or
malformed values fail before cost authorization and transport; no adapter
silently drops an advertised control.

| Provider | Temperature | Top-p | Seed | Stop sequences | Thinking budget |
| :-- | :--: | :--: | :--: | :--: | :--: |
| OpenAI / OpenAI-compatible / Copilot / Azure OpenAI | [0, 2] | yes | yes | yes | no |
| Anthropic Messages API | legacy: [0, 1]; after Opus 4.6: 1 only | legacy: (0, 1]; after Opus 4.6: [0.99, 1] | no | yes | no |
| Gemini | [0, 2] | yes | yes | yes | no |
| Cohere v2 | [0, 1] | yes | yes | yes | no |
| AWS Bedrock Converse | [0, 1] | yes | no | yes | no |
| Ollama / local Qwen / local abliterated | [0, 2] | yes | yes | yes | no |
| Local Ouro | [0, 2] | yes | yes | no | no |
| Claude CLI | no | no | no | no | yes |
| Recursive MAS | no | no | no | no | no |

Temperature is validated against the selected leaf's range shown above, top-p
against `(0.0, 1.0]`, and seeds against the portable unsigned 32-bit range. A
request may carry at most four non-empty stop sequences of at most 256 UTF-8
bytes each. `neoth chat` exposes
`--temperature`, `--top-p`, and `--sampling-seed`; internal callers use the
same strict contract for stop sequences and Claude CLI thinking budgets.
Anthropic validation resolves the effective request/default model before
authorization. Unknown future Claude 4.x versions take the post-Opus-4.6
compatibility path instead of risking a provider-side rejection.
Non-essential internal temperature hints validate the exact value against the
effective leaf and model first; seed hints consult the leaf capability and stay
inside the portable range. Omitted hints emit a warning. Operator-provided Chat
or Recipe controls are never downgraded: they fail before authorization.
`neoth recipe run ... --dry-run` prints the resolved model and sampling
overrides so automation can be reviewed without dispatching a provider call.

## Output ceilings, authorization and current release gate

The v1.0 contract under current integration carries an explicit per-request
`max_output_tokens` value from the caller to the selected concrete provider
leaf. The leaf must advertise output-token-limit support, resolve the effective
wire ceiling, and bind that same ceiling to cost authorization and the WAL
request record. A provider that cannot enforce the requested ceiling must reject
the request; it may not silently omit the wire field or reuse an approval for a
different ceiling.

The n8n `/api/provider/call` request accepts an optional
`max_output_tokens` JSON field. It permits an integer from `1` through
`131072`; omission preserves the legacy request and response shape. When the
field is supplied, a successful response includes
`requested_max_output_tokens` and `effective_output_token_ceiling`. The latter
is the exact adapter and authorization ceiling for the request; it is never a
claim of observed remote token use.

```json
{ "prompt": "Prepare the briefing", "max_output_tokens": 2048 }
```

Cron stores the same optional value as `execution.max_output_tokens` and exposes
it through `neoth cron add --max-output-tokens` and `neoth cron edit
--max-output-tokens`. The range is again `1` through `131072`; omission keeps
legacy job behavior, and `--clear-execution` clears the stored ceiling together
with the other execution overrides.

```bash
neoth cron add --id morning --cron "0 7 * * *" --prompt "Prepare briefing" --max-output-tokens 2048
neoth cron edit --id morning --max-output-tokens 1024
```

Both caller surfaces use the common provider authorization, cost, and WAL
boundary. A configured value is rejected before a provider call if the selected
leaf cannot prove an exact wire-enforced ceiling. See `GOLD-R4-14a` in the
[authoritative roadmap](../PLAN/ROAD_TO_1_0_GOLD.md).

## Role routing

| Role | Typical model choice |
| :-- | :-- |
| Fast answer | Cheap/fast cloud or local model. |
| Deep answer | Stronger reasoning provider. |
| Profile extraction | Local Qwen/Ouro path. |
| Coding implementation | Fast code-capable provider. |
| Coding review | Deep/review provider. |
| Council dissent | Multiple role-bound providers. |
| Vision/audio | CLIP/Whisper or configured multimodal provider. |

## Configure providers

```bash
neoth provider list
neoth provider known
neoth provider show openai_api
neoth provider test openai_api
neoth init --force
```

`provider` is an inspection surface: its implemented subcommands are `list`,
`known`, `show <provider>`, and `test <provider>`. Provider mutations go through
the onboarding wizard or the hemisphere configuration commands.

`provider test` does not accept a `--live` flag. Its help points to the
implemented interactive wire check,
`neoth hemispheres test --question "Reply with OK"`; `--live` belongs to
`neoth doctor --live` for the separate service-health probes.

Typical `~/.neoth/freedom.yaml` configuration:

```yaml
provider_kind: openai_compat
provider_endpoint: http://127.0.0.1:1234/v1
provider_model: operator-model-id

inference:
  openai_compat_profile: generic

profile:
  learn_provider: local_qwen
  allow_cloud_fallback: false
```

Custom topology slots can bind a named compatible cloud explicitly:

```yaml
inference:
  mode: custom
  right:
    provider: openai_compat
    openai_compat_profile: openrouter
    endpoint: https://openrouter.ai/api/v1
    model: qwen/qwen3-72b-instruct
```

### Named provider instances

Use named instances when two routes use the same provider descriptor but must
retain separate endpoint, model, and credential identities. The list belongs
under `inference:`; a Left or Right slot that uses an instance contains only
`provider_instance_id`.

```yaml
inference:
  mode: custom
  provider_instances:
    - id: compat_a
      descriptor: openai_compat
      endpoint: https://vendor-a.example/v1
      model: '@fast'
      models_aliases: { '@fast': vendor-a-chat }
    - id: compat_b
      descriptor: openai_compat
      endpoint: https://vendor-b.example/v1
      model: '@fast'
      models_aliases: { '@fast': vendor-b-chat }
  left: { provider_instance_id: compat_a }
  right: { provider_instance_id: compat_b }
```

The same `openai_compat` descriptor may therefore represent distinct vendor or
tenant routes without borrowing another instance's endpoint or model. Instance
IDs are durable identifiers: 1–64 lowercase ASCII letters, digits, or
underscores, beginning with a letter. IDs must be unique; descriptors and role
references must be known. A named slot cannot mix `provider_instance_id` with
any inline authority (`provider`, `model`, `key`, `endpoint`, compatibility
profile, region, API version, or voice). This includes explicitly writing an
inline field as `null`; `provider_instance_id: null` is also invalid.

Legacy inline slots remain supported. Use either the existing inline form or a
single named reference for one slot, never a mixture.

### Inspect or add an instance

Use the instance subcommands to inspect the public registry or add one new,
initially unbound record:

```bash
neoth provider instance list
neoth provider instance show compat_a
neoth provider instance add \
  --id compat_c \
  --descriptor openai_compat \
  --model vendor-chat \
  --endpoint https://vendor-c.example/v1 \
  --openai-compat-profile generic
```

`list` includes every declared record, even one that no role or fallback uses;
`show` selects exactly one durable ID. Both read only the public
`freedom.yaml` configuration. They do not load private credentials, contact a
keychain, construct a provider, grant consent, or start catalog discovery.

`add` accepts only the durable `--id`, a known `--descriptor`, and optional
public transport fields: `--model`, `--endpoint`,
`--openai-compat-profile`, `--region`, and `--api-version`. It never accepts a
key, role, or fallback argument. A successful add takes a pre-mutation rollback
snapshot and writes the public configuration, but it does not bind the new
record to a role or fallback, resolve credentials, grant consent, create a
provider, or start discovery. Configure private instance credentials separately
in `credentials.yaml`, then bind the ID through the relevant hemisphere or
fallback configuration.

Each instance can define its own `models_aliases` map. After selecting that
instance, its entries take precedence over the global `models_aliases` map;
missing entries still use the global map. Resolution remains one level: an
alias value is sent as the model rather than expanded through another alias.
The same selection applies to Profile, installed Skills, Channel/MCP and
Council role or sub-role requests, including their cost and audit identities.
Inline slots and named instances without local aliases retain global behavior.

`neoth catalog refresh` keeps a separate model catalog for each selected named
instance. Its key combines the catalog provider and instance ID, for example
`openai_compat__compat_a`; `neoth catalog list` and `neoth catalog show` expose
these exact entries. Claude CLI uses the shared `anthropic_api` catalog prefix.
Legacy inline routes keep their existing provider-only catalog keys.

`neoth hemispheres show` includes each role's catalog key, cached recommendation,
and model choices. A missing named entry produces no recommendation or choices
from another instance. This display does not change the configured request model.

Cron execution through a named instance requires an explicit
`execution.hemisphere_role`. A no-role provider or fallback lookup by coarse
provider enum refuses a matching named instance, even when only one exists, so
it cannot choose the wrong endpoint.

An `aws_bedrock` named instance must supply its own valid `region`. It never
inherits the global `provider_region`; missing or invalid instance region fails
closed at consent and provider construction.

Instance keys live only in the private `~/.neoth/credentials.yaml` map:

```yaml
inference_provider_instance_keys:
  compat_a: <provider-instance-a-secret>
  compat_b: <provider-instance-b-secret>
```

Do not put these values in `freedom.yaml`. Public configuration rendering strips
all instance-key values. With the keychain backend, the dynamic target is
`inference-provider-instance/<id>/key`; credentials may retain
`compat_a: null` as metadata for a keychain-owned value, so the placeholder is
preserved without exposing the secret.

Named instances select existing implemented descriptors only. They do not add
network-adapter, protocol, capability, or provider-parity coverage.

Supported Chat-Completions profiles are `generic`, `openrouter`, `deepseek`,
`moonshot_kimi`, and `qwen_chat`. Named profiles preserve vendor-specific
refusal/error attribution and are accepted only with a reviewed matching
official endpoint. OpenRouter keeps bounded observed upstream provider/model
evidence separately from the authorized router leaf; that evidence never
rewrites cost or consent authorization.

The shared OpenAI-compatible Chat-Completions transport accepts at most an
8 MiB successful JSON envelope, a 1 MiB SSE line/residual or joined event-data
payload, and 1 MiB of cumulatively retained streaming or non-stream refusal
metadata. It reads transport chunks as bytes, so UTF-8 characters may straddle
chunks, and joins standard multi-`data:` events before decoding. Malformed,
invalid, oversized or truncated envelopes fail with digest-only diagnostics.

The native Ollama `/api/chat` transport uses the same shared primitives: an
8 MiB successful JSON envelope, byte-oriented NDJSON framing with a 1 MiB
line/EOF-residual cap, and 64 KiB HTTP error bodies reported as status plus
digest only. A malformed or invalid-UTF-8 NDJSON frame now fails the stream
instead of being logged raw and skipped, so a lost frame can never be followed
by a synthetic "done" chunk that reports a complete generation. Real delta
text, `done_reason`, prompt/eval token counts and the loopback-versus-remote
identity split are unchanged.

Anthropic, Gemini, Cohere, Azure OpenAI and AWS Bedrock use the same shared
readers on their single-shot JSON transports: 8 MiB successful bodies, 64 KiB
error bodies, and errors that report a status plus digest evidence instead of
the envelope. Where an adapter has to classify the error — an Azure policy
refusal, a Bedrock `__type` — it classifies under the cap and still reports
only the classification and the digest. The Copilot token exchange is bounded
at 64 KiB; Copilot chat runs through the OpenAI-compatible transport.

Retained quota evidence (`Retry-After` bookkeeping) is now a digest for every
one of those adapters. That replaces the previous substring scrub of the API
key, which only removed the key in the exact encoding the endpoint happened to
echo.

The v1.0 Gold gate remains open until the Claude CLI, Tmux and sidecar
subprocess transports have equivalent bounded readers.

For Ollama, only normalized loopback endpoints (`localhost`, `127.0.0.0/8`, or
`[::1]`) identify as `local_ollama`. LAN, public and Ollama Cloud endpoints
identify as `ollama_remote` and cross the same paid-provider authorization
boundary as other remote inference. Selecting the Ollama provider kind does
not by itself make a remote endpoint local or free.

### Remote Ollama consent

Remote Ollama consent is bound to the canonical endpoint origin, not merely to
the `local_ollama` provider kind. A grant for endpoint A never authorizes
endpoint B. Changing the endpoint therefore makes the old grant stale and
requires a new decision before any provider transport is constructed. Stale
grants remain visible and revocable through `neoth consent`; malformed,
oversized, symlinked, or future-format marker files fail closed.

`Allow once` is an exact-route, command-scoped capability. It is not written as
a durable grant and cannot be reused by a later CLI, GUI, Buddy, daemon, retry,
fallback, or post-reply provider call. `Allow always` and revocation use the
same transactional mutation service across CLI, slash commands, onboarding,
GUI, and Buddy. The service binds the configured route set, writes the
pre-mutation intent before changing authority, commits the marker change
atomically, and retains retryable audit evidence across crashes or a temporarily
unavailable WAL service.

GUI and Buddy first-send consent use a private, expiring challenge. The
challenge is bound to the exact config hash and canonical route set; the secret
and a resulting one-shot token travel over standard input, never process
arguments or logs. A config or endpoint change between preflight and decision
invalidates the challenge. Consent status exposes configured, granted, stale,
invalid, and audit-pending state instead of retaining an optimistic green state
after an error.

### Endpoint-bound cloud consent

Configurable OpenAI, OpenAI-compatible, Azure OpenAI, and AWS Bedrock routes
are authorized by their canonical runtime destination, not only by provider
name. Bedrock consent is bound to the effective region's exact runtime origin
(`https://bedrock-runtime.<region>.amazonaws.com`). A grant for one endpoint,
Azure resource, or Bedrock region never authorizes another. Primary, role,
subrole, learn, utility, teacher, discovery, and enabled fallback routes all
use the same route derivation as the concrete transport.

### RecursiveMAS requires two independent gates

RecursiveMAS executes operator-installed third-party code whose upstream
license is unresolved, and that sidecar inherits the host's network access.
NEOTH therefore keeps code execution acknowledgement and prompt egress
authority separate:

```bash
# 1. Review and acknowledge the operator-installed third-party sidecar.
neoth rmas consent --acknowledge

# 2. Grant revocable prompt egress for the RecursiveMAS provider.
neoth consent grant recursive_mas
```

`neoth rmas consent` shows both live states and the exact missing command. The
first marker never implies or creates provider authority. Egress can be removed
without changing the code acknowledgement:

```bash
neoth consent revoke recursive_mas
```

The `known` catalogue and a configurable OpenAI-compatible URL are discovery
and transport substrate, not a claim of OpenClaw-class provider parity. Auth,
OAuth, region/project fields, capability/model discovery, tool/image/thinking
wire semantics, pricing and every Hemisphere/Skill/Cron/Buddy/GUI consumer
still require an explicit tested provider disposition before v1.0 Gold.

### Profile extraction provider instances

Set `inference.profile_provider_instance_id` to route manual `neoth profile
run`, post-chat learning, and channel learning through one named provider
instance. The selected instance supplies its exact endpoint, credential,
model, compatibility profile, region, consent route, and audit identity.
`profile_provider_instance_id` is mutually exclusive with the legacy coarse
`inference.profile_provider`; leaving both unset preserves each caller's
existing profile/learn fallback behavior.

## Privacy behavior

| Question | Expected answer |
| :-- | :-- |
| Which provider saw this prompt? | `neoth privacy audit` should show it. |
| Did profile extraction use cloud? | Only if explicitly configured. |
| Did a provider fail open? | It should surface failure and policy fallback, not silently reroute private learning. |
| Can I force local-only? | Yes, by provider/profile policy. |

## Circuit breakers

Provider failures are tracked so NEOTH does not hammer a broken backend.

| State | Meaning |
| :-- | :-- |
| Closed | Calls allowed. |
| Open | Provider temporarily rejected due to repeated failures. |
| Half-open | Probe call allowed to test recovery. |

The quota tracker exposes active 429 backoff and operator-observed caps. Provider
adapters also use circuit breakers internally; there is no separate
`provider status/reset` command.

```bash
neoth quota status
neoth quota reset <provider>
```

Fallback backoff is isolated by provider instance. Named routes use the quota
key `instance:<provider_instance_id>`; legacy routes retain their provider
descriptor key. A 429 from one named OpenAI-compatible endpoint therefore does
not suppress another instance using the same transport. Existing legacy backoff
entries remain active. Use the key shown by `quota status` when resetting an
individual entry.

## Metering

NEOTH records provider usage so operators can control cost and route intelligently.

```bash
neoth usage --days 30
neoth quota status
```

Tracked dimensions:

- provider
- model
- role
- request count
- token usage where available
- request/token usage where recorded
- estimated cost where available

Circuit-breaker state is adapter-internal and is not part of the `usage`
roll-up.

## Local model cache

See [local-models.md](local-models.md).

```bash
neoth models list
neoth models pull clip
neoth models pull whisper
neoth ouro list
neoth ouro fetch --checkpoint ByteDance/Ouro-1.4B-Thinking
```

Qwen is selected through `neoth init`; it is not a `models pull` target. The
linked local-model guide documents each distinct workflow.

## Good defaults

| Operator type | Suggested setup |
| :-- | :-- |
| Normal user | One strong cloud provider + local Qwen for profile learning. |
| Privacy hardliner | Local models first, cloud only for explicit high-value calls. |
| Developer | Fast code model + deep review model + local profile extraction. |
| Homelab | Local gateway/Ollama/vLLM + Tailscale mesh + cloud fallback disabled. |
| Heavy multimodal | CLIP + Whisper + ffmpeg + document pipeline. |

### Inspect Buddy provider routes

`neoth buddy status --output json` includes `provider_routes`; table output shows
the same role bindings. Each route identifies its named instance (if configured),
transport descriptor, configured model and alias-resolved display model. The
status also reports whether a fallback chain is configured and its length.
Providerless legacy roles use the global route fields; named instances use only
their own fields. Missing models remain unset. Endpoint credentials, query strings
and fragments are omitted. This command reads configuration without constructing
a provider or making a network call.

### Change Buddy routes

`neoth buddy provider` exposes the canonical `hemispheres` actions: `show`,
`set`, `select`, `mode`, `preset` and `test`. Existing role validation, configuration
transactions, rollback handling and audit behavior apply unchanged.

To set a quota-fallback order using instances already defined in configuration:

```bash
neoth buddy fallback replace --provider-instance-id compat_primary --provider-instance-id compat_secondary
neoth buddy fallback clear
```

Replacement changes only `fallback.chain`; it preserves `max_hops` and does not
grant provider consent. Unknown or duplicate instance IDs are rejected before
publication. JSON output includes previous/new counts and the rollback snapshot
receipt, which is subject to the configured rollback policy. Runtime fallback
continues to use the existing HTTP-429 and per-hop consent rules.

To select an existing named instance for a role, use the same canonical action
through either CLI surface:

```bash
neoth hemispheres select --role right --provider-instance-id compat_secondary
neoth buddy provider select --role right --provider-instance-id compat_secondary
```

The role stores the instance ID; its endpoint, credentials, model and alias scope
remain owned by the registry entry. Other roles retain their effective routes
when leaving Single mode. The result identifies the selected instance and the
resolved configured model; missing models remain unconfigured. Selection does
not grant provider consent. An audit failure after publication explicitly reports
that the configuration was already committed.
