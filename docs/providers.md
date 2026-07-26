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

profile:
  learn_provider: local_qwen
  allow_cloud_fallback: false
```

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
