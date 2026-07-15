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
Non-essential internal temperature/seed hints consult the selected leaf first
and emit a warning when that leaf cannot represent them. Operator-provided Chat
or Recipe controls are never downgraded: they fail before authorization.

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

Typical `~/.neoth/freedom.yaml` configuration:

```yaml
provider_kind: openai_compat
provider_endpoint: http://127.0.0.1:1234/v1
provider_model: operator-model-id

profile:
  learn_provider: local_qwen
  allow_cloud_fallback: false
```

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
