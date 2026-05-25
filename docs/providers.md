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
neoth provider setup openai
neoth provider setup gemini
neoth provider setup claude
neoth provider setup local-qwen
neoth provider setup ouro
neoth provider doctor
```

Typical config:

```toml
[providers.fast]
kind = "openai-compatible"
model = "fast-model"

[providers.deep]
kind = "claude"
model = "deep-model"

[providers.profile]
kind = "local-qwen"
allow_cloud_fallback = false
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

Commands:

```bash
neoth provider status
neoth provider reset <id>
```

## Metering

NEOTH records provider usage so operators can control cost and route intelligently.

```bash
neoth usage summary --last 30d
neoth quota status
```

Tracked dimensions:

- provider
- model
- role
- request count
- token usage where available
- error rate
- circuit-breaker state
- estimated cost where available

## Local model cache

See [local-models.md](local-models.md).

```bash
neoth model list
neoth model fetch qwen
neoth model fetch ouro
neoth model fetch clip
neoth model fetch whisper
```

## Good defaults

| Operator type | Suggested setup |
| :-- | :-- |
| Normal user | One strong cloud provider + local Qwen for profile learning. |
| Privacy hardliner | Local models first, cloud only for explicit high-value calls. |
| Developer | Fast code model + deep review model + local profile extraction. |
| Homelab | Local gateway/Ollama/vLLM + Tailscale mesh + cloud fallback disabled. |
| Heavy multimodal | CLIP + Whisper + ffmpeg + document pipeline. |
