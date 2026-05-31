# Configuration

NEOTH's normal path is the GUI/CLI wizard. Advanced users can edit config files directly.

## File overview

| File | Purpose |
| :-- | :-- |
| `~/.neoth/freedom.yaml` | Main operator preferences, autonomy, channels, memory, privacy. |
| `~/.neoth/credentials.yaml` | Local credential references and secrets metadata. |
| `~/.neoth/inference.toml` | Provider and local model routing. |
| `~/.neoth/policy.yaml` | Machine-level policy and allowlists. |
| `~/.neoth/council.toml` | Council budget and trigger behavior. |
| `~/.neoth/plugins/` | Installed WASM plugins. |
| `~/.neoth/skills/` | Installed skills. |
| `~/.neoth/wal/` | Event log. Do not edit manually. |
| `~/.neoth/models/` | Local model cache. |

## Wizard first

```bash
neoth gui
```

or:

```bash
neoth init
```

The wizard should be enough for normal users. Manual editing is for operators.

## `freedom.yaml`

Example:

```yaml
operator:
  language: en
  answer_style: direct

privacy:
  local_profile_extraction: true
  allow_cloud_fallback: false

profile:
  require_approval: true
  learn:
    preferences: true
    projects: true
    health: false

autonomy:
  level: standard

channels:
  telegram:
    enabled: true
  whatsapp:
    enabled: false
  slack:
    enabled: false

mesh:
  tailscale: true
  hysteria: false
  keet: false
```

## Autonomy

| Level | Behavior |
| :-- | :-- |
| `strict` | Ask before profile changes, sends, network, plugins, file mutation, workflows. |
| `standard` | Auto-allow low-risk read-only actions; ask before mutation or external action. |
| `elevated` | Allow routine local actions; gate sensitive/high-impact actions. |
| `full` | Execute within explicit policy scope; audit everything. |

## Inference

`~/.neoth/inference.toml`:

```toml
[inference]
allow_cloud_fallback = false

[providers.fast]
kind = "openai-compatible"
model = "fast-model"

[providers.deep]
kind = "claude"
model = "deep-model"

[providers.profile]
kind = "local-qwen"
```

See [providers.md](providers.md) and [local-models.md](local-models.md).

## Council

`~/.neoth/council.toml`:

```toml
[council.budget]
trigger = "smart"
max_debates_per_day = 5
max_usd_per_day = 2.00
```

See [council.md](council.md).

## Policy

`policy.yaml` is the machine guardrail layer.

```yaml
channels:
  telegram:
    allowed_chat_ids: [123456789]

filesystem:
  writable_roots:
    - "~/projects"

network:
  allow_domains:
    - "api.openai.com"
    - "api.anthropic.com"

plugins:
  default_network: false
```

## Credentials

Credential setup should normally happen through:

```bash
neoth credential import
neoth channel setup telegram
neoth provider setup openai
```

Secrets should not be pasted into docs, tickets, logs, or profile memory.

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

## Reload behavior

| Change | Reload |
| :-- | :-- |
| Skills | Hot-reloaded automatically (file watcher); `neoth reload` re-reads tunable config. |
| Provider config | Daemon reload or restart depending on provider. |
| Channels | Restart `neoth serve` after credential changes. |
| Plugins | Restart after enabling/disabling code plugins. |
| Policy | Reload where supported; restart for safest behavior. |

## Validate config

```bash
neoth doctor
neoth doctor --explain freedom.yaml
neoth privacy audit --last 24h
```
