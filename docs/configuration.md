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
neoth provider add openai                    # register a provider
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
