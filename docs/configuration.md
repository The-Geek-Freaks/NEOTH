# Configuration

Neoth reads config from ~/.neoth/. All files are plain text — edit with any editor.
Most changes take effect immediately on the next request or via `neoth reload-skills`.

---

## File overview

| File | Purpose |
|------|---------|
| `~/.neoth/freedom.yaml` | Master permission and learning config |
| `~/.neoth/policy.yaml` | Per-deployment machine safety rules |
| `~/.neoth/soul.md` | Identity and voice template |
| `~/.neoth/claude.md` | Operational rules template |
| `~/.neoth/inference.toml` | Local model config (Phase 2) |
| `~/.neoth/council.toml` | Council debate budget (Phase 2) |

---

## freedom.yaml

The main switchboard. Read before every LLM call — no restart needed after edits.

```yaml
operator:
  id: your-handle       # Set at neoth init. Identifies you in WAL events.
  role: developer       # Injected into context. Free text.
  default_language: en  # ISO 639-1. Neoth mirrors your language; this is the fallback.
  code_language: en     # Language for code and commits.
```

### Scopes

High-risk capabilities are off by default.

```yaml
scopes:
  security_research: false  # Pentest/exploit skills. When true, Neoth injects security
                            # context on relevant keywords.
  server_safety: true       # Enforces machine rules from policy.yaml. Leave true.
  destructive_ops: false    # Destructive shell, mass-delete. false = asks first.
  edge_content: false       # Uncensored generation. Off by default.
```

### Profile learning

Controls what Neoth learns. Full detail in [profile.md](profile.md).

```yaml
profile:
  learn:
    enabled: true              # Master switch
    require_approval: false    # true = new claims held until `neoth profile approve`
    identity: true             # Name, age, role, city-level location
    preferences: true          # Food, music, sleep, communication style
    relationships: true        # People you mention: name, role, sentiment
    skills: true               # Domains and proficiency
    goals: true                # Short/medium/long-term objectives
    health: false              # PII - medications, conditions, allergies. OFF by default.
    schedule: true             # Routines, recurring patterns
    emotional_baseline: true
    operator_preferences: true # How you want Neoth to behave

  decay_rate_override: null    # null = default 0.995/day.
                               # At 0.995 confidence halves after ~138 days without
                               # reinforcement. Increase toward 1.0 to slow decay.
  confidence_injection_floor: 0.6   # Fields below this are hidden from the LLM.
  daily_cost_cap_usd: 1.00          # Max spend on extraction per day (cloud only).
```

### Inference

```yaml
inference:
  allow_cloud_fallback: false  # Privacy default. When false: if local model is down,
                               # extraction is skipped, not sent to cloud.
                               # Set true only if you accept cloud exposure.
  local_model_path: ~/.neoth/models/qwen3-4b-int4.gguf
  cloud_provider_order:        # Used when allow_cloud_fallback=true.
    - claude-cli
    - codex-cli
    - gemini-cli
```

### Channels

```yaml
channels:
  proactive:
    enabled: false   # Neoth messaging you unprompted. Phase 3. Off in v0.1.0.
  identity_merge:
    automatic: false # Never auto-merges identities across channels.
                     # Manual: neoth identity merge <uuid1> <uuid2>
```

### Storage

```yaml
storage:
  wal_dir: ~/.neoth/wal
  disk_thresholds:
    warn_pct: 70           # Warning at 70% disk usage
    stop_raw_text_pct: 80  # Stops storing raw conversation text at 80%
    read_only_pct: 90      # WAL read-only at 90%. Still responds, no learning.
    refuse_start_pct: 95   # Refuses to start at 95%. Free disk first.
```

### Council (Phase 2)

```yaml
council:
  enabled: true
  budget:
    max_debates_per_day: 5
    max_rounds_total_per_day: 25
    max_usd_per_day: 2.00       # Ignored for CLI-auth users.
    warn_debates_per_day: 4
  smart_trigger:
    keyword_list: [architecture, security, refactor, destructive, breaking]
    min_user_msg_tokens: 800    # Short questions never trigger council.
    min_assembled_tokens: 5000
    require_dissent_score_gt: 0.4
    max_auto_triggers_per_hour: 2
```

---

## policy.yaml

Per-deployment rules. Machine-specific things that would not belong in freedom.yaml.

```yaml
servers:
  my_prod_server:
    addresses: [10.0.1.5, prod.example.local]
    no_remote_reboot: true      # Physical access required to reboot.
    requires_confirmation_for:
      - systemctl stop
      - kill -9
      - rm -rf

channels:
  telegram:
    allowed_chat_ids: [123456789]         # Numeric IDs only. No usernames.
  whatsapp:
    allowed_phone_numbers: ["+491234567890"]  # E.164 format.
  slack:
    allowed_workspace_ids: [T01234567]
    allowed_user_ids: [U01234567]

forbidden_paths:
  - /etc/shadow
  - ~/.ssh/id_*
```

Full schema: `~/.neoth/policy.example.yaml`.

---

## soul.md and claude.md

**soul.md** — Neoth's identity template. Injected into every LLM context. Edit the Voice and
behavior sections. Do not modify the hard constraint sections (Framework G.6, G.13 markers) —
those are safety rails.

**claude.md** — Operational discipline rules (verify before claiming done, no guessing state, etc.).
Machine-specific safety rules belong in policy.yaml, not here.

Changes: `neoth reload-skills` or send SIGHUP to the daemon.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NEOTH_HOME` | `~/.neoth` | Override config and WAL location |
| `NEOTH_LOG` | `info` | Log level: trace, debug, info, warn, error |
| `TELEGRAM_BOT_TOKEN` | — | Required for Telegram |
| `SLACK_BOT_TOKEN` | — | Slack bot token xoxb- prefix (Phase 2) |
| `SLACK_APP_TOKEN` | — | Slack app token xapp- prefix (Phase 2) |
| `WHATSAPP_TOKEN` | — | Meta WA Business API token (Phase 2) |
| `WHATSAPP_PHONE_ID` | — | Meta WA Business phone number ID (Phase 2) |

Never put token values in freedom.yaml or policy.yaml. Those files are hash-tracked in WAL events.

---

## Hot-reload behavior

| What changed | How to apply |
|--------------|-------------|
| `freedom.yaml` | Automatic on next request |
| `policy.yaml` | Automatic on next request |
| `soul.md` / `claude.md` | `neoth reload-skills` or SIGHUP |
| Skills in `~/.neoth/skills/` | `neoth reload-skills` |
| Plugins | Daemon restart (`neoth stop && neoth start`) |
| `inference.toml` | Daemon restart |

SIGHUP: `kill -HUP $(neoth status --pid)`
