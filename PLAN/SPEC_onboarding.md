# SPEC: `neoth init` Onboarding Wizard -- NEOTH v1.1

> **Status:** BUILD-READY (Phase 1 Day 3-4 deliverable).
> **Normative basis:** `00_DESIGN_v1.1_FINAL.md`, `SPEC_channels.md`,
> `SPEC_skill_plugin_system.md`, `SPEC_proactive_learning.md` section 7,
> `SPEC_council_governance.md`.
> **Brand:** NEOTH. CLI binary `neoth`. Config root `~/.neoth/`. Zero telemetry by default.

---

## 0. Scope

Covers:
- First-run detection and the 7-step interactive wizard
- Idempotency (re-run behavior, per-section reconfiguration)
- Non-interactive / scripted mode
- Output artifacts written to `~/.neoth/`
- `.initialized` marker file
- Telemetry policy (ZERO by default, opt-in only)

Out of scope: OAuth token exchange (Day 5+), Telegram webhook management (Day 7+),
WAL-backed audit trail for config changes (Day 11+), multi-operator switching.

---

## 1. First-Run Detection

### 1.1 Algorithm

```rust
fn is_first_run(neoth_dir: &Path) -> bool {
    !neoth_dir.join(".initialized").exists()
}
```

Missing marker triggers wizard regardless of whether other `~/.neoth/` files exist.
Wizard detects existing files and asks before overwriting (see section 4.2).

### 1.2 Trigger Conditions

| Condition | Wizard behavior |
|-----------|----------------|
| `~/.neoth/` does not exist | Full wizard, create directory |
| `~/.neoth/` exists but `.initialized` missing | Full wizard, preserve existing files |
| `.initialized` present, `--force` absent | Show config summary, offer per-section reconfigure |
| `.initialized` present, `--force` given | Re-run full wizard from step 1 |
| `--noninteractive` + `.initialized` present | Merge provided flags into existing config |

### 1.3 Directory Layout

```
~/.neoth/
+-- .initialized          <- marker file (JSON, section 6.3)
+-- freedom.yaml          <- operator identity + inference policy
+-- policy.yaml           <- behavioral policy (from policy.example.yaml)
+-- council.toml          <- council budget (SPEC_council_governance.md section 1)
+-- credentials/
|   +-- providers.yaml    <- LLM credentials (mode 0600)
|   +-- channels.yaml     <- channel tokens (mode 0600)
+-- skills/               <- user skill YAMLs (hot-reload via SIGHUP)
+-- plugins/              <- WASM plugins (Phase 2, Day 23+)
+-- wal/                  <- WAL segments (Day 2+)
```

Permissions: `~/.neoth/` mode `0700`. `credentials/` mode `0700`.
All files under `credentials/` mode `0600`. umask `0077` in `main()` covers this.
Wizard verifies and warns if permissions drift.

---

## 2. Wizard Overview

The wizard runs 7 sequential steps. Each step:
1. Prints a section header (no emoji; ANSI color only if TERM supports it)
2. Shows current value if reconfiguring
3. Reads user input with a sensible default
4. Validates immediately, re-prompts on error (max 3 retries, then abort step)
5. Stages value in memory; writes to disk only after all steps complete (atomic write)

Terminal detection: if stdout is not a TTY (piped), wizard aborts with exit 1 unless
`--noninteractive` is set.

Progress: `[1/7]`, `[2/7]`, ... prefix on each section header.

---

## 3. Step-by-Step Specification

### Step 1 -- Welcome + License Acceptance

```
================================================================
  Neoth v{VERSION} -- Personal AI Agent
  neoth knows.
================================================================

Neoth is open-source software distributed under the MIT OR Apache-2.0 license.
Full license text: https://github.com/<owner>/neoth/blob/main/LICENSE

Telemetry: ZERO. Neoth never phones home. Your data stays on your machine.
Optional opt-in later: neoth telemetry on

[1/7] License
  Do you accept the license terms? [y/N]:
```

- Default: `N` (must be explicit `y` or `yes`, case-insensitive)
- On `N` or empty: print `Aborted. Re-run neoth init when ready.` and exit 0
- On acceptance: continue to step 2
- Non-interactive: `--accept-license` flag required; absent exits 1
- `--force` re-run: still shown, still requires acceptance

Rationale: Exit 0 on refusal -- deliberate abort, not failure.

---

### Step 2 -- Operator Identity

```
[2/7] Operator Identity

How should Neoth refer to you? This sets your operator-id in freedom.yaml.
  Default: {OS_USERNAME}
  Operator-id [press Enter for default]:
```

Validation:
- 2-32 characters
- Pattern `[a-zA-Z0-9_-]` only
- Reserved words (rejected): `neoth`, `root`, `system`, `admin`, `daemon`, `nobody`
- Confirmed: `Operator-id set to: {id}`

Storage: `freedom.yaml` field `operator.id`.
Re-run: `Current operator-id: {id}. Change? [y/N]:` -- skip on N.
Non-interactive: `--operator-id <value>`. Missing -> uses OS username silently.

---

### Step 3 -- Language

```
[3/7] Language

Primary language for Neoth responses:
  [1] English (en)      <- default
  [2] Deutsch (de)
  [3] Francais (fr)
  [4] Espanol (es)
  [5] Other (enter BCP-47 code, e.g. ja, zh-CN, pt-BR)

Primary language [1]:

Code language (for code blocks, default: en):
  Press Enter to use same as primary, or enter BCP-47 code:
```

Validation: simplified pattern `^[a-z]{2,3}(-[A-Za-z]{2,8})*$`.
Warn but do not block if code not in known locale list.

Storage in `freedom.yaml`:
```yaml
operator:
  language:
    primary: "en"
    code: "en"
```

Non-interactive: `--language <bcp47>` and `--code-language <bcp47>`.

---

### Step 4 -- Role

```
[4/7] Role

What is your primary role? Neoth uses this to calibrate tool routing,
response style, and skill auto-loading.

  [1] developer           -- code, review, debug, architecture
  [2] security-researcher -- pentesting, vuln research, exploit dev
  [3] founder             -- strategy, product, fundraising, hiring
  [4] data-scientist      -- notebooks, pipelines, models, stats
  [5] writer              -- docs, copywriting, longform
  [6] none                -- no role preset, clean slate

Role [1]:
(Change any time: neoth profile --set-role <role>)
```

Validation: listed key or custom string 1-32 chars `[a-z0-9_-]`.
Storage: `freedom.yaml` field `operator.role`.

Role maps to auto-loaded skills (Phase 2, Day 38+):

| Role | Auto-loaded skills |
|------|-------------------|
| `developer` | `code-review`, `git-ops`, `shell-assist` |
| `security-researcher` | `pentest-assistant`, `cve-lookup`, `shell-assist` |
| `founder` | `research-brief`, `doc-write` |
| `data-scientist` | `notebook-assist`, `code-review` |
| `writer` | `doc-write`, `grammar-check` |
| `none` | (empty) |

Phase 1: role stored only; printed in `neoth chat` session header.
Non-interactive: `--role <key>`.

---

### Step 5 -- LLM Provider Connection

```
[5/7] LLM Provider

Neoth needs an LLM provider for its Left Hemisphere (primary response channel).

Detecting installed CLIs...
  claude (Anthropic Claude CLI): FOUND at /usr/local/bin/claude
  codex  (OpenAI Codex CLI):     NOT FOUND
  gemini (Google Gemini CLI):    NOT FOUND

Available options:
  [1] Claude (claude CLI)           <- recommended, Left Hemisphere default
  [2] OpenAI (codex CLI or API key)
  [3] Gemini (gemini CLI or API key)
  [4] OpenAI-compatible (custom URL + API key)
  [5] Skip for now

Provider [1]:
```

CLI detection: `command -v claude` etc. on Unix; same inside WSL shell on Windows.
Found CLIs listed first in numbered options.

#### 5a -- Claude via claude CLI

```
[stub] Phase 1: would verify: claude auth status
[stub] Phase 1: would prompt if needed: claude auth login
Binary: /usr/local/bin/claude
Model:  claude-opus-4-7 (Left Hemisphere default per 00_DESIGN_v1.1)
Confirm? [Y/n]:
```

Phase 1: connection test stubbed. Actual CLI spawning added Day 5
(reqwest + eventsource-stream per Cargo.toml Day-5 comment).
Wizard writes `kind: claude_cli` to credentials.

#### 5b -- OpenAI / Codex via API key

```
Enter your OpenAI API key (starts with sk-...):
  (input is hidden)

Endpoint [https://api.openai.com/v1]:
Model [gpt-4o]:

[stub] Phase 1: would POST /v1/models to verify key.
Connection: [stub] OK
```

Key format: `^sk-[A-Za-z0-9_-]{32,}` for OpenAI; custom endpoints skip format check.
Stored in `~/.neoth/credentials/providers.yaml` mode 0600.
Never written to `freedom.yaml` or any world-readable file.

Security warning if key stored as literal:
```
WARNING: API key stored plaintext in ~/.neoth/credentials/providers.yaml (mode 0600).
Prefer: export NEOTH_PROVIDER_KEY=sk-...   (leave api_key blank in config file)
```

#### 5c -- Gemini via API key

```
Enter your Gemini API key (from https://aistudio.google.com/):
  (input is hidden)

[stub] Phase 1: would GET /v1beta/models to verify.
Connection: [stub] OK
```

#### 5d -- Skip

```
Skipping provider. neoth chat will error until you run: neoth provider add
```

Storage (`~/.neoth/credentials/providers.yaml`, mode 0600):

```yaml
# neoth credentials -- LLM provider config
# DO NOT COMMIT THIS FILE.
providers:
  left_hemisphere:
    kind: claude_cli          # claude_cli | openai_api | gemini_api | openai_compat
    binary_path: /usr/local/bin/claude
    # api_key: ""             # empty = use env NEOTH_PROVIDER_KEY
    model: claude-opus-4-7
    verified_at: 2026-05-13T00:00:00Z
```

Re-run: current provider kind + masked key (last 4 chars).
`[1] Keep current  [2] Reconfigure  [3] Test connection`

Non-interactive: `--provider <kind> --provider-key <key> --provider-endpoint <url>`.
Key via `--provider-key`: wizard logs one-line warning about `ps aux` visibility.

---

### Step 6 -- Optional: First Channel (Telegram)

```
[6/7] Channel (optional)

Channels let you interact with Neoth through messaging apps.

  [1] Telegram Bot          <- recommended for personal use
  [2] Skip for now

Channel [2]:
```

Default `2` (skip). Always skippable.

#### 6a -- Telegram Bot Setup

```
Step 1. Message @BotFather on Telegram: https://t.me/BotFather
Step 2. Send: /newbot   Follow prompts. You receive a token like:
        1234567890:ABCDefghIJKlmnopQRStuvwxyz12345678

Step 3. Paste your bot token (input is hidden):
        Bot token:

[stub] Phase 1: would call Telegram getMe API.
Bot: @{bot_username}  (stub -- Day 7 adds teloxide for actual verification)

Step 4. Start a chat: https://t.me/{bot_username}
        Send any message so Telegram registers your chat ID.

Step 5. Your Telegram user ID (optional, restricts access to your account):
        User ID [skip]:
```

Validation:
- Token format: `\d{8,12}:[A-Za-z0-9_-]{35}`
- User ID: numeric string, optional
- Empty `allowed_user_ids` means any user who messages the bot is accepted

Test: Phase 1 stub only. Day 7 implements actual `getMe` call per `SPEC_channels.md`.

Storage (`~/.neoth/credentials/channels.yaml`, mode 0600):

```yaml
# neoth credentials -- channel config
# DO NOT COMMIT THIS FILE.
channels:
  telegram:
    enabled: true
    bot_token: "1234567890:ABCDefgh..."
    allowed_user_ids: [123456789]     # empty list = accept all users
    verified_at: 2026-05-13T00:00:00Z
```

`freedom.yaml` additions:

```yaml
channels:
  telegram:
    enabled: true
  proactive:
    enabled: false   # Phase 3+ opt-in per SPEC_channels.md A2
```

On verification failure:
```
  Verification failed: {error}
  [1] Retry  [2] Skip (add later: neoth channel add telegram)
```

Re-run: shows current bot username (masked token). Offers test / reconfigure / keep.
Non-interactive: `--telegram-token <token>` + optional `--telegram-user-id <id>`.
Absent token in non-interactive mode: channel skipped silently.

---

### Step 7 -- Summary + Next Steps

```
[7/7] Setup Complete

Neoth has been configured:

  Operator:   {operator_id}
  Language:   {primary} / code: {code}
  Role:       {role}
  Provider:   {kind} ({model})
  Channel:    @{bot_username} via Telegram  [or: none configured]

Written to disk:
  ~/.neoth/freedom.yaml
  ~/.neoth/credentials/providers.yaml  (mode 0600)
  ~/.neoth/credentials/channels.yaml   (mode 0600, if channel configured)
  ~/.neoth/.initialized

Next steps:
  neoth chat "hello"     -- start a conversation
  neoth profile show     -- view operator profile
  neoth quota status     -- check council budget
  neoth skill list       -- list available skills

  If Telegram configured: send a message to @{bot_username} to test.
  Start the daemon: neothd

Docs: https://github.com/<owner>/neoth/blob/main/docs/install.md

Neoth knows. Good luck.
```

Non-interactive: summary printed regardless. Errors emit JSON to stderr:
```json
{"step":5,"field":"provider","error":"API key verification failed: 401 Unauthorized"}
```

---

## 4. Idempotency

### 4.1 Re-run Detection

When `.initialized` present and `--force` absent:

```
Neoth is already configured.
  Initialized: {timestamp}   Version: {version}

Reconfigure sections:
  [1] Operator identity
  [2] Language
  [3] Role
  [4] LLM provider
  [5] Channels
  [6] Show current config
  [7] Exit

Section [7]:
```

Selected section runs in isolation. All other config unchanged.

### 4.2 Safety Rules

- Wizard NEVER overwrites an existing file without showing the affected YAML section
  and prompting confirmation.
- On user rejection: section keeps old value, wizard continues to summary.
- `freedom.yaml`: read at wizard start, deep-merged at wizard end (not replaced).
- `credentials/`: only the affected provider/channel block is replaced.

### 4.3 Concurrent Run Protection

`~/.neoth/.lock` created via `O_CREAT|O_EXCL` at wizard start. Removed at exit.
If lock exists: `neoth init is already running. Remove ~/.neoth/.lock to force.` Exit 1.

---

## 5. Non-Interactive Mode

### 5.1 Flag Reference

```
neoth init [OPTIONS]

  --noninteractive              disable interactive prompts; fail on missing required values
  --accept-license              accept license without prompt (required with --noninteractive)
  --operator-id <id>            set operator identity
  --language <bcp47>            primary language [default: en]
  --code-language <bcp47>       code language [default: same as --language]
  --role <role>                 operator role
  --provider <kind>             claude_cli | openai_api | gemini_api | openai_compat
  --provider-binary <path>      CLI binary path (for claude_cli)
  --provider-key <key>          API key (prefer env NEOTH_PROVIDER_KEY)
  --provider-endpoint <url>     custom endpoint (for openai_compat)
  --provider-model <model>      override default model
  --telegram-token <token>      Telegram bot token (prefer env NEOTH_TELEGRAM_TOKEN)
  --telegram-user-id <id>       restrict bot to single Telegram user ID
  --force                       re-run full wizard even if already initialized
  --dry-run                     print what would be written, write nothing
  --output-json                 final config summary as JSON to stdout
```

### 5.2 Minimal Scripted Deploy

```bash
NEOTH_PROVIDER_KEY="sk-..." neoth init \
  --noninteractive \
  --accept-license \
  --operator-id <your-id> \
  --language de \
  --role security-researcher \
  --provider openai_api \
  --provider-model gpt-4o
```

### 5.3 CI / Dockerfile

```dockerfile
ENV NEOTH_PROVIDER_KEY=${NEOTH_PROVIDER_KEY}
RUN neoth init \
    --noninteractive \
    --accept-license \
    --operator-id cibot \
    --provider openai_api
```

---

## 6. Output Artifacts

### 6.1 `~/.neoth/freedom.yaml` (written / merged)

Wizard populates `operator` and `channels` blocks. All other template keys preserved.

Minimum output after wizard:

```yaml
# freedom.yaml -- operator configuration
# Managed by neoth init. Safe to hand-edit after initialization.

operator:
  id: "yourname"
  role: "security-researcher"
  language:
    primary: "de"
    code: "en"

inference:
  allow_cloud_fallback: false   # H3 fix: privacy-first default (SPEC_local_inference.md)

channels:
  telegram:
    enabled: true
  proactive:
    enabled: false   # Phase 3+ opt-in
```

### 6.2 `~/.neoth/council.toml` (created if missing)

Defaults from `SPEC_council_governance.md section 1`. Not exposed in 7-step wizard.

### 6.3 `~/.neoth/.initialized` Marker

```json
{
  "initialized_at": "2026-05-13T12:34:56.789Z",
  "neoth_version": "0.1.0",
  "wizard_version": 1,
  "operator_id": "yourname",
  "steps_completed": [1, 2, 3, 4, 5, 6, 7],
  "provider_kind": "claude_cli",
  "channels": ["telegram"]
}
```

Written atomically: to `.initialized.tmp` then renamed. Mode `0600`.
Re-run: `initialized_at` preserved, `reconfigured_at` added, `steps_completed` takes union.

---

## 7. Telemetry Policy

**Default: ZERO.** No opt-out prompt. No background ping. No anonymous stats dialog.

Wizard does NOT call any remote URL except provider/channel verification explicitly
triggered by the user in steps 5 and 6. No registration with any service.

`.initialized` marker is local-only and never transmitted.

Opt-in only: `neoth telemetry on` (Phase 3+, not implemented Day 1-30).

---

## 8. Error Handling

| Error | Behavior |
|-------|---------|
| `~/.neoth/` not writable | Exit 2: Cannot write ~/.neoth/: permission denied. Run: chmod 700 ~/.neoth |
| Provider verification fails | Warn + retry/skip offer; wizard continues |
| Telegram token invalid | Warn + retry/skip offer; wizard continues |
| Non-TTY without `--noninteractive` | Exit 1: Not a terminal. Use --noninteractive. |
| `--noninteractive` without `--accept-license` | Exit 1: --accept-license required. |
| Lock file exists | Exit 1: Already running. Remove ~/.neoth/.lock to force. |
| Partial write failure | Rollback, remove `.initialized.tmp`, exit 2 |

Exit codes:
- `0` -- success (including deliberate abort at license step)
- `1` -- config error (bad input, missing required flag)
- `2` -- I/O error (permission denied, disk full)
- `3` -- provider verification failed in `--noninteractive` mode

---

## 9. Implementation Notes (Phase 1 Day 3-4)

### 9.1 Rust Crate Dependencies

Add to `Cargo.toml` on Day 3:

```toml
clap        = { version = "4.5", features = ["derive", "env"] }
dialoguer   = "0.11"   # interactive prompts: Select, Input, Password, Confirm
indicatif   = "0.17"   # progress spinner for connection test stubs
console     = "0.15"   # TTY detection: Term::stdout().is_term()
chrono      = { version = "0.4", features = ["serde"] }
```

`dialoguer` covers all 7 steps. `console` provides TTY detection.

### 9.2 Atomic Config Write Strategy

1. Accumulate all wizard state in `WizardState` struct (in-memory throughout wizard)
2. After step 7: serialize to `.tmp` files in `~/.neoth/`
3. Rename `.tmp` -> final: `credentials/` first, then `freedom.yaml`, then `.initialized`
4. Any rename failure: attempt rollback of already-renamed files, exit 2

### 9.3 Existing File Merge

`freedom.yaml`: load as `serde_yaml::Value`, deep-merge wizard sections, serialize back.
Use `indexmap::IndexMap` (not `HashMap`) to preserve YAML key order.
`credentials/`: replace only the affected provider or channel block.

### 9.4 Module Structure

```
src/cli/
+-- mod.rs       <- Clap root + subcommand dispatch
+-- init.rs      <- neoth init wizard (7 steps, WizardState, step runners)
+-- chat.rs      <- neoth chat stub (Day 5+)
+-- profile.rs   <- neoth profile stub (Day 38+, SPEC_proactive_learning section 7)
+-- quota.rs     <- neoth quota stub (Day 50+, SPEC_council_governance)
+-- provider.rs  <- neoth provider subcommand stub
+-- channel.rs   <- neoth channel subcommand stub
```

### 9.5 Required Tests (Day 4 gate)

Unit:
- `is_first_run()` with temp dir: exists/missing cases
- operator-id validation: reserved words, length bounds, charset rejection
- BCP-47 simplified validation: valid and invalid codes
- Telegram token regex: valid/invalid format
- API key format: sk- prefix check, min length

Integration (isolated temp HOME):
- Full `--noninteractive` run: assert `.initialized` written + `freedom.yaml` correct
- Re-run idempotency: second run reads existing, prompts before overwrite
- `--dry-run`: assert no files written to disk

---

## 10. `neoth profile` CLI Reference

Phase 1 stub. Full implementation Day 38+ (SPEC_proactive_learning.md section 7).

```
neoth profile show              -- print operator profile from idx_profile (Hypothalamus)
neoth profile --set-role <r>   -- update freedom.yaml + emit WAL 0x36 PROFILE_DELTA
neoth profile redact <field>   -- add to idx_profile_redactions (never_recreate: true)
neoth profile export            -- dump profile as JSON
```

Wizard step 4 sets initial role. Subsequent changes via `neoth profile --set-role`.

---

## 11. `neoth quota` CLI Reference

Phase 1 stub. Full implementation Day 50+ (SPEC_council_governance.md).

```
neoth quota status              -- today council usage vs budget (council.toml)
neoth quota reset               -- reset daily counters (operator auth required)
neoth quota set --max-debates N -- update council.toml max_debates_per_day
```

---

## 12. Post-Wizard Channel Commands

If step 6 was skipped:

```
neoth channel add telegram      -- runs step 6 logic in isolation
neoth channel list              -- list configured channels + enabled status
neoth channel test telegram     -- send echo message to verify connection
neoth channel remove telegram   -- delete from credentials/channels.yaml + freedom.yaml
```

---

## 13. Security Checklist

- [ ] No operator-id, role, or language transmitted to any remote during wizard
- [ ] API keys never printed to stdout (masked `****{last4}`)
- [ ] API keys never in tracing logs (log `[redacted]`)
- [ ] `credentials/` files created mode `0600`
- [ ] `~/.neoth/` created mode `0700`
- [ ] Telegram token masked in all logs and summary output
- [ ] `--provider-key` flag: warn if visible in `ps aux` (recommend env var)
- [ ] Lock file via `O_CREAT|O_EXCL` (no TOCTOU window)
- [ ] `.initialized` written last via atomic rename from `.tmp`
- [ ] Zero telemetry by default; no remote call without explicit user trigger

---

## 14. Future (Phase 2+)

- Step 5: configure Right Hemisphere (Gemini) + Corpus Callosum (Codex) at Day 38+
- OAuth PKCE flow for Claude CLI
- `neoth init --profile <file>`: import from exported profile JSON
- `neoth init --import-jarvis`: migration from OpenClaw/Jarvis config format
- Multi-operator: `neoth init --operator <id>` for secondary operators on same machine
- `neoth telemetry on`: opt-in anonymous version-check ping (Phase 3+)
