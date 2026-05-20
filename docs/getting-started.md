# Getting Started

Get Neoth running in about 10 minutes.

---

## Prerequisites

- **Rust 1.86+** (for building from source). Check: `rustc --version`
- OR grab a pre-built binary from the [releases page](https://github.com/your-org/neoth/releases)
- At least one LLM CLI installed and authenticated:
  - Claude CLI: `claude` — authenticate with your Anthropic account
  - Codex CLI: `codex` — OpenAI account
  - Gemini CLI: `gemini` — Google account
- Minimum 2 GB free disk for WAL + models
- For local model support **(Phase 2):** a GPU with 3 GB VRAM (see [local-models.md](local-models.md))

---

## Install

### Option A — cargo install (simplest)

```
cargo install neoth
```

### Option B — build from source

```
git clone https://github.com/your-org/neoth
cd neoth
cargo build --release
# Binary: target/release/neoth
```

Add `target/release/` to your PATH or copy the binary somewhere in your PATH.

### Option C — pre-built binary

Download from releases, extract, put `neoth` in your PATH. Done.

---

## First run: `neoth init`

Run this once. It creates `~/.neoth/` and walks you through the basics.

```
$ neoth init

  ███╗   ██╗███████╗ ██████╗ ████████╗██╗  ██╗
  ████╗  ██║██╔════╝██╔═══██╗╚══██╔══╝██║  ██║
  ██╔██╗ ██║█████╗  ██║   ██║   ██║   ███████║
  ██║╚██╗██║██╔══╝  ██║   ██║   ██║   ██╔══██║
  ██║ ╚████║███████╗╚██████╔╝   ██║   ██║  ██║
  ╚═╝  ╚═══╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝

  Neoth knows. v0.1.0

[init] Creating ~/.neoth/ ...
[init] Operator ID (leave blank to auto-generate, or enter an ID): your-handle
[init] Default language (ISO 639-1, e.g. en, de): en
[init] Operator role (e.g. developer, security_researcher, none): developer
[init] Writing ~/.neoth/freedom.yaml ... done
[init] Writing ~/.neoth/policy.yaml ... done (from example template)
[init] Writing ~/.neoth/soul.md ... done
[init] Writing ~/.neoth/claude.md ... done
[init] WAL directory: ~/.neoth/wal/ ... created

[init] Done. Run `neoth chat "hello"` to test.
```

This creates:
- `~/.neoth/freedom.yaml` — your permission and learning config ([full reference](configuration.md))
- `~/.neoth/policy.yaml` — per-machine safety rules ([reference](configuration.md#policyyaml))
- `~/.neoth/soul.md` — Neoth's identity template ([reference](configuration.md#soulmd))
- `~/.neoth/claude.md` — operational rules template ([reference](configuration.md#claudemd))
- `~/.neoth/wal/` — the event log (do not delete)

---

## First chat

```
$ neoth chat "hello"

Neoth: Hey. What's up?
```

If you see a response, your LLM auth is working. If you get an auth error, see
[troubleshooting.md#llm-auth-failures](troubleshooting.md#llm-auth-failures).

Try something with memory:

```
$ neoth chat "I'm a backend developer working mostly in Rust"
$ neoth chat "what do you know about me?"
```

After the second message Neoth will recall what you told it in the session. Persistent cross-session
profile learning kicks in from **(Phase 2)** onwards — see [profile.md](profile.md).

---

## First channel: Telegram

The fastest way to get Neoth into a messaging app is Telegram.

**Step 1 — Create a bot**

1. Open Telegram, search for `@BotFather`
2. Send `/newbot`
3. Choose a display name (e.g. `My Neoth`)
4. Choose a username ending in `bot` (e.g. `myneoth_bot`)
5. BotFather replies with a token: `123456789:ABC-DEF1234...`

**Step 2 — Add the token**

Add to your environment (or put in your shell profile):

```
export TELEGRAM_BOT_TOKEN="123456789:ABC-DEF1234..."
```

**Step 3 — Allow your user ID**

Find your numeric Telegram user ID. The easiest way: forward a message from yourself to
`@userinfobot`. It replies with your numeric ID (e.g. `987654321`).

Edit `~/.neoth/policy.yaml`:

```yaml
channels:
  telegram:
    allowed_chat_ids: [987654321]   # your numeric ID
```

Usernames are NOT allowed here — they change. Numeric IDs only.

**Step 4 — Start**

```
$ neoth start
```

```
[neoth] WAL open: ~/.neoth/wal/
[neoth] Telegram adapter: polling
[neoth] Ready.
```

Send a message to your bot in Telegram. You should get a reply.

---

## What happens next?

After your first conversations, Neoth starts building a picture of you:

- **Recall** — it can pull up relevant past conversations when they matter
- **Profile learning** (Phase 2) — it will remember your preferences, skills, and working style
  across sessions without you having to repeat yourself
- **Council** (Phase 2) — for complex or ambiguous questions, multiple LLMs debate before
  answering

See [profile.md](profile.md) to understand what gets stored and how to control it.

---

## Running as a daemon

```
neoth start --daemon
```

Logs go to `~/.neoth/neoth.log`. Stop with `neoth stop`.

---

## Next steps

- Connect more channels: [channels.md](channels.md)
- Understand configuration: [configuration.md](configuration.md)
- All commands: [cli-reference.md](cli-reference.md)
