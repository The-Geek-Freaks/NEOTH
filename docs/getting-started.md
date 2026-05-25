# Getting Started

Get NEOTH running, create first memory, and connect a first surface.

NEOTH has two happy paths:

| Path | Use it when |
| :-- | :-- |
| **GUI path** | You want guided setup, plain-language choices, and no config editing. |
| **CLI path** | You are installing over SSH, scripting setup, or prefer terminal control. |

## 1. Install

Fast path:

```bash
cargo install neoth
```

Source path:

```bash
git clone https://github.com/The-Geek-Freaks/NEOTH
cd NEOTH/SRC
cargo install --path neothd
cargo install --path neothd-gui
```

Verify:

```bash
neoth --version
neoth doctor
```

See [install.md](install.md) for release binaries, Linux/macOS installer, Windows MSVC, and source-build details.

## 2. Run the wizard

GUI:

```bash
neoth gui
```

CLI:

```bash
neoth init
```

The wizard configures:

| Step | What you choose | What NEOTH writes |
| :-- | :-- | :-- |
| Identity | Name, language, style, role, response preference. | Operator profile seed and communication defaults. |
| Privacy | How much NEOTH may remember and what needs approval. | Profile approval gate, redaction policy, autonomy level. |
| Models | Cloud provider, local models, cost and fallback rules. | Provider routing and local model configuration. |
| Channels | GUI, CLI, Telegram, WhatsApp, Slack, Discord, Keet, email, calendar. | Credentials, channel allowlists, and safe defaults. |
| Tools | Obsidian, n8n, Paperless, Todoist, local folders, plugins. | Integration config and capability boundaries. |
| Mesh | LAN, Tailscale, Hysteria, cluster nodes. | Discovery, pairing, topology, and consent rules. |

The normal path does not require editing YAML. Advanced config still lives in `~/.neoth/freedom.yaml` for operators who want it.

## 3. First chat

```bash
neoth chat "hello"
```

Try a first approved memory:

```bash
neoth chat "Remember that I prefer direct answers and work mostly in Rust."
neoth profile pending
neoth profile approve <id>
neoth recall "how do I like answers?"
```

Depending on your autonomy setting, NEOTH may ask in the GUI instead of requiring CLI approval.

## 4. Check what NEOTH knows

```bash
neoth profile show --evidence
neoth privacy audit --last 7d
neoth wal verify
```

Useful actions:

| Command | Purpose |
| :-- | :-- |
| `neoth profile show --evidence` | Show profile claims with sources and confidence. |
| `neoth profile redact <field>` | Remove a fact and prevent unwanted relearning. |
| `neoth profile pending` | Review memory proposals before they become durable facts. |
| `neoth privacy audit` | Show provider destinations, network surfaces, and sensitive events. |
| `neoth wal verify` | Verify the local event chain. |

## 5. Connect a first channel

Telegram is usually the fastest phone path.

1. Open Telegram and talk to `@BotFather`.
2. Create a bot with `/newbot`.
3. Copy the bot token.
4. Run the channel wizard:

```bash
neoth channel setup telegram
neoth serve
```

Other surfaces:

| Surface | Command |
| :-- | :-- |
| WhatsApp Business | `neoth channel setup whatsapp` |
| Slack | `neoth channel setup slack` |
| Discord | `neoth channel setup discord` |
| Keet | `neoth channel setup keet` |
| Email | `neoth channel setup email` |
| Calendar | `neoth channel setup calendar` |

See [channels.md](channels.md) for credentials, allowlists, webhook notes, and E2E checks.

## 6. Set up local models

Local models are optional, but they are the best default for private profile learning.

```bash
neoth model list
neoth model fetch qwen
neoth model fetch ouro
neoth model fetch clip
neoth model fetch whisper
```

| Model | Used for |
| :-- | :-- |
| Qwen | Local profile extraction and memory learning. |
| Ouro | Local thinking/reasoning provider. |
| CLIP | Image embeddings and visual recall. |
| Whisper | Audio and video transcription. |

See [local-models.md](local-models.md).

## 7. Use the coding buddy

```bash
cd ~/src/my-project
neoth code "map this repo and propose the next migration" --canvas
neoth code "implement the accepted migration with tests" --dispatch
neoth kanban watch
```

NEOTH can keep:

- project decisions
- codebase conventions
- accepted plans
- review findings
- test failures and fixes
- follow-up tasks

See [../PLAN/SPEC_coding_workflow.md](../PLAN/SPEC_coding_workflow.md) for the design and [cli-reference.md](cli-reference.md) for commands.

## 8. Keep it healthy

Run this when setup feels wrong:

```bash
neoth doctor
neoth status
neoth privacy audit
neoth wal verify
```

If a channel fails, check [troubleshooting.md](troubleshooting.md).

If a provider fails, check [providers.md](providers.md).

If memory feels wrong, check [profile.md](profile.md).
