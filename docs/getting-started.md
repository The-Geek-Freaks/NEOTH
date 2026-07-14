# Getting Started

Get NEOTH running, create first memory, and connect a first surface.

NEOTH has two happy paths:

| Path | Use it when |
| :-- | :-- |
| **GUI path** | You want guided setup, plain-language choices, and no config editing. |
| **CLI path** | You are installing over SSH, scripting setup, or prefer terminal control. |

## 1. Install

Current path (the source tree is 1.0.0, but no signed `v1.0.0` archive or
crates.io package exists yet):

```bash
git clone https://github.com/The-Geek-Freaks/NEOTH
cd NEOTH/SRC
cargo install --locked --path neothd --features release-desktop
cargo install --locked --path neothd-gui
cargo install --locked --path neoth-migrate
cargo install --locked --path neoth-relay
```

After the signed release is published, the bootstrap installer downloads that
archive and verifies it before installation:

```bash
curl -fsSL https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/SRC/install.sh | bash
export PATH="$HOME/.local/bin:$PATH" # automatic profile wiring applies to new shells
```

Binary installs require `minisign` or `cosign`; without either verifier they
fail closed. `NEOTH_ALLOW_UNVERIFIED_RECOVERY=1` is an explicit emergency-only
override for artifacts authenticated out of band.

The separate manual crates.io workflow publishes `neoth-plugin-sdk` first and
allows `neoth` only after the exact SDK version is visible to Cargo.

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
| Channels | GUI, CLI, Telegram, WhatsApp, Slack, Discord. | Credentials, channel allowlists, and safe defaults. Email and calendar are configured separately after the wizard. |
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
neoth verify
```

Useful actions:

| Command | Purpose |
| :-- | :-- |
| `neoth profile show --evidence` | Show profile claims with sources and confidence. |
| `neoth profile redact <field>` | Remove a fact and prevent unwanted relearning. |
| `neoth profile pending` | Review memory proposals before they become durable facts. |
| `neoth privacy audit` | Show provider destinations, network surfaces, and sensitive events. |
| `neoth verify` | Verify HMAC compaction markers in the local WAL. |

## 5. Connect a first channel

Telegram is usually the fastest phone path.

1. Open Telegram and talk to `@BotFather`.
2. Create a bot with `/newbot`.
3. Copy the bot token.
4. Connect the channel:

```bash
neoth channel add telegram
neoth channel test telegram
neoth serve
```

Other surfaces:

| Surface | Command |
| :-- | :-- |
| WhatsApp Business | `neoth channel add whatsapp` |
| Slack | `neoth channel add slack` |
| Keet | Unavailable: no supported public chat API; `neoth channel remove keet` clears legacy state. |
| Discord | `neoth channel add discord`; verify the bot identity without sending via `neoth channel test discord` |
| Email | Source-build opt-in: compile `imap_fetch`, configure IMAP credentials, then run `neoth email fetch` (the named release bundles currently omit this feature) |
| Calendar | Set `calendar.caldav_url` plus credentials in `freedom.yaml` / `credentials.yaml`; use `neoth calendar list` or the GUI Calendar panel |

See [channels.md](channels.md) for credentials, allowlists, webhook notes, and E2E checks.

## 6. Set up local models

Local models are optional, but they are the best default for private profile learning.

```bash
neoth models list
neoth models pull clip
neoth models pull whisper
neoth ouro list
neoth ouro fetch --checkpoint ByteDance/Ouro-1.4B-Thinking
```

Qwen selection is part of `neoth init`; it is intentionally not a
`neoth models pull` target because onboarding sizes the inference topology
before selecting the repository. See [local-models.md](local-models.md) for the
Qwen, Ouro, CLIP, and Whisper workflows.

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
neoth verify
```

If a channel fails, check [troubleshooting.md](troubleshooting.md).

If a provider fails, check [providers.md](providers.md).

If memory feels wrong, check [profile.md](profile.md).
