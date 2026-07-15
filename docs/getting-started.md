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
cd NEOTH
NEOTH_SRC_DIR="$PWD" bash scripts/install.sh
```

The source-wide installer needs Node.js 22.16+ only to build the Keet
standalone. Published desktop archives include it and need no Node.js.

After the signed release is published, the bootstrap installer downloads that
archive and verifies it before installation:

```bash
curl -fsSL https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/SRC/install.sh | bash
export PATH="$HOME/.local/bin:$PATH" # automatic profile wiring applies to new shells
```

Binary installs need no preinstalled verifier. They prefer installed `minisign`
or `cosign`; otherwise they download a temporary Cosign binary and compare it
to a platform SHA-256 pinned from an immutable official Sigstore source before
execution. A mismatch fails closed. `NEOTH_ALLOW_UNVERIFIED_RECOVERY=1` is an
explicit emergency-only path for a verifier download failure and an archive
authenticated out of band.

The same installation transaction includes NEOTH's release-bound Graphify
self-knowledge. It is already generated and verified in the release; a normal
machine does not need Python, Graphify, or a separate model download to use it.
Upgrades replace only that immutable baseline and preserve your NEOTH Wiki and
`User Overlays`.

The separate manual crates.io workflow publishes `neoth-plugin-sdk` first and
allows `neoth` only after the exact SDK version is visible to Cargo.

Verify:

```bash
neoth --version
neoth doctor
```

See [install.md](install.md) for release binaries, Linux/macOS installer, Windows MSVC, and source-build details.

## 2. Choose GUI or CLI once

Start the installed product:

```bash
neoth
```

On a desktop, the first launch presents one keyboard- and screen-reader-safe
GUI/CLI choice and persists it under the active `NEOTH_HOME`. Later bare
launches open the chosen surface without asking again. SSH, CI, and headless
sessions never wait for a popup and use the CLI for that session.

For automation, set the exact lowercase override
`NEOTH_INTERFACE=gui` or `NEOTH_INTERFACE=cli`. The explicit choice becomes
the instance default; invalid, empty, differently-cased, or whitespace-padded
values fail closed instead of silently choosing another surface.

Direct GUI launch:


```bash
neoth gui
```

Direct CLI setup:

```bash
neoth init --cli
```

Switch later with `neoth gui`, `neoth interface set gui`,
`neoth interface set cli`, or **Open CLI** under GUI Settings → Maintenance.

## 3. Run the wizard

The wizard configures:

| Step | What you choose | What NEOTH writes |
| :-- | :-- | :-- |
| Identity | Name, language, style, role, response preference. | Operator profile seed and communication defaults. |
| Privacy | How much NEOTH may remember and what needs approval. | Profile approval gate, redaction policy, autonomy level. |
| Models | Cloud provider, local models, cost and fallback rules. | Provider routing and local model configuration. |
| Channels | Pick an initial surface and common phone/work channels. The Channels panel and `neoth channel` expose the complete canonical registry after onboarding. | Credentials, channel allowlists, and safe defaults. Email and calendar are configured separately after the wizard. |
| Tools | Obsidian, n8n, Paperless, Todoist, local folders, plugins. | Integration config and capability boundaries. |
| Mesh | LAN, Tailscale, Hysteria, cluster nodes. | Discovery, pairing, topology, and consent rules. |

The normal path does not require editing YAML. Advanced config still lives in `~/.neoth/freedom.yaml` for operators who want it.

## 4. First chat

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

## 5. Check what NEOTH knows

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

## 6. Connect a first channel

Telegram is usually the fastest phone path.

1. Open Telegram and talk to `@BotFather`.
2. Create a bot with `/newbot`.
3. Copy the bot token.
4. Get your numeric Telegram user ID (for example from `@userinfobot`).
5. Connect the channel with a closed sender allowlist:

```bash
neoth channel add telegram \
  --token "$TELEGRAM_BOT_TOKEN" \
  --telegram-user-id "$TELEGRAM_USER_ID"
neoth channel test telegram
neoth serve
```

Other surfaces:

| Surface | Command |
| :-- | :-- |
| WhatsApp Business | `neoth channel add whatsapp` |
| Slack | `neoth channel add slack` |
| Keet-identity private topic | Run `neoth-keet-bridge setup` and `serve`, exchange peer `self_id` values, then `neoth channel add keet`; this is a NEOTH Pear/Hyperswarm topic, not an existing Keet app room. |
| Discord | `neoth channel add discord`; verify the bot identity without sending via `neoth channel test discord` |
| All messaging adapters | Open the GUI Channels panel or run `neoth channel list`; both use the same 15-channel registry and the same add/test/remove contract. |
| Email | Source-build opt-in: compile `imap_fetch`, configure IMAP credentials, then run `neoth email fetch` (the named release bundles currently omit this feature) |
| Calendar | Set `calendar.caldav_url` plus credentials in `freedom.yaml` / `credentials.yaml`; use `neoth calendar list` or the GUI Calendar panel |

See [channels.md](channels.md) for credentials, allowlists, webhook notes, and E2E checks.

## 7. Set up local models

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

## 8. Use the coding buddy

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
