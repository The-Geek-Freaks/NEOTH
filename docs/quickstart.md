# NEOTH Quickstart

This guide is for someone who has never installed a local AI assistant before.
Follow it in order. Do not edit YAML unless you choose the operator path.

## The current source path

> The source tree is versioned for **NEOTH 1.0.0**. Tagged release artifacts and
> the crates.io package are not published yet. Until the first signed release,
> use the source checkout; the bootstrap installer has no stable archive to
> download yet.

```bash
git clone https://github.com/The-Geek-Freaks/NEOTH
cd NEOTH
NEOTH_SRC_DIR="$PWD" bash scripts/install.sh
neoth
neoth doctor
```

After `v1.0.0` is published, the signed-release shortcuts are:

```bash
curl -fsSL https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/SRC/install.sh | bash
export PATH="$HOME/.local/bin:$PATH" # automatic profile wiring applies to new shells
```

Windows (PowerShell): `irm https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/SRC/install.ps1 | iex`.

## Rebuild or update from source

```bash
cd NEOTH
git pull --ff-only
NEOTH_SRC_DIR="$PWD" bash scripts/install.sh
neoth
```

## First run: choose once

Bare `neoth` opens one accessible **Graphical setup / Command-line setup**
choice on a graphical desktop, persists it in `NEOTH_HOME/interface.json`, and
does not ask again. SSH, CI, inactive Windows sessions, macOS sessions without
a matching logged-in console user, and display-less Unix sessions use the CLI
without opening a popup. Automation can
set exactly `NEOTH_INTERFACE=gui` or `NEOTH_INTERFACE=cli`; malformed values
fail closed. You can switch later with `neoth gui`,
`neoth interface set gui`, `neoth interface set cli`, or **Open CLI** in GUI
Settings → Maintenance.

The selected wizard asks five things:


| Question | Safe default |
| :-- | :-- |
| Who are you? | Your first name or handle. |
| How private should NEOTH be? | Local-first. |
| Which model should answer? | Local model if available, otherwise your chosen provider. |
| What may NEOTH remember? | Ask before durable memory. |
| Which surfaces should connect? | Start with GUI and CLI, add channels later. |

You can change every answer later.

> **Heads-up — security-research skills are on by default.** NEOTH bundles dual-use
> registers (`lowkey_base`, `raskal`, `archon`) for authorised pentest / CTF / research
> work. They ship **enabled** and are authorisation-scoped (they refuse mass-harm and
> out-of-scope targets). Turn off any you don't want in `freedom.yaml` under
> `skills.disabled:` (see the README Privacy section for the snippet).

## Your first useful commands

```bash
neoth chat "Remember that I prefer direct answers."
neoth recall "how do I like answers?"
neoth profile show
neoth profile communication status
neoth privacy audit --last 7d
```

Expected result:

- NEOTH recalls the preference.
- The fact-profile view shows the materialised claim, while communication
  status shows whether local presentation adaptation is active.
- The privacy audit shows whether anything left your machine.

## Add a chat channel

Start with one channel. Do not connect every app on day one.

```bash
neoth connect            # list channels + how to wire each one
neoth connect telegram   # show Telegram's connect steps
neoth doctor
```

If Doctor warns about channel wiring, run:

```bash
neoth doctor --explain "channels wiring"
```

## Use local-only mode

```bash
neoth preset activate fully-local
neoth preset apply fully-local
neoth doctor
neoth privacy audit --last 30d
```

Local-only mode is strict: if a local model is not ready, NEOTH should explain
the missing model or cache instead of silently sending private profile work to a
cloud model.

## Common setup errors

| Symptom | Command | Meaning |
| :-- | :-- | :-- |
| `cargo` is not found | `rustup --version` | Rust is not installed or the terminal was not restarted. |
| GUI does not start | `neoth doctor` | Doctor will check config, model cache, and runtime files. |
| Local model is slow | `neoth doctor --explain "model caches"` | Model files may be missing or CPU fallback is active. |
| Telegram/Slack does nothing | `neoth doctor --explain "channels wiring"` | Token, socket-mode, webhook, or allowed-user config is incomplete. |
| Claude CLI behaves strangely | `neoth doctor --explain "tmux for claude_cli"` | Interactive CLI providers may need tmux/PTY support. |
| Plugins do not run | `neoth doctor --explain "wasm plugins"` | Build/runtime plugin host state does not match config. |
| Cluster discovery is quiet | `neoth doctor --explain "cluster mDNS announcer"` | Current network is not trusted for broadcast discovery. |

## Keep it boring

For the first hour:

1. Install NEOTH.
2. Run the GUI.
3. Add one memory.
4. Verify the memory.
5. Run the privacy audit.
6. Add one channel.
7. Run Doctor again.

That gives you a working buddy before you touch providers, plugins, n8n, mesh,
or coding automation.
