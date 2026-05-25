# NEOTH Docs

NEOTH is a loyal, local-first AI buddy and operator runtime.

These docs are written for the NEOTH 1.0 public release surface: normal users get the GUI wizard and plain-language controls; pros get the CLI, policies, WAL, local models, plugins, private mesh, and automation.

## Start here

| You are... | Read first | Why |
| :-- | :-- | :-- |
| A normal user | [getting-started.md](getting-started.md) | Install NEOTH, run the wizard, create first memory, connect a channel. |
| Installing on a machine | [install.md](install.md) | Release binaries, cargo install, source build, Windows MSVC, verification. |
| A CLI/operator user | [cli-reference.md](cli-reference.md) | Every command and common operator workflows. |
| Privacy-focused | [profile.md](profile.md), [security/threat-model.md](security/threat-model.md) | Profile approval, redaction, outbound surfaces, audit commands. |
| Using local models | [local-models.md](local-models.md), [providers.md](providers.md) | Qwen, Ouro, CLIP, Whisper, provider routing, fallback rules. |
| Connecting chat apps | [channels.md](channels.md) | Telegram, WhatsApp, Slack, Discord, Keet, email, calendar. |
| Building workflows | [cron-vs-n8n.md](cron-vs-n8n.md), [n8n-api.md](n8n-api.md) | Built-in cron vs n8n, loopback API, auth, audit trail. |
| Extending NEOTH | [plugins.md](plugins.md) | Skills, WASM plugins, permissions, hostcalls, sandbox boundaries. |
| Debugging setup | [troubleshooting.md](troubleshooting.md) | Model auth, channel setup, local models, plugins, privacy checks. |

## Product map

| Area | Docs |
| :-- | :-- |
| First run | [getting-started.md](getting-started.md), [install.md](install.md) |
| Commands | [cli-reference.md](cli-reference.md), [configuration.md](configuration.md) |
| Memory | [profile.md](profile.md), [import-format.md](import-format.md), [architecture.md](architecture.md) |
| Channels | [channels.md](channels.md), [live-e2e-protocol.md](live-e2e-protocol.md) |
| Providers | [providers.md](providers.md), [local-models.md](local-models.md) |
| Council | [council.md](council.md), [architecture.md](architecture.md) |
| Automation | [cron-vs-n8n.md](cron-vs-n8n.md), [n8n-api.md](n8n-api.md) |
| Plugins | [plugins.md](plugins.md), [configuration.md](configuration.md) |
| Security | [security/threat-model.md](security/threat-model.md), [faq.md](faq.md) |
| Troubleshooting | [troubleshooting.md](troubleshooting.md), [faq.md](faq.md) |

## Common paths

### Normal user path

```bash
cargo install neoth
neoth gui
```

Then use the wizard to pick:

- privacy defaults
- local or cloud models
- memory approval level
- chat channels
- Obsidian and document integrations
- automation and autonomy level

### Pro operator path

```bash
neoth init
neoth status
neoth doctor
neoth privacy audit
neoth model list
neoth cluster status
neoth code "plan the next migration" --dispatch
```

### Privacy audit path

```bash
neoth privacy audit --last 30d
neoth profile show --evidence
neoth profile pending
neoth wal verify
neoth plugin audit
```

## Internal planning vs public docs

The `docs/` directory is for users, operators, and contributors.

The `PLAN/` directory is the internal architecture and execution record: specs, reviews, roadmaps, threat work, and backlog history. Start with:

| File | Purpose |
| :-- | :-- |
| [../PLAN/ROAD_TO_1_0.md](../PLAN/ROAD_TO_1_0.md) | v0.3 -> v1.0 release sequencing. |
| [../PLAN/00_DESIGN_v1.1_FINAL.md](../PLAN/00_DESIGN_v1.1_FINAL.md) | Architecture and design direction. |
| [../PLAN/SPEC_coding_workflow.md](../PLAN/SPEC_coding_workflow.md) | Coding canvas, Kanban, dispatch, review loop. |
| [../PLAN/SPEC_profile_claim_guard.md](../PLAN/SPEC_profile_claim_guard.md) | Profile evidence, injection guard, redaction semantics. |
| [../PLAN/SPEC_skill_plugin_system.md](../PLAN/SPEC_skill_plugin_system.md) | Skills and WASM plugin safety model. |

## License

NEOTH is dual-licensed under MIT or Apache-2.0. See the repo root.
