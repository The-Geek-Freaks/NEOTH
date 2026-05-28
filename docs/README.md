# NEOTH Docs

NEOTH is a private AI buddy and local operator runtime: simple enough for
normal users, explicit enough for pros.

## Start here

| Need | Read |
| :-- | :-- |
| Install from zero | [quickstart.md](quickstart.md) |
| Choose an install path | [install.md](install.md) |
| Prove privacy/local behavior | [privacy.md](privacy.md) |
| Understand commands | [cli-reference.md](cli-reference.md) |
| Fix setup problems | [troubleshooting.md](troubleshooting.md) and `neoth doctor --list-checks` |
| Connect chat apps | [channels.md](channels.md) |
| Use local models | [local-models.md](local-models.md) |
| Configure providers | [providers.md](providers.md) |
| Build workflows | [cron-vs-n8n.md](cron-vs-n8n.md), [n8n-api.md](n8n-api.md) |
| Extend NEOTH | [plugins.md](plugins.md) |
| Compare alternatives | [compare/README.md](compare/README.md) |
| Read release notes | [release-notes-v1.0.md](release-notes-v1.0.md) |

## Common paths

### Normal user

```bash
cargo install neoth
neoth gui
neoth doctor
```

### Operator

```bash
neoth init
neoth status
neoth doctor
neoth privacy audit --last 30d
neoth profile show --evidence
neoth wal verify
```

### Fully local

```bash
neoth preset activate fully-local
neoth preset apply fully-local
neoth doctor
neoth privacy audit --destinations
```

### Coding buddy

```bash
neoth code "plan the next migration"
neoth kanban watch
neoth code check
neoth recall "why did we choose the current storage layout?"
```

## Product map

| Area | Docs |
| :-- | :-- |
| First run | [quickstart.md](quickstart.md), [getting-started.md](getting-started.md), [install.md](install.md) |
| Commands | [cli-reference.md](cli-reference.md), [configuration.md](configuration.md) |
| Memory | [profile.md](profile.md), [import-format.md](import-format.md), [architecture.md](architecture.md) |
| Privacy/security | [privacy.md](privacy.md), [security/threat-model.md](security/threat-model.md), [../SECURITY.md](../SECURITY.md) |
| Channels | [channels.md](channels.md), [live-e2e-protocol.md](live-e2e-protocol.md) |
| Providers | [providers.md](providers.md), [local-models.md](local-models.md) |
| Council/brain paths | [council.md](council.md), [architecture.md](architecture.md) |
| Automation | [cron-vs-n8n.md](cron-vs-n8n.md), [n8n-api.md](n8n-api.md) |
| Plugins | [plugins.md](plugins.md), [configuration.md](configuration.md) |
| Competitors | [compare/openhuman.md](compare/openhuman.md), [compare/openclaw.md](compare/openclaw.md), [compare/hermes.md](compare/hermes.md) |

## Internal planning vs public docs

`docs/` is for users, operators, and contributors.

`PLAN/` is the internal architecture and execution record: specs, reviews,
roadmaps, threat work, and backlog history. Public users should not need it to
install or understand NEOTH.

## License

NEOTH is dual-licensed under MIT OR Apache-2.0.
