# CLI Reference

The CLI is the operator cockpit for NEOTH. GUI users can ignore most of this; pros can script almost everything.

## First run

```bash
neoth init
neoth gui
neoth doctor
neoth status
```

| Command | Purpose |
| :-- | :-- |
| `neoth init` | Run CLI onboarding wizard. |
| `neoth gui` | Start the GUI wizard/chat/control surface. |
| `neoth doctor` | Diagnose setup, providers, channels, local models, WAL, policy. |
| `neoth status` | Show daemon, memory, provider, channel, cluster, and model status. |

## Chat and recall

```bash
neoth chat "hello"
neoth recall "the router issue from last month"
neoth ingest ./document.pdf
```

| Command | Purpose |
| :-- | :-- |
| `neoth chat <prompt>` | Ask NEOTH from the terminal. |
| `neoth recall <query>` | Search memory and indexed context. |
| `neoth ingest <path>` | Ingest a file, folder, document, image, audio, or video. |
| `neoth search <query>` | Search local indexed material where configured. |

## Profile

```bash
neoth profile show --evidence
neoth profile pending
neoth profile approve <id>
neoth profile decline <id> --reason "wrong"
neoth profile redact identity.location
neoth profile pause
neoth profile resume
```

| Command | Purpose |
| :-- | :-- |
| `profile show` | Show active profile facts. |
| `profile show --evidence` | Include evidence, confidence, and source. |
| `profile pending` | List pending memory proposals. |
| `profile approve <id>` | Approve a pending profile claim. |
| `profile decline <id>` | Decline a pending profile claim. |
| `profile redact <field>` | Remove and optionally block relearning. |
| `profile export` | Export profile as JSON/Markdown. |
| `profile pause/resume` | Control learning. |

## Privacy and audit

```bash
neoth privacy audit --last 30d
neoth wal verify
neoth wal show --last 50
neoth plugin audit
```

| Command | Purpose |
| :-- | :-- |
| `privacy audit` | Show destinations, sensitive events, provider calls, plugin activity. |
| `wal verify` | Verify local event chain. |
| `wal show` | Inspect recent WAL events. |
| `plugin audit` | Inspect plugin capabilities and activity. |

## Providers and models

```bash
neoth provider list
neoth provider setup openai
neoth provider doctor
neoth model list
neoth model fetch qwen
neoth model fetch ouro
neoth model fetch clip
neoth model fetch whisper
```

| Command | Purpose |
| :-- | :-- |
| `provider list` | Show configured providers. |
| `provider setup <name>` | Configure cloud/local provider. |
| `provider doctor` | Diagnose auth, routing, circuit breakers. |
| `model list` | Show local model catalog/cache. |
| `model fetch <name>` | Download a local model. |
| `model doctor` | Diagnose local model cache and runtime. |

## Channels

```bash
neoth channel setup telegram
neoth channel setup whatsapp
neoth channel setup slack
neoth channel setup discord
neoth channel setup keet
neoth channel setup email
neoth channel setup calendar
neoth channel doctor
neoth serve
```

| Command | Purpose |
| :-- | :-- |
| `channel setup <name>` | Guided channel setup. |
| `channel doctor` | Verify credentials, allowlists, webhooks, send path. |
| `serve` | Run daemon/channel server. |

## Coding buddy

```bash
neoth code "map this repo and propose a plan" --canvas
neoth code "implement the accepted migration with tests" --dispatch
neoth code review --promote-findings
neoth kanban watch
```

| Command | Purpose |
| :-- | :-- |
| `code <task>` | Run coding workflow. |
| `code --canvas` | Build a planning canvas. |
| `code --dispatch` | Split and dispatch bounded work. |
| `code review` | Review current changes. |
| `kanban watch` | Show live task board. |

## Council

```bash
neoth council ask "review this plan"
neoth council status
neoth council history
neoth council show <id>
```

| Command | Purpose |
| :-- | :-- |
| `council ask` | Force a multi-role review. |
| `council status` | Show budget and trigger state. |
| `council history` | List prior debates. |
| `council show <id>` | Inspect a debate. |

## Skills and plugins

```bash
neoth skill list
neoth skill install ./skill
neoth skill enable rust-review
neoth reload-skills

neoth plugin list
neoth plugin install ./plugin
neoth plugin enable my-plugin
neoth plugin audit my-plugin
```

| Command | Purpose |
| :-- | :-- |
| `skill ...` | Manage data-only skills. |
| `plugin ...` | Manage sandboxed WASM plugins. |
| `reload-skills` | Reload skills without restarting where supported. |

## Automation

```bash
neoth cron list
neoth cron run morning-brief
neoth n8n status
neoth n8n workflows
```

| Command | Purpose |
| :-- | :-- |
| `cron list/run` | Built-in recurring jobs. |
| `n8n status` | Loopback API/workflow status. |
| `n8n workflows` | Installed starter workflows. |

## Mesh and cluster

```bash
neoth cluster discover
neoth cluster confirm <peer>
neoth cluster status
neoth cluster topology
neoth local resources
```

| Command | Purpose |
| :-- | :-- |
| `cluster discover` | Find candidate nodes. |
| `cluster confirm <peer>` | Approve a peer. |
| `cluster status` | Show mesh health. |
| `cluster topology` | Show connected surfaces/nodes. |
| `local resources` | Show GPU/CPU/RAM/model usage. |

## Maintenance

```bash
neoth backup create
neoth rollback list
neoth update check
neoth update apply
neoth export --out ~/neoth-export
```

| Command | Purpose |
| :-- | :-- |
| `backup create` | Create backup. |
| `rollback list` | Show rollback points. |
| `update check/apply` | Self-update where configured. |
| `export` | Export memory/profile/vault data. |
