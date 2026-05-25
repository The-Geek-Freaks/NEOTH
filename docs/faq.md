# FAQ

## What is NEOTH?

NEOTH is a loyal, local-first AI buddy and operator runtime.

It combines:

- GUI and CLI
- long-term profile memory
- local model paths
- chat channels
- coding canvas and Kanban
- Obsidian mirror
- n8n/cron automation
- Paperless/email/calendar workflows
- private mesh and cluster pairing
- auditable policy and permission gates

## Who is it for?

Both normal users and pros.

| User | NEOTH path |
| :-- | :-- |
| Normal user | `neoth gui`, guided wizard, plain-language settings, no YAML happy path. |
| Developer | `neoth code`, canvas, Kanban, repo memory, review promotion, tests. |
| Privacy hardliner | Local profile extraction, redaction, audit, no silent cloud fallback. |
| Homelab operator | Tailscale/Hysteria/Keet mesh, cluster status, local models, n8n, Paperless. |
| Automation builder | Cron, n8n localhost API, plugins, skills, capability gates. |

## Does NEOTH send my data to the cloud?

Only when you configure a cloud provider or enable a cloud-backed feature.

Default privacy model:

| Data/action | Default stance |
| :-- | :-- |
| Profile extraction | Local model path where available. |
| Profile facts | Approval/evidence/redaction controlled. |
| Raw memory | Local WAL and local indexes. |
| Provider calls | Audited destination and explicit provider config. |
| Cloud fallback for learning | Off unless explicitly enabled. |
| Plugins | Sandboxed and capability-scoped. |

Run:

```bash
neoth privacy audit --last 30d
```

That shows where requests went and which sensitive surfaces were used.

## Can I use NEOTH without Claude/OpenAI/Gemini?

Yes, if you configure a capable local model for the tasks you expect.

Cloud providers are useful for high-end reasoning and convenience. Local Qwen/Ouro paths are useful for profile learning, private recall, and local reasoning when your hardware can handle it.

```bash
neoth model list
neoth model fetch qwen
neoth model fetch ouro
```

## Does NEOTH work offline?

Partially to fully, depending on your model setup.

| Function | Offline behavior |
| :-- | :-- |
| WAL memory | Works offline. |
| Profile browsing/redaction | Works offline. |
| Recall over local indexes | Works offline. |
| Local Qwen/Ouro inference | Works offline after model download. |
| CLIP/Whisper local media processing | Works offline after model download. |
| Cloud provider calls | Require network. |
| External channels | Require network. |
| Tailscale/Hysteria/Keet mesh | Depends on network path. |

## How do I delete or correct memory?

Show evidence:

```bash
neoth profile show --evidence
```

Redact one field:

```bash
neoth profile redact identity.location
```

Redact all profile facts:

```bash
neoth profile redact --all
```

Review pending memory before it is accepted:

```bash
neoth profile pending
neoth profile approve <id>
neoth profile decline <id> --reason "wrong"
```

## Can NEOTH relearn something I redacted?

Not if the redaction is marked as blocked from relearning.

NEOTH's profile memory is designed around evidence, approval, redaction, and replay safety. Redaction should be a control surface, not a suggestion.

## Why Rust?

NEOTH has a sensitive local runtime: memory, WAL, provider routing, plugins, channels, and automation.

Rust is a good fit because it gives:

- predictable performance
- single-binary deployment
- strong type boundaries
- no garbage collector pauses in the WAL path
- safer plugin and permission plumbing
- good cross-platform story

## How is NEOTH different from a normal chatbot?

| Normal assistant | NEOTH |
| :-- | :-- |
| Starts over every session. | Builds continuity over weeks and months. |
| Lives in one app. | Follows you through GUI, CLI, phone channels, Obsidian, automation, and private mesh. |
| Has opaque memory. | Shows evidence, confidence, approval state, and redactions. |
| Optimizes for provider defaults. | Adapts to your language, style, constraints, tools, and privacy settings. |
| Sends things you cannot easily audit. | Exposes provider destinations, memory facts, plugin capabilities, and WAL events. |
| Is easy or powerful, rarely both. | Wizard-first for normal users, deep operator stack for pros. |

## How is NEOTH different from Hermes, OpenHuman, and OpenClaw?

Short version:

| Project | Main strength | NEOTH synthesis |
| :-- | :-- | :-- |
| Hermes | Workflow and Kanban-shaped coding. | NEOTH adds loyal memory, profile safety, private mesh, and operator runtime around the coding loop. |
| OpenHuman | Human-readable assistant memory. | NEOTH adds WAL authority, local profile extraction, channels, automation, and coding cockpit. |
| OpenClaw | Gateway/channel/canvas/agent energy. | NEOTH folds that direction into a Rust local-first buddy with permissioned memory. |
| NEOTH | Loyal buddy + private memory + coding studio + operator runtime. | One memory, every surface, your rules. |

See the comparison table in the root [README](../README.md#neoth-vs-hermes-vs-openhuman-vs-openclaw).

## What is the WAL?

The WAL is NEOTH's write-ahead event log.

It is the durable source of truth for memory and sensitive runtime events: profile changes, provider calls, plugin actions, channel sends, automation, recovery, and verification.

Useful commands:

```bash
neoth wal verify
neoth wal show --last 50
```

## What are skills and plugins?

| Extension | Best for | Safety model |
| :-- | :-- | :-- |
| Skills | Instructions, templates, domain knowledge, workflows. | Data-only, no code execution. |
| WASM plugins | Real logic at lifecycle hooks. | Capability declarations, fuel limit, memory cap, timeout, hostcall allowlist. |

## Can NEOTH control my computer?

Only inside the autonomy and permission policy you choose.

Read-only and low-risk actions can be allowed automatically at standard settings. Mutating, external, credential, system, or high-impact actions require approval unless you explicitly grant a scoped capability.

## Does NEOTH support multiple users?

NEOTH is primarily operator-owned.

Channel integrations can identify different humans and isolate their conversation/profile state where configured. For a personal deployment, the common case is one operator with multiple surfaces and devices.

## What should I run when something feels wrong?

```bash
neoth doctor
neoth status
neoth privacy audit
neoth wal verify
```

Then check [troubleshooting.md](troubleshooting.md).

## License?

NEOTH is dual-licensed under MIT or Apache-2.0. See the repository root.
