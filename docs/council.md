# Council

The council is NEOTH's multi-model dissent path. It does not ask every model every time. It triggers when the request is complex, risky, contradictory, high-impact, or explicitly configured.

## Roles

| Role | Job |
| :-- | :-- |
| **Fast / Left** | Normal replies, low-latency help, routine coding, simple tool use. |
| **Deep / Right** | Architecture, risk, long reasoning, review, hard tradeoffs. |
| **Callosum / Orchestrator** | Context passing, dissent surfacing, final synthesis, budget, and audit. |

## When council fires

| Trigger | Example |
| :-- | :-- |
| Complexity | "Design the cluster sync protocol and prove failure modes." |
| Risk | Security, privacy, data deletion, external sends, secrets, migration. |
| Contradiction | Recall says one thing, current context says another. |
| Operator request | `--council` or policy rule. |
| Low confidence | The fast answer is weak or uncertain. |
| High-impact action | Anything that affects files, credentials, calendar, email, cluster, or public output. |

## Manual use

```bash
neoth council ask "review this plan for security and implementation risk"
neoth chat --council "should I run this migration?"
neoth code --council "review the architecture before implementation"
```

## Budget

Council is useful because it is selective.

```toml
[council.budget]
max_debates_per_day = 5
max_usd_per_day = 2.00
trigger = "smart"
```

Check:

```bash
neoth council status
neoth quota status
```

## Dissent output

A good council result should expose:

| Field | Purpose |
| :-- | :-- |
| Main answer | What NEOTH recommends. |
| Dissent | What another role disagreed with. |
| Risk | What could go wrong. |
| Evidence | Which memory, file, provider, or tool result mattered. |
| Action | What is safe to do next. |

## Audit

Council activity should leave WAL events so the operator can inspect:

- why council triggered
- which providers participated
- what the dissent was
- what the final synthesis chose
- how much budget was used

Commands:

```bash
neoth council history
neoth council show <id>
neoth privacy audit --last 7d
```

## Tuning

| Setting | Effect |
| :-- | :-- |
| `trigger = "off"` | Never auto-trigger; manual only. |
| `trigger = "smart"` | Default: complexity/risk/dissent/budget aware. |
| `trigger = "aggressive"` | More debates, useful during design/review. |
| `max_debates_per_day` | Hard cap for automatic council. |
| `max_usd_per_day` | Cost cap for cloud-backed council. |

## Failure behavior

| Failure | Expected behavior |
| :-- | :-- |
| Provider rate limit | Fall back to remaining roles or explain that council is degraded. |
| Budget exhausted | Use fast/deep configured default and record why council did not run. |
| Local model unavailable | Surface fetch/config command and avoid silent privacy fallback. |
| Dissent unresolved | Show the uncertainty instead of pretending consensus exists. |
