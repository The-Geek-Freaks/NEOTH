# When to use NEOTH's cron vs an n8n workflow

NEOTH ships two scheduling surfaces. They overlap on purpose: simple
recurring tasks should live in `freedom.yaml` because the operator
can read the schedule + tweak it without leaving NEOTH. Anything
multi-step / cross-service belongs in n8n because the YAML cron
intentionally has no "if this then that" syntax.

This page is the rule-of-thumb. Skim it before adding a third
cron entry that pulls data from three places and posts to four
channels — that's the n8n threshold.

---

## Use `freedom.yaml` cron when

| Shape                                     | Example                                           |
| ----------------------------------------- | ------------------------------------------------- |
| One CLI command, no logic                 | `0 9 * * 1-5  →  neoth recall "today's standup"`  |
| Cleanup / sweep                           | `0 3 * * *   →  neoth memory gc --tier cold`      |
| Single-channel send                       | `0 21 * * *  →  neoth chat send daily-summary`    |
| Operator-readable in 1 line               | Anything that fits the format above               |

Schedule lives in `freedom.yaml::cron.entries[]` — every entry is
5-field standard cron + a `command:` string. NEOTH's `cron` task
picks them up on daemon start + on `neoth reload`. No external
process. No webhook plane. No browser UI.

**Strengths:**
- Operator sees the full schedule by running `cat freedom.yaml`.
- Survives reboot via the daemon's normal `neoth serve` start.
- Same security envelope as the rest of NEOTH (consent gates,
  autonomy level, WAL audit).
- Zero extra processes — runs inside the daemon's tokio runtime.

**Limitations:**
- No `if X then Y else Z` branching.
- No fan-out to multiple downstreams from one trigger.
- No external service triggers (webhook in, GitHub push, etc.).
- No retry-with-backoff envelope (you write the retry in the command).

---

## Use an n8n workflow when

| Shape                                     | Example                                                 |
| ----------------------------------------- | ------------------------------------------------------- |
| Multi-step pipeline                       | Recall → summarise via provider → send via channel      |
| Fan-out from one trigger                  | One schedule fires write-to-archive AND send-to-channel |
| Conditional logic                         | If "consent denied" count > 5 → escalate                |
| External webhook in                       | GitHub push triggers a NEOTH summary                    |
| Visual debugging needed                   | Operator wants to step through node-by-node             |

The three bootstrap workflows (`daily_summary` / `morning_brief` /
`weekly_stats`) shipped in `assets/n8n_workflows/` show the
pattern: every node is an HTTP request against NEOTH's localhost
API; n8n owns the orchestration.

**Strengths:**
- Visual flow + per-node debug view.
- Branching, loops, fan-out built-in.
- Triggers from external services (Webhook, GitHub, Calendar, ...).
- Operator can hand a workflow to a non-developer collaborator.

**Limitations:**
- Extra process — operator must install + maintain n8n.
- Schedule lives in n8n's database, not `freedom.yaml`.
- More moving parts during an outage diagnosis.
- Operator-facing UX is "open browser to n8n" — friction vs CLI.

---

## Decision flow

```
                  ┌─ one CLI command? ──→ freedom.yaml cron
                  │
new recurring task ┤
                  │
                  └─ multi-step / branching / external trigger ──→ n8n workflow
```

**Tiebreaker:** if the schedule is something an operator will tweak
weekly ("change the morning brief from 07:30 to 08:00"), n8n is
nicer — they edit in the UI without restarting NEOTH. If it's
"fire and forget" (the sweep cleanup), `freedom.yaml` keeps the
state visible.

---

## Migration notes

A `freedom.yaml` cron entry can be ported to n8n by:

1. Create an n8n "Schedule Trigger" with the same cron expression.
2. Add an "HTTP Request" node pointing at NEOTH's localhost API
   (`http://127.0.0.1:9744/api/...`) with the bearer token from
   `freedom.yaml::n8n.api_token`.
3. Delete the `freedom.yaml::cron.entries[]` entry.
4. Run `neoth reload` so NEOTH stops scheduling the local cron.

n8n → `freedom.yaml` migration goes the other way: when the n8n
workflow simplifies down to a single HTTP call, copy the schedule
into `freedom.yaml::cron.entries[]` + delete the n8n workflow.
