# When to use NEOTH Cron vs an n8n workflow

NEOTH Cron is the native, audited agent scheduler. Jobs live in
`~/.neoth/jobs.yaml`, are atomically live-reloaded by `neoth serve`, and may use
a cron expression, a fixed interval, or a one-shot timestamp. n8n remains the
better surface for visual, cross-service orchestration.

## Use NEOTH Cron when

| Shape | Example |
| --- | --- |
| One autonomous agent task | Prepare a 07:00 brief and announce it in Telegram |
| Bounded tool use | Let one job call an exact allow-list of tools from selected MCP servers |
| Provider-specific workload | Run a research job on one model with ordered 429 fallbacks |
| Dependency wave | Run `publish` only after `collect` and `review` both succeeded |
| Native delivery | Announce through one configured channel or call one registered signed webhook |
| Durable one-shot | Execute once at an RFC3339 timestamp without duplicating after restart |

The job records operator intent only. Provider calls still cross the normal cost,
WAL, and permission gates. Unknown cost or missing output ceilings are not turned
into a cheap estimate. MCP access requires both explicit capability ids and exact
tool names. Delivery targets are checked before provider spend, and the durable
delivery ledger distinguishes queued from delivered.

Useful commands:

```bash
neoth cron create --id morning-brief --name "Morning brief" \
  --cron "0 7 * * *" --tz Europe/Berlin \
  --prompt "Prepare today's concise brief" --channel telegram

neoth cron create --id one-off-review --name "One-off review" \
  --at 2026-08-01T09:00:00Z --prompt "Review the launch evidence" \
  --delivery-mode none

neoth cron pause morning-brief
neoth cron resume morning-brief
neoth cron deliveries --job morning-brief
```

Strict and Custom autonomy disable scheduled execution fail-closed. Manual
`neoth cron run <id>` is also refused while the daemon owns the WAL.

## Use n8n when

| Shape | Example |
| --- | --- |
| Visual branch-heavy workflow | Route an incident through several conditional service steps |
| Broad fan-out | Write to multiple unrelated SaaS systems from one trigger |
| External trigger catalogue | GitHub, CRM, calendar, and vendor-specific trigger nodes |
| Human node-level debugging | A non-developer needs to inspect and replay individual steps |
| Long integration workflow | Loops, joins, transformations, and service-specific retry policies |

n8n owns those orchestration semantics and its database. NEOTH remains behind the
localhost-authenticated integration boundary; do not copy provider or channel
secrets into workflow nodes.

## Decision rule

Use NEOTH Cron when the unit of work is one governed agent job, optionally with a
small exact MCP tool scope and prerequisite jobs. Use n8n when the workflow itself
is the product: many service nodes, visible branching, fan-out, joins, or external
event triggers.

If you need three or more unrelated destinations or start encoding control flow
inside a prompt, move the orchestration to n8n.

## Migration notes

To move a NEOTH job to n8n:

1. Recreate its cron/interval trigger in n8n.
2. Call NEOTH only through the authenticated localhost API.
3. Pause the native job with `neoth cron pause <id>` and verify the n8n run.
4. Delete it only after the replacement has produced the expected audited result.

To move an n8n workflow to NEOTH, first reduce it to one governed agent task.
Create and validate the job with `neoth cron create`, preview it, fire it once with
`neoth cron run`, then disable the n8n trigger. Do not run both schedules during
the cut-over.
