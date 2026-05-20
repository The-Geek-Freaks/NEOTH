# Council — Multi-LLM Debate

For complex or ambiguous questions, Neoth can run a structured debate between multiple
LLMs before responding. The result is a synthesized answer that has been stress-tested
against opposing views.

**Council is a Phase 2 feature.** Not in v0.1.0.

---

## The three roles

Think of it as three specialists who confer before the answer reaches you:

| Role | Provider | Job |
|------|---------|-----|
| Left Hemisphere | Claude Opus | Primary reasoning. Produces the answer you see. |
| Right Hemisphere | Gemini Pro | Pattern analysis. Looks for things Left missed. Never talks to you directly. |
| Corpus Callosum | Codex GPT | Synthesis and dissent surfacing. Decides if the hemispheres agree enough. |

You always get the answer from Left (Claude). Right and Callosum work in the background.

---

## When Council fires automatically

Council does NOT fire on every message — that would burn through your LLM quotas within hours.
It fires only when all of these conditions are true:

1. **Keyword match** — your message contains one of the trigger keywords:
   `architecture`, `security`, `refactor`, `destructive`, `breaking`
2. **Complexity gate** — your message is substantial (not a short question)
3. **Dissent signal** — Left's initial answer scores above a disagreement threshold
   when Callosum checks it
4. **Rate gate** — fewer than 2 auto-triggers in the past hour
5. **Budget gate** — fewer than 5 debates fired today

All five must pass. A short "what's the security update for openssh?" does not trigger
council even though it contains "security" — the complexity gate kills it.

When council is suppressed, you get Left's direct answer and a note in the WAL event log.

---

## Manual invocation

Force a council debate regardless of triggers:

```
neoth council invoke --task "should I use async or sync Rust here?"
```

With a file:

```
neoth council invoke --task "review this design" --file design.md
```

Manual invokes count against the daily debate budget.

---

## Quota budgets

Council debates consume real LLM quota. The defaults in freedom.yaml limit damage:

```
max_debates_per_day = 5
max_rounds_total_per_day = 25
max_usd_per_day = 2.00
```

**CLI-auth users** (Claude Pro, ChatGPT Plus, Gemini Premium): the `max_usd_per_day` field
is ignored because you pay a flat subscription. The debates-per-day and rounds-per-day caps
still apply.

**API-key users**: all three caps apply.

---

## HTTP 429 handling

When a provider hits its rate limit (HTTP 429), council does not fail — it cascades to the
next provider in the fallback chain. You will not see an error; the debate continues with
a substitute.

The cascade order:
- Debate primary: `claude-cli -> gemini-cli -> codex-cli`
- Debate fallback: `qwen-local -> mistral-cli -> deepseek-cli`
- Emergency: local model (if available)

A 429 event is logged in WAL for visibility.

---

## Quota status

```
neoth quota status
```

Example output:

```
Provider quotas — last 24h
================================================================
claude-cli      [████████░░] 162/200 requests  (81% used)
codex-cli       [██████░░░░] 119/200 requests  (60% used)
gemini-cli      [█████░░░░░] 142/250 requests  (57% used)
qwen-local      [unlimited] 8,234 requests

Council debates today: 3 / 5 max
Auto-triggers this hour: 1 / 2 max

Health:
  claude-cli       OK
  codex-cli        OK
  gemini-cli       OK     (last 429: never)
  qwen-local       OK
```

The `requests` counts come from WAL events, not from the providers themselves. They may
differ from the provider's own count if a request failed before logging.

---

## Managing council

```
# View recent debates
neoth council list --since 7d

# Full transcript of a specific debate
neoth council inspect <verdict_id>

# Pause auto-triggers until tomorrow
neoth council suppress --until tomorrow

# Adjust the daily debate cap
neoth council budget set max_debates_per_day 10

# Manually reset quota tracking (debug only)
neoth quota reset claude-cli
```

---

## Adjusting trigger sensitivity

If council fires too often, raise the gates in freedom.yaml:

```yaml
council:
  smart_trigger:
    min_user_msg_tokens: 1200    # was 800 — only longer messages qualify
    require_dissent_score_gt: 0.6  # was 0.4 — require stronger disagreement
    max_auto_triggers_per_hour: 1  # was 2 — halve the rate
```

If you want council to never fire automatically but keep manual invocation:

```yaml
council:
  smart_trigger:
    max_auto_triggers_per_hour: 0
```
