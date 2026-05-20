# Profile — Proactive Learning

Neoth learns about you over time so it does not need to be re-told things it has already
heard. This page explains what gets stored, how it works, and how to control it.

Profile learning is a **Phase 2** feature. In v0.1.0 (Day-30 MVP), profile commands exist
but no automatic learning fires yet.

---

## What profile fields exist

Neoth builds a typed profile with the following categories:

| Category | Examples | Default |
|----------|----------|---------|
| `identity` | Name, age, role, city-level location | ON |
| `preferences` | Food, music, sleep schedule, communication style | ON |
| `relationships` | People you mention: name + role + sentiment | ON |
| `skills` | Domains + proficiency (Beginner/Intermediate/Advanced/Expert) | ON |
| `goals` | Short/medium/long-term objectives + status | ON |
| `health` | Conditions, medications, allergies, fitness habits | **OFF (PII)** |
| `schedule` | Routines, recurring patterns, important dates | ON |
| `emotional_baseline` | Typical state, stressors, energy patterns | ON |
| `operator_preferences` | How you want Neoth to behave (tone, autonomy, language) | ON |

Health fields require an explicit opt-in in `freedom.yaml`:

```yaml
profile:
  learn:
    health: true    # default is false
```

---

## How learning works

After every conversation exchange, Neoth runs a background extraction pass over the
last 2-3 turns. It looks for things you said directly — not things you quoted, forwarded,
or that Neoth itself said.

Each finding becomes a **profile claim** with a **confidence score** between 0.0 and 1.0.

Claims strengthen over time (Hebbian reinforcement):
- First time you mention something: claim created at low confidence
- Each time you confirm or repeat it: confidence increases
- After ~26 reinforcements from 0.5: confidence reaches 0.95

Claims weaken if you stop mentioning them:
- Default decay: 0.995 per day
- At 0.995/day: confidence halves after ~138 days without reinforcement
- Below 0.1 confidence: claim becomes inactive (still in WAL audit trail, not shown to LLM)

### What counts as valid evidence

Only your own words count. The extraction layer attributes each segment of conversation before
running: your statements, Neoth's responses, quoted/forwarded text, code blocks. Only segments
classified as your direct speech feed into profile extraction. Pasting an article or forwarding
a message cannot poison your profile.

---

## Privacy: local extraction by default

Profile extraction runs on a **local model** (Qwen3-4B, see [local-models.md](local-models.md)).
Your conversation text stays on your machine.

The cloud LLM (Claude) only sees the profile **summary** — the high-confidence fields formatted
into a few hundred tokens — not the raw conversation content it was extracted from.

If the local model is unavailable (not downloaded, GPU offline), extraction is **skipped** for
that session. It does not silently fall back to a cloud provider unless you explicitly opt in:

```yaml
inference:
  allow_cloud_fallback: true   # default is false
```

---

## PII gates

Some fields are sensitive enough to require explicit opt-in:

- `health` — medical information. Off by default.
- `identity.location` — precise coordinates. City-level is always on if `identity: true`;
  GPS-level requires a separate flag.

Even with health turned off, your conversation text is not transmitted anywhere for extraction
(local model only). The gate just prevents health-related claims from being stored in `idx_profile`.

---

## CLI commands

```
# Show your active profile (fields with confidence >= 0.1)
neoth profile show

# Show full detail including confidence scores and evidence events
neoth profile show --raw

# Remove a specific field permanently
neoth profile redact identity.location

# Remove an entire category
neoth profile redact health

# Remove everything (GDPR right-to-delete)
neoth profile redact --all

# Pause learning for this session
neoth profile pause

# Pause for the rest of the day
neoth profile pause --scope=day

# Pause indefinitely
neoth profile pause --scope=forever

# Resume after a pause
neoth profile resume

# Export your profile as JSON
neoth profile export

# Export as Markdown
neoth profile export --format=md

# Export only high-confidence fields
neoth profile export --confidence-floor=0.7

# Show what the extractor did for a specific event
neoth profile inspect <event_id>
```

---

## GDPR right-to-delete

`neoth profile redact --all` removes all profile claims from the active index immediately.
The WAL audit trail records *that* a redaction occurred and *when*, but not *what* the
values were — those are zeroed out during the next compaction pass.

If you want to prevent a specific field from ever being re-learned:

```
neoth profile redact identity.location
```

By default, Neoth will not re-learn that field even if you mention your location again in
the future. The redaction registry persists across daemon restarts.

If you want to allow the field to be re-learned later, use:

```
neoth profile redact identity.location --allow-relearn
```

---

## How the profile is used

Neoth uses your profile in three places:

**Context injection** — fields with confidence >= 0.6 are included in the LLM's context
before every response. The LLM knows your name, communication style, relevant skills, etc.
without you repeating them. Budget: ~200 tokens for the profile section.

**Recall ranking** — when Neoth searches past conversations for relevant context, results
related to your skill domains get a small boost. If you work in security research, security-related
past conversations rank higher.

**Council consultation** (Phase 2) — when multiple LLMs are debating an answer, the synthesizing
model can consult your profile to break ties. It only sees the same 200-token summary, not raw scores.

---

## Approval gate

If you want to review profile changes before they take effect:

```yaml
profile:
  learn:
    require_approval: false   # set to true
```

With approval on, new claims are held in a staging queue. Review and approve:

```
neoth profile show --pending
neoth profile approve         # approve all pending
neoth profile approve <id>    # approve one
neoth profile reject <id>     # reject one permanently
```
