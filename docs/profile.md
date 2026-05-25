# Profile And Memory

NEOTH learns about the operator so it does not need to be reintroduced every session. Profile memory is permissioned, evidence-backed, redactable, and auditable.

## What NEOTH can learn

| Category | Examples | Default stance |
| :-- | :-- | :-- |
| `identity` | Name, role, language, city-level location. | On with approval/evidence. |
| `preferences` | Communication style, food, music, tools, answer length. | On with approval/evidence. |
| `projects` | Active repos, goals, services, decisions, constraints. | On with approval/evidence. |
| `relationships` | People you mention and their role in your life/work. | On with care. |
| `skills` | Domains, proficiency, preferred stack, learning goals. | On with approval/evidence. |
| `goals` | Short, medium, long-term objectives and status. | On with approval/evidence. |
| `schedule` | Routines, recurring patterns, important dates. | On with approval/evidence. |
| `health` | Conditions, meds, allergies, fitness habits. | Off unless explicitly enabled. |
| `operator_preferences` | Tone, autonomy, privacy, provider preference, coding style. | On with approval/evidence. |

## How learning works

```text
Conversation / document / channel event
  |
  v
Attribution and sanitizer
  |
  |---- your own words
  |---- quoted/forwarded text
  |---- model output
  |---- code/document content
  v
Profile extractor
  |
  v
Claim guard
  |
  v
Approval gate
  |
  v
WAL event + idx_profile view
```

Only your own attributable words should become profile claims. Forwarded text, quoted emails, copied articles, model output, and code blocks are not trusted as "things the operator believes" by default.

## Profile claims

Every durable profile fact should carry:

| Field | Purpose |
| :-- | :-- |
| Claim key | Stable field path such as `preferences.answer_style`. |
| Value | The learned fact. |
| Evidence | Event/source proving why NEOTH believes it. |
| Confidence | Strength of the claim. |
| Source | Channel, file, chat, document, or operator action. |
| Approval state | Pending, approved, declined, redacted. |
| Redaction policy | Whether it may be relearned. |
| Timestamp | When it was learned or updated. |

## Approval gate

Review proposed memory before it becomes active:

```bash
neoth profile pending
neoth profile approve <id>
neoth profile decline <id> --reason "not true"
```

Autonomy affects when NEOTH asks:

| Autonomy | Profile behavior |
| :-- | :-- |
| Strict | Queue memory proposals for explicit approval. |
| Standard | Queue sensitive or uncertain claims; allow low-risk preferences based on policy. |
| Elevated | Apply routine claims, queue sensitive/high-impact claims. |
| Full | Apply within policy scope, still audit everything. |

## Local extraction

Profile extraction is designed to run locally where possible.

```bash
neoth model fetch qwen
neoth model fetch ouro
```

Cloud fallback for profile extraction must be explicit. If local inference is unavailable and fallback is disabled, NEOTH should skip learning instead of silently uploading private context.

## Redaction

Show profile facts:

```bash
neoth profile show --evidence
```

Redact one field:

```bash
neoth profile redact identity.location
```

Redact everything:

```bash
neoth profile redact --all
```

Block relearning:

```bash
neoth profile redact identity.location --never-recreate
```

Allow relearning later:

```bash
neoth profile redact identity.location --allow-relearn
```

## Pause and resume learning

```bash
neoth profile pause
neoth profile pause --scope day
neoth profile pause --scope forever
neoth profile resume
```

## Export

```bash
neoth profile export --format json --out profile.json
neoth profile export --format md --out profile.md
```

## How profile affects answers

| Use | Effect |
| :-- | :-- |
| Context injection | Approved high-confidence facts inform tone, constraints, projects, and preferences. |
| Recall ranking | Relevant memories are boosted based on operator profile and active topic. |
| Coding buddy | Repo conventions, review preferences, test habits, and prior decisions become available. |
| Council | Dissent and synthesis can consider operator constraints without seeing raw private logs. |
| Proactivity | NEOTH can suggest reminders or workflows when patterns are strong enough and policy permits it. |

## Privacy checklist

```bash
neoth profile show --evidence
neoth profile pending
neoth privacy audit --last 30d
neoth wal verify
```

You should be able to answer:

- What does NEOTH know?
- Why does it believe that?
- When did it learn it?
- Which provider saw what?
- Can I correct or delete it?
- Can I block relearning?

If the answer is unclear, treat it as a bug.
