# Profile And Memory

NEOTH has two deliberately separate profile systems:

1. A default-on, deterministic communication profile that learns only how to
   present answers and clarify intent.
2. An optional LLM-backed fact profile for durable claims about the operator's
   preferences, projects and goals.

The communication profile is functional without enabling fact learning. It is
local, subject-bound, inspectable, correctable and removable.

## Communication adaptation

NEOTH classifies observable presentation signals from authenticated human
turns. Raw messages are processed in memory and discarded; only bounded typed
evidence, subject/session bindings, timestamps, content/event hashes and
derived estimates are persisted in
`~/.neoth/profile/communication.json`.

| Dimension | Accepted explicit values |
| :-- | :-- |
| `directness` | `direct`, `balanced`, `gentle` |
| `structure` | `prose`, `bullets`, `numbered-steps` |
| `ambiguity` | `literal-explicit`, `balanced`, `inferential` |
| `processing-load` | `one-chunk`, `compact`, `deep` |
| `context-amount` | `minimal`, `short-recap`, `continuity-rich` |
| `pace` | `immediate-full`, `staged`, `ask-before-next` |
| `clarification` | `act-with-stated-assumptions`, `ask-one-question`, `clarify-first` |
| `correction-style` | `acknowledge-and-fix`, `explain-then-fix`, `silent-fix` |

Explicit settings outrank explicit corrections, response feedback and passive
observations. Passive evidence must cross the configured observation,
distinct-session and confidence floors before it affects a prompt, and its
weight decays over time. At exact `full` autonomy, stricter thresholds may make
a stable low-risk accommodation durable until revoked. No communication
preference can change authentication, permission, cost or safety decisions.

### Inspect and correct

```bash
neoth profile communication status
neoth profile communication show
neoth profile communication why directness

neoth profile communication set directness direct
neoth profile communication set structure numbered-steps

neoth profile communication reset structure
neoth profile communication reset

neoth profile communication disable
neoth profile communication enable
```

`why` shows typed evidence metadata, never raw messages. Resetting one dimension
removes its evidence and estimate. Running `reset` without a dimension removes
the complete local operator communication subject, including any explicitly
declared context. Privacy/reset actions remain available while automatic
adaptation is disabled.

### Prompt disclosure

```bash
neoth profile communication prompt-export none
neoth profile communication prompt-export accommodations-only
neoth profile communication prompt-export label-and-accommodations
```

The default is `accommodations-only`: providers receive concrete presentation
instructions, not a diagnostic or neurotype label. `none` disables this prompt
layer without deleting the local state.

NEOTH never infers autism, ADHD, neurodivergence or another health diagnosis.
Neuro-context can be stored only through an explicit typed operator action:

```bash
neoth profile communication context declare neurodivergent
neoth profile communication context declare autistic
neoth profile communication context declare adhd
neoth profile communication context show
neoth profile communication context clear
```

Declarations default to accommodations-only use. Sending the label itself
requires two independent opt-ins: the global prompt-export mode must be
`label-and-accommodations`, and the declaration must be created with
`--prompt-use label-and-accommodations`. `context clear` revokes future use but
keeps the local declaration history; use a complete communication `reset` for
physical local removal of that subject.

### Incognito

```bash
neoth chat --incognito "one private turn"
```

An Incognito CLI turn returns before opening communication-profile state and
does not record new communication evidence. It therefore performs zero
communication-profile reads and writes. The provider lifecycle remains
auditable through content-free typed metadata. GUI, Buddy, channel and direct
n8n API Incognito controls are not yet parity-complete.

### Current wiring boundary

| Surface | Prompt adaptation | Inspect/correct/reset controls |
| :-- | :-- | :-- |
| CLI chat | Wired | CLI commands above |
| Authenticated inbound channel dispatch | Wired with subject isolation | CLI only |
| Council, retry/fallback and sub-agent layers reached by chat | Preserve the compiled presentation layer | CLI only |
| GUI and Buddy conversations that invoke `neoth chat` | Inherit chat adaptation | Not yet exposed in GUI/Buddy |
| Direct n8n `/api/provider/call` | Wired to the fixed authenticated operator subject; never learns automation prompts; supports `incognito: true` | Profile controls remain CLI-only |
| Doctor | Wired communication-state readiness/integrity check | Strict schema, typed evidence, subject isolation and private permissions; reports counts without profile content |
| `neoth memory --forget <topic>` | Separate memory cascade with explicit communication metadata | Never erases communication state because typed evidence is not topic-addressable; points to the dedicated erase command |
| `neoth memory erase-communication-profile` | Wired dry-run/`--confirm` erasure for one exact subject; omission defaults to operator | `--subject` accepts a case-sensitive pseudonymous handle; metadata-only audit hashes the selected subject |
| `neoth export` | Writes the V2 redacted `communication_profile.json` in JSONL and Markdown bundles | It contains only active concrete accommodations plus schema/presence/redaction metadata; `--subject` and `--list-subjects` fail because generic export has no authenticated private-DSAR authority |

These remaining parity gaps keep `GOLD-R4-11` open in the Gold roadmap.
`profile.communication.cluster_sync` is reserved and defaults to `false`; no
production synchronization path consumes it yet.

## Optional fact profile

The fact-profile extractor is off by default because it invokes a model and can
cost provider tokens:

```yaml
profile:
  learn_enabled: false
  learn_provider: local_qwen
  allow_cloud_fallback: false
  require_approval: true
```

When explicitly enabled or manually run, the pipeline is:

```text
Conversation / document / channel event
  |
  v
Attribution and sanitizer
  |
  |---- operator-authored text
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

Only attributable operator text may become a proposal. Forwarded text, quoted
emails, copied articles, model output and code blocks are not evidence of what
the operator believes. Automatic health and diagnostic claims are rejected;
explicit neuro-context belongs only to the typed communication declaration
surface above.

### Fact categories

| Category | Examples | Default stance |
| :-- | :-- | :-- |
| `identity` | Name, role, language, city-level location. | Evidence-backed and approval-gated. |
| `preferences` | Food, music, tools and durable operator choices. | Evidence-backed and approval-gated. |
| `projects` | Active repos, goals, services, decisions and constraints. | Evidence-backed and approval-gated. |
| `relationships` | People mentioned and their role in the operator's life/work. | Sensitive; evidence and approval required. |
| `skills` | Domains, proficiency, preferred stack and learning goals. | Evidence-backed and approval-gated. |
| `goals` | Short-, medium- and long-term objectives. | Evidence-backed and approval-gated. |
| `schedule` | Routines, recurring patterns and important dates. | Sensitive; evidence and approval required. |
| `health` | Conditions, diagnoses, medication and similar medical claims. | Automatic inference and storage are blocked. |

Every durable fact claim carries a field key, value, source/evidence identity,
confidence, approval state, redaction policy and timestamp.

### Review and run

```bash
neoth profile pending
neoth profile approve <extraction-id>
neoth profile decline <extraction-id> --reason "not true"

neoth profile show
neoth profile show --field preferences.answer_style
neoth profile summary

neoth profile run --last-n 20
neoth profile run --trigger-event <event-id>
```

The exact autonomy and `profile.require_approval` policy determine whether a
claim is queued or applied. Profile mutations remain auditable.

### Redaction

```bash
neoth profile redact identity.location --reason "remove this field"
neoth profile redactions
neoth profile unredact --id <redaction-id>
```

Redaction marks a field `never_recreate` until the operator explicitly revokes
that redaction. There is no `profile redact --all`, `profile pause`,
`profile resume` or `profile export` command in the current CLI.

`neoth memory --forget <topic>` previews and, with `--confirm`, deletes matching
SQLite/WAL-backed memory and fact-profile data. It never covers the separate
communication JSON state because typed presentation evidence is not
topic-addressable; the command reports that boundary explicitly. Use
`neoth memory erase-communication-profile` for a no-write operator inventory
and add `--confirm` for complete operator-subject erasure. A channel-subject
DSAR export requires an independently authenticated private-DSAR authority;
the generic export CLI neither enumerates pseudonymous handles nor supplies
that authority.

The general `neoth export` command writes the V2 redacted
`communication_profile.json` for both output formats. It contains only active
concrete operator accommodations and non-sensitive schema, presence and
redaction metadata; it never emits a subject handle, session, hash, evidence,
scope, provenance, confidence, timestamp, declared context, or any count of
those records. An absent state has an explicit redacted absent marker. Private
`--subject <handle>` and `--list-subjects` modes remain parser-compatible but
fail before state read, output creation or stdout because no authenticated
private-DSAR authority is implemented. `--since` does not filter this
current-state record.
The separate general `idx_profile` fact-claim set is not yet exported, so
complete fact-profile export remains an open Gold requirement.

## Privacy checklist

```bash
neoth profile communication status
neoth profile communication show
neoth profile show
neoth profile pending
neoth privacy audit --last 30d
neoth verify
```

You should be able to answer:

- What does NEOTH know?
- Why does it believe that?
- When did it learn it?
- Which provider saw which prompt layer?
- Can I correct or delete it?
- Can I stop relearning or prompt export?

If the answer is unclear, treat it as a bug.
