# C2 — Addendum: fermisense article (re-read) + system-design-101 clean-room path

Written by the main agent, not a subagent. Agent C's report dismissed the fermisense
article as "off-topic — zero design constraints". **That verdict is wrong and is
superseded here.** The article was re-fetched and read in full (27.6 KB of text).
It is not about permission tiers — Agent C was right about that — but it is directly
about NEOTH's core thesis, and it carries concrete, portable numbers.

---

## Part 1 — fermisense.com/when-machines-take-the-wheel/

Real title: **"The Rise of Intelligence Ownership: a task-trained open source model vs
the frontier"** (Fermisense, 2026-07-27). It is a vendor content-marketing piece with a
sales CTA, so treat its framing with suspicion — but the experiment it reports is
specific, reproducible and cited, and its thesis is *NEOTH's own thesis with numbers
attached*.

### What it actually claims

A GRPO-trained fine-tune of a **9B open-source model** beat five frontier
configurations (GPT-5.5, GPT-5.6-sol, Gemini 3.1 Pro, Claude Opus 4.8, Claude Fable 5)
on one e-commerce catalog-review workflow:

| Metric | Frontier best | Trained 9B specialist |
|---|---|---|
| Share of achievable score | 76.9 % | **87.3 %** (base 9B untrained: 64.2 %) |
| Cost / 1,000 listings | $19 (cheapest) – $172 (dearest); $34 for the strongest | **$0.50** |
| Cost multiple | — | 40× cheaper than cheapest frontier, ~340× vs dearest |

Training cost: **two RTX PRO 6000 GPUs, 1,000 optimizer steps, ~3.5 days, ~$500 GPU
time**, using the open-source `prime-rl` framework. It crossed the frontier band after
~250 steps (≈1 day). Appendix lists 8 more third-party deployments with the same shape
(Cognition, AT&T, LinkedIn, Ambience, Phonely, OpenPipe, Perplexity, Checkr) plus
Bridgewater (~30 % fewer mistakes), Harvey, Intercom Fin Apex.

### The five ideas worth taking

1. **"If a decision can be scored, a model can practice it; if it can only be debated,
   it cannot."** This is a clean gate for NEOTH's own self-improvement loop.
2. **Digital twin** — the workflow rebuilt as a simulated environment with the *same
   tools*, the *same scorer* and known-correct answers per episode (177,767 episodes
   built from the Amazon Berkeley Objects dataset, ~13,000-category taxonomy).
3. **Asymmetric error costs encoded in the reward** — a missed policy violation costs
   **7×** a false alarm. Business priority expressed as a number, not prose.
4. **The prompt tax.** 2,800 characters of optimized instructions raised input-token
   bills by **28–55 % on every call, forever**, and made the strongest zero-shot
   extractor (Gemini) *worse*. "Prompted task knowledge is rented per call; trained task
   knowledge is bought once and lives in the weights."
5. **Deployed models generate their own training data** — logged decisions distil into
   supervised fine-tuning sets, so each retrain is cheaper and better-informed.

### The right-tool matrix (portable as a routing policy)

|  | Verifiable outcome | Non-verifiable outcome |
|---|---|---|
| **High volume** | Fine-tune a specialist | Human in the loop |
| **Low volume** | Prompt-optimized frontier | Human in the loop |
| **Changing facts, not judgment** | Retrieval — at any volume | Retrieval |

Their 9-point "is this a fine-tuning candidate" checklist, condensed: high volume ·
outcome checkable by rule/test/rubric with no human · experts agree what correct looks
like · a capable model already succeeds *sometimes* · the right answer can't be a lucky
guess · multi-step (reason → tool calls → committed decision) · runs on your own tools
and schemas · different mistakes carry different costs · sensitive data cannot leave
your infrastructure.

That last point is the sovereignty argument, and it is NEOTH's whole reason to exist.

### NEOTH ground truth — verified, not assumed

```
rg -in 'fine.?tune' --type rust SRC/neothd/src
  → 4 hits, ALL about model naming (abliterated/uncensored variants):
    analytics/babel/anonymize.rs:98, coding/tool_router.rs:179,
    cli/models.rs:106, models/gguf_variants.rs:37
  → zero training-data or fine-tuning machinery
```

| Capability | NEOTH today | Gap |
|---|---|---|
| Scored eval harness | `memory/eval_harness.rs` (719), `recall/goldset.rs` (256), `council/eval.rs` (390), `council/quality_score.rs` (961), `skills/test_harness.rs` (948) | Exists, but each scores **one subsystem**. No workflow-level episode runner, no rubric with per-error-class weights. |
| Corpora | `eval/prompt_injection_corpus` only | No task-episode corpus |
| Per-call cost | `providers/cost.rs` (1533), `meter.rs` (355), `quota.rs` (630), `token_cap.rs` (259), `council/daily_budget.rs` (605), `daemon/usage_log.rs` (1349: `UsageEvent`, `record_provider_call`, `aggregate`→`UsageRollup`/`PerProviderTotals`) | Cost **per call** is solid. Cost **per decision / per workflow** does not exist. |
| Trajectory export | `daemon/export.rs` (947) exports *memory* (episode/consolidated/longterm/groundtruth) as JSONL | No agent-trajectory or decision-trace export. Nothing SFT-shaped. |
| Asymmetric error cost | `security/risk_gate.rs`, `permissions/tier_classifier.rs` classify risk | No numeric per-error-class weighting anywhere |
| Specialist ↔ frontier delegation | `models/hemisphere_preset.rs`, `providers/recursive_mas.rs`, `coding/cerebellum_provider.rs`, `models/selector.rs` | Routing exists. The *criterion* (volume × verifiability) does not. |

### Steal-list

| # | Item | Target NEOTH file | Effort | Real consumer |
|---|---|---|---|---|
| F1 | **Fine-tune dataset export** — `neoth export training-set` producing OpenAI/ShareGPT-shaped JSONL from `daemon/usage_log.rs` events + `skills/teacher.rs` corrections + `feedback/` accept/reject signals. Operator-owned, local-only, redacted through `security/redact.rs`. | `daemon/train_export.rs` (new) + `cli/export.rs` | M | Alex, directly. Also the natural feed for a future local specialist. |
| F2 | **Cost-per-decision rollup** — extend `UsageRollup` with a workflow/task dimension so a rollup answers "what did *this* recurring task cost me this month", not just "what did this provider cost". | `daemon/usage_log.rs` (extend `UsageRollup`, `aggregate`) + GUI usage panel | S | GUI cost panel, `neoth usage` |
| F3 | **Prompt-tax metric** — measure the token delta that system-prompt/skill/context injection adds per call, and surface it. NEOTH injects skills, memory, repo context and council prompts; nothing currently reports what that overhead costs. | `tokens/budget.rs` + `providers/meter.rs` | S | `neoth usage --prompt-tax`, GUI |
| F4 | **Weighted rubric with asymmetric error classes** — a scorer where each error class carries an operator-set multiplier (their 7× missed-violation constant is the worked example). | `council/quality_score.rs` (extend) + `freedom.yaml` weights | M | Council scoring, eval harness |
| F5 | **Workflow episode runner ("digital twin lite")** — replay recorded task episodes against the current config with a fixed scorer, so a config/model/skill change is scored on *Alex's own* workload before it ships. | `eval/` corpus + `memory/eval_harness.rs` (generalize) | L | Release gate, `neoth eval run` |
| F6 | **Fine-tune-candidate advisor** — run the 9-point checklist against the operator's own `usage_log` data and say "this recurring workflow of yours is a specialist candidate; here is the volume, the cost, and whether it's verifiable". | `analytics/` (new `specialist_advisor.rs`) | M | Proactive surface, `neoth advise` |
| F7 | **Route-by-verifiability policy** — encode the volume × verifiability matrix as an explicit routing input in `models/selector.rs`, instead of the current implicit capability/cost heuristics. | `models/selector.rs` + `models/hemisphere_preset.rs` | M | Every provider dispatch |

**F1 + F2 are the standout pair.** They cost little, they are pure operator sovereignty
(your data, your costs, exportable, local), and F1 turns NEOTH's existing correction and
feedback machinery — which already exists and is currently only used in-place — into an
asset Alex owns and can act on. That is the article's actual argument applied to NEOTH.

**Do NOT adopt:** in-process training. NEOTH ships a Rust daemon; GPU RL training is a
separate, offline, opt-in workflow. NEOTH's job is to *produce the dataset and the
scorer*, not to run GRPO. Anything else violates rule 1 (self-contained) and rule 8
(runs on Alex's mom's Win11 box).

**Licence:** article text is © Fermisense, all rights reserved — quote sparingly with
attribution, do not reproduce. The *ideas and numbers* are facts and freely usable.

---

## Part 2 — system-design-101: the clean-room rewrite path

Operator question: *"dann machen wir eben einen rewrite … und bauen den in neoth ein was
nützlich ist? damit brechen wir kein copyright"* — can we write our own version instead?

**Short answer: yes, and it is legally clean — provided it is a genuine clean-room
rewrite and not a paraphrase.** The distinction matters, so here it is precisely.

### What the licence actually restricts

ByteByteGo's `system-design-101` is **CC BY-NC-ND 4.0**:
- **ND (NoDerivatives)** — you may not distribute an adapted version of *their work*.
- **NC (NonCommercial)** — you may not use *their work* commercially.
- Both attach to **their specific expression**: their diagrams, their images, their exact
  wording, and their creative selection/arrangement.

### What copyright does not cover

**Facts, ideas, methods, systems and topic names are not copyrightable.** Nobody owns
"what a CDN is", "how a write-through cache differs from write-back", the CAP theorem,
consistent hashing, or the fact that an API gateway sits in front of services. That
knowledge is in RFCs, vendor docs, papers and a hundred textbooks. A **list of topics**
carries thin-to-no copyright.

So the boundary is:

| Allowed | Not allowed |
|---|---|
| Using their table of contents as a **topic checklist** | Copying or translating their prose |
| Writing original explanations from **primary sources** | Sentence-by-sentence paraphrase of their text (= derivative work) |
| Drawing our own diagrams from the underlying protocol | Re-drawing their diagrams, even restyled |
| Stating the same facts | Reusing their examples, analogies, ordering and phrasing together |

Paraphrasing their article closely is the one thing that would actually be a derivative
work under ND — which is exactly the trap a lazy "rewrite" falls into.

### Clean-room protocol (mandatory if we do this)

1. **Topic list only.** Extract nothing but headings from the repo into a scratch
   checklist. Never copy body text or images into the tree.
2. **Different author, different sources.** The writer works from primary sources —
   RFCs, official docs (AWS/GCP/Postgres/Kafka/Redis), the original papers (Dynamo,
   Raft, Bigtable) — and does **not** have the ByteByteGo text open.
3. **Original diagrams** in NEOTH's own design-system style, or none at all.
4. **Cite primary sources**, never system-design-101, so provenance is auditable.
5. `THIRD_PARTY_LICENSES` gets **no** ByteByteGo entry — because nothing of theirs ships.

### Honest cost/benefit

A 40+ topic system-design knowledge pack written properly is **days of work per
subsection**, and NEOTH already has `tools/deep_research.rs`, `tools/arxiv.rs` and
`tools/web_fetch.rs` — meaning it can *fetch* current authoritative material on demand
rather than carrying a frozen snapshot. A bundled pack goes stale; retrieval does not.

Also relevant: there are **freely licensed alternatives** that need no clean-room dance
at all — MIT/Apache/CC-BY system-design corpora exist and can be bundled directly with
attribution. Checking those first is strictly cheaper than rewriting ByteByteGo from
scratch.

### Verdict

- **system-design-101 as a source artifact: still SKIP.** Nothing of theirs enters the tree.
- **A NEOTH-native system-design knowledge skill: VIABLE, and copyright-clean**, under the
  clean-room protocol above. Tracked as an optional, low-priority item — it is
  knowledge-pack work, not engine work, and it competes for time with F1–F7 above, which
  are worth more.
- **Better first move:** survey permissively-licensed system-design corpora (MIT / Apache /
  CC-BY). If one is good enough, bundle it with attribution and skip the rewrite entirely.
