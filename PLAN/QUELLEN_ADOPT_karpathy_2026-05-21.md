# QUELLEN Adoption Report: andrej-karpathy-skills
**Date:** 2026-05-21  
**Source:** `QUELLEN/andrej-karpathy-skills/` (forrestchang/andrej-karpathy-skills — Karpathy-inspired Claude Code guidelines)  
**Analyst:** senior AI engineer pass

---

## 1. What This Repo Is

A single-CLAUDE.md plugin (Claude Code marketplace: `forrestchang/andrej-karpathy-skills`) encoding four behavioural anti-patterns Andrej Karpathy documented from observing LLM coding failures. The repo has **no per-skill YAML files** — the entire content is one document with four principles, plus a Cursor `.mdc` mirror and `plugin.json`/`marketplace.json` packaging metadata.

**Canonical files with skill-relevant content:**
- `CLAUDE.md` — the four principles as plain prose directives
- `.cursor/rules/karpathy-guidelines.mdc` — identical content, Cursor packaging
- `EXAMPLES.md` — annotated before/after code showing each principle in practice
- `.claude-plugin/plugin.json` — Claude Code plugin manifest
- `.claude-plugin/marketplace.json` — marketplace entry metadata

There is no `skills/` subdirectory, no per-skill YAML, no individual trigger files.

---

## 2. The Four Principles (source inventory)

| # | Principle | Core Rule | Anti-pattern it addresses |
|---|-----------|-----------|---------------------------|
| P-1 | **Think Before Coding** | State assumptions explicitly. Present multiple interpretations instead of picking silently. Stop and name confusion. | LLM picks wrong interpretation, runs with it without checking |
| P-2 | **Simplicity First** | Minimum code that solves today's problem. No speculative features, abstractions, configurability, or impossible-case error handling. | 1000-line implementation where 100 would do; premature abstraction |
| P-3 | **Surgical Changes** | Touch only what the task requires. Never "improve" adjacent code, comments, or formatting. Clean up only orphans YOUR change created. | LLM modifies/removes code it doesn't understand as collateral |
| P-4 | **Goal-Driven Execution** | Transform every task to verifiable success criteria. State a plan with per-step verify checks. Loop until criteria are met, not until code looks done. | Vague "make it work" goals that require constant clarification; claiming done without proof |

---

## 3. META-COGNITION Assessment

Karpathy's insight is specifically about **how an LLM manages its own uncertainty and scope creep** — not domain knowledge. These are metacognitive operators, not domain skills:

- P-1 encodes *gradient-of-confidence*: when to stop and surface uncertainty vs. when to proceed.  
- P-2 encodes *scope discipline*: resist the pull to solve tomorrow's problem.  
- P-3 encodes *blast-radius control*: the minimal-footprint heuristic under partial understanding.  
- P-4 encodes *verification loop*: the loop-until-done-with-evidence contract.

**Key finding:** None of these are topic-routable. An operator doesn't type "use simplicity first" or "apply surgical changes" — these behaviours need to be ALWAYS-ON across every provider call. Keyword routing is the wrong delivery mechanism.

---

## 4. Skill-by-Skill Classification

The source has no discrete skill files. The four principles map to NEOTH constructs as follows:

### P-1 — Think Before Coding
**Classification: SKIP-DUPLICATE (partial) + ADOPT-AS-CORE (residual)**

Partial overlap: NEOTH's `verification_before_completion` skill
(`assets/skills/verification_before_completion/skill.yaml`) already covers the
"don't claim done without evidence" half. The assumption-surfacing half (present
interpretations, name confusion) is **not yet in NEOTH**.

CORE candidate: inject into the base system prompt injected for every provider
call — `src/providers/mod.rs` `build_provider_context()` or equivalent. Not a
routed skill; a NEOTH-wide behavioural guard.

Proposed target: `src/providers/context_guards.rs` — a module that assembles
the NEOTH-wide system-prompt preamble (distinct from per-skill prompts). If this
module doesn't exist yet, add 3–5 lines to the system_prompt construction in
`cli/chat.rs::run_chat_with`.

### P-2 — Simplicity First
**Classification: ADOPT-AS-CORE**

No existing NEOTH equivalent. This principle should never be keyword-gated — it
applies to every code-writing exchange regardless of topic. Belongs in the
base system-prompt preamble alongside P-1.

Proposed target: same `context_guards.rs` or `cli/chat.rs` system-prompt
injection point. One paragraph, not a separate skill file.

### P-3 — Surgical Changes
**Classification: ADOPT-AS-CORE**

No existing NEOTH equivalent. Same argument as P-2: always-on, not triggered by
operator phrasing. The "don't touch adjacent code" rule is especially valuable
for NEOTH because providers operate on multi-file contexts.

Proposed target: `src/providers/context_guards.rs` preamble paragraph.

### P-4 — Goal-Driven Execution
**Classification: SKIP-DUPLICATE**

Completely covered by `assets/skills/verification_before_completion/skill.yaml`.
That skill's system prompt already encodes:  
  - run a command, quote the output, reference file:line  
  - never say "should work" or "probably fine"  
  - the loop contract (not done until evidence is observed)

The EXAMPLES.md "Goal-Driven" examples are just the verification skill in
practice. No additional port needed.

---

## 5. Summary Table

| Principle | File | Decision | NEOTH target |
|-----------|------|----------|--------------|
| P-1 Think Before Coding | `CLAUDE.md §1` | ADOPT-AS-CORE (assumption-surfacing half only) | `src/providers/context_guards.rs` or system-prompt preamble in `cli/chat.rs` |
| P-2 Simplicity First | `CLAUDE.md §2` | ADOPT-AS-CORE | same preamble |
| P-3 Surgical Changes | `CLAUDE.md §3` | ADOPT-AS-CORE | same preamble |
| P-4 Goal-Driven Execution | `CLAUDE.md §4` | SKIP-DUPLICATE | covered by `assets/skills/verification_before_completion/skill.yaml` |
| Plugin metadata | `plugin.json`, `marketplace.json` | SKIP-OUT-OF-SCOPE | Claude Code marketplace packaging, not portable to NEOTH |
| Cursor rules | `.cursor/rules/` | SKIP-OUT-OF-SCOPE | Cursor IDE format only |
| EXAMPLES.md | annotated examples | SKIP — reference only | no code to port; use as test-case input for `neoth skill test` harness |

---

## 6. Proposed Implementation: `context_guards.rs`

**Path:** `SRC/neothd/src/providers/context_guards.rs`

Responsibility: returns a `&'static str` (or `String`) system-prompt preamble
injected once per provider call before skill-specific prompts. Keeps the
metacognitive rules separated from per-skill routing so they can be versioned
and tested independently.

Minimal surface:

```rust
/// Returns the NEOTH-wide metacognitive preamble injected into every
/// provider system prompt.  Assembled from:
///   - Karpathy P-1: surface assumptions, name confusion
///   - Karpathy P-2: minimal solution — no speculative features
///   - Karpathy P-3: surgical changes — touch only what the task requires
/// P-4 is covered by the verification_before_completion skill.
pub fn metacognitive_preamble() -> &'static str { ... }
```

Calling site: `cli/chat.rs::run_chat_with` — prepend to the system_prompt
string before passing to provider. Takes ~5 lines to wire.

**Not** a `SkillManifest` — no `trigger_keywords`, no `~/.neoth/skills/` entry.
Always injected regardless of routing outcome.

---

## 7. What NOT to Do

- Do not create three separate skill YAML files for P-1/P-2/P-3. These
  principles are not topic-routable; keyword triggers would fire too broadly
  (every message with "code" or "fix") or too narrowly (miss implicit coding
  tasks).
- Do not port `EXAMPLES.md` as test fixtures into the skill loader. The
  examples are human-readable teaching material, not machine-parseable skill
  invocations. Use them as inspiration for `neoth skill test` harness cases.
- Do not re-port P-4. `verification_before_completion/skill.yaml` is already
  stronger than the Karpathy prose version (it names specific evidence types:
  command, output line, file:line).

---

## 8. Open Items

| ID | Item | Effort |
|----|------|--------|
| KP-1 | Implement `context_guards.rs` + wire into `cli/chat.rs` | 0.5d |
| KP-2 | Add 3 unit tests: preamble non-empty, no duplicate injection when skill also fires, preamble appears before skill system_prompt in concatenated output | 0.5d |
| KP-3 | Add `EXAMPLES.md` cases as input corpus for `neoth skill test` harness (when harness ships) | deferred — depends on SK-3 |

**KP-1 + KP-2 are independent of any pending NEOTH work.** Can land in the
same PR as the next skill batch.
