# E-22 — Skill hot-reload scope

**SPEC ref:** `SPEC_skill_plugin_system.md` §13 Q1.
**Decision required:** when a skill file changes on disk while the
daemon is running, what should hot-reload cover?

## The four scope options

### (1) No hot-reload — operator restarts the daemon

`neoth reload` requires `neoth serve` restart. Today's behaviour.

| Pros | Cons |
| ---- | ---- |
| Zero new code paths; existing reload flow handles config | Operator workflow interrupted on every skill edit |
| No partial-state hazards (skill router cache + LRU + router-stage state stay consistent) | Slow iteration for skill authors |

### (2) Hot-reload skill metadata only

`SkillFrontmatter` / `description` / `keywords` reload; the
`SkillBody` (prompts, handlers) stays as it was at daemon start.
Operator needs daemon restart to pick up body changes.

| Pros | Cons |
| ---- | ---- |
| Router can pick up new keywords without restart | Confusing — body changes silently no-op until restart |
| Cheap: just re-parse the frontmatter section | Operator sees "I changed the prompt and nothing changed" → bug report |

### (3) Hot-reload everything except active invocations

Both metadata and body reload on file change. Skills currently
mid-invocation (e.g. waiting on a provider response) finish on the
old version; the next invocation picks up the new version.

| Pros | Cons |
| ---- | ---- |
| Operator iteration loop matches edit-save-rerun expectations | Mid-invocation state visible — operator sees "two versions ran for one chat" if the timing is unlucky |
| Active invocations atomic (no spliced-version chaos) | Requires per-invocation version pinning in the router |

### (4) Hot-reload everything + abort active invocations

File change forces every in-flight skill invocation to abort with
a clean "skill reloaded" error. Next invocation runs the new
version.

| Pros | Cons |
| ---- | ---- |
| Fully consistent — only one version of a skill ever runs | Operator chat in progress gets cancelled; high surprise factor |
| Useful for skill-development mode | Production-grade NEOTH should NEVER cancel in-flight chats |

## My recommendation

**Pick (3) — everything reloads, active invocations finish on old
version.**

Rationale:
1. (1) is the operator-friction extreme; (4) is the consistency
   extreme. (3) is the standard "watch mode" semantics every modern
   dev tool uses (vite, cargo watch, esbuild — all option-3).
2. (2) is the "uncanny valley" — it pretends to hot-reload but
   doesn't actually update behaviour, which generates bug reports.
3. Per-invocation version pinning is a small bookkeeping cost
   (clone an `Arc<SkillBody>` at invocation start) — much cheaper
   than the operator-friction of (1).

## What ships when Alex picks one

- **(1) verdict** → close as "no work; existing reload flow
  documented".
- **(2) verdict** → ship `SkillFrontmatter::reload_from_disk()` +
  `notify` crate wire-up + operator-facing warning when body
  differs from on-disk.
- **(3) verdict** → ship the `Arc<SkillBody>` clone-at-invocation
  pattern + `notify` watcher that swaps the registry's `Arc`
  pointer atomically. Tests: pin one invocation grabs version A,
  another invocation after swap grabs version B.
- **(4) verdict** → (3) + a CancellationToken plumbed through
  every skill invocation + an operator-facing "skill reloaded;
  retry your last message" message.

## What stays unchanged regardless

- `neoth reload` CLI surface still works for config-only reloads.
- Skill installation (`neoth skill install <path>`) still copies
  into `~/.neoth/skills/` + emits the matching WAL event.
- The skill router's keyword index rebuild stays incremental
  regardless of which hot-reload scope wins.
