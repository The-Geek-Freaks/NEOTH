# NEOTH Launch Kit

Copy-paste-ready promotion copy + a placement playbook. Every channel below
that needs an interactive login (HN, Reddit, X, Product Hunt, Lobsters) can't
be automated from this environment — paste and post. Everything with an API/PR
path (GitHub release, Discussions, awesome-list PRs) is a one-liner your agent
can fire once you allow the `gh release`/`gh pr`/`gh api` permission.

Positioning (use everywhere, keep it consistent):
> **NEOTH — a local-first personal AI daemon in Rust. It remembers with
> receipts, fails closed by default, and predicts its own collapse.**

Lead with credibility (unknown author → mechanisms, not adjectives): the
15-minute skeptic path (`docs/evaluation.md`), the HMAC-chained audit
(`neoth verify`), the honest Partial/Goal comparison, MIT/Apache dual license,
and the Babel-Index research angle.

---

## Posting order (the playbook)

1. **Day 0, publish the GitHub Release** (`v1.0.0-beta.2`) — gives every link
   below a stable anchor and shows up in GitHub's release feed.
2. **Day 0, GitHub Discussions → Announcements**: post the "NEOTH is public"
   note (below), pin it.
3. **Day 1, Show HN** (Tue-Thu, ~15:00 UTC is the sweet spot). One shot — don't
   waste it. Reply to every comment for the first 4 hours.
4. **Day 1-2, r/rust** (Rust angle) and **r/LocalLLaMA** (local-AI angle) —
   different copy, don't cross-post identically.
5. **Day 2, r/selfhosted** (self-host angle) + **Lobsters** (`rust`, `ai`).
6. **Day 2, X/Twitter thread** + tag relevant accounts.
7. **Week 1, awesome-list PRs** (backlinks = durable SEO): awesome-rust,
   awesome-selfhosted, awesome-ai-agents, awesome-local-ai.
8. **Week 1, dev.to / hashnode long-form** ("How I built an AI that predicts
   its own collapse") — evergreen search traffic.

Rules: never post the same text to two subreddits. Never lead with "I built".
Lead with the problem. Answer skeptics with a command they can run, not a claim.

---

## Show HN

**Title:**
`Show HN: NEOTH – a local-first personal AI in Rust that predicts its own collapse`

**Body:**
```
NEOTH is a personal AI daemon that runs on your machine. Three things make it
different from the current crop of personal-AI projects, and all three are
verifiable rather than claimed:

1. Memory with receipts. Every sensitive action (profile write, provider call,
   channel send) lands in an append-only, HMAC-chained WAL. `neoth verify`
   recomputes the chain; edit one frame and it fails. The trust anchor is a key
   on your disk, not a promise in a README.

2. Fail-closed by default. Cloud calls, profile-to-cloud extraction, and
   channel egress are denied until you grant them once, on purpose. Both the
   grant and the refusal are logged.

3. It predicts its own collapse. NEOTH scores its own event stream for
   degradation (retry storms, agent loops, context death spirals) with seven
   variables per rolling window, warns before the failure, and self-calibrates
   with a reported Brier score. This is built on an open research framework
   (delta-kosmologie) and is, as far as I know, not in any other assistant.

I'm an unknown author with no track record, so I wrote the repo to be checked,
not trusted: there's a 15-minute "verify it yourself" path that has you build
from source and confirm each claim with a command.

It's pre-1.0 (Rust, MIT/Apache). The comparison table marks unfinished things
Partial/Goal, not Yes. Honest feedback wanted — especially on the collapse-
prediction idea, which is the part I'm least sure generalises.

Repo: https://github.com/The-Geek-Freaks/NEOTH
Verify-it-yourself: https://github.com/The-Geek-Freaks/NEOTH/blob/main/docs/evaluation.md
```

First comment (post yourself, seeds the discussion):
```
Happy to answer anything. The part I'd most like torn apart: the Babel-Index
collapse score. The seven-variable model and the pre-registered failure labels
are in docs/babel-index.md — if the math doesn't hold, I want to know before
1.0.
```

---

## r/rust

**Title:** `NEOTH: a local-first personal AI daemon in Rust — HMAC-chained audit, WASM plugin sandbox, and a self-diagnosis loop`

**Body:**
```
Sharing a Rust project I've been building: NEOTH, a personal AI daemon that's
local-first and audit-first.

Rust-relevant bits you might find interesting:
- Append-only, HMAC-chained WAL as the source of truth; SQLite views are
  rebuildable projections over it. `neoth verify` recomputes the chain.
- A WASM plugin host (wasmtime) with a capability sandbox: a plugin's manifest
  declares the hostcalls it needs, and an over-level call is refused at runtime
  and audited (0xC7 frame). Fuel + memory caps.
- A sealed typestate PermissionToken<T> in the plugin SDK for compile-time
  capability enforcement.
- Provider layer with no hardcoded model whitelist — any model id passes
  through, catalog discovered at runtime.

It's dual MIT/Apache, pre-1.0. Feature-gated wasm host on native targets.
Would genuinely value review of the WAL and the capability-token design.

https://github.com/The-Geek-Freaks/NEOTH
```

---

## r/LocalLLaMA

**Title:** `Built a local-first personal AI that runs on your own machine, keeps an auditable memory, and warns you before it goes off the rails`

**Body:**
```
NEOTH is a local-first personal AI daemon. Local-only mode is a first-class
path (one preset, verified by an audit command, not a buried toggle), and it
routes to local models (Qwen, and a recurrent local reasoner called Ouro) as
first-class providers alongside cloud.

The bit this crowd might care about most: it watches its own event stream and
scores it for collapse — retry storms, agent loops, context death spirals —
seven variables per rolling window, warns before failure, self-calibrates with
a Brier score. If you run agents unattended, "the agent looped overnight"
becomes a warning you got, not a log you dig up.

Memory is five tiers + your Obsidian/Paperless vault, every sensitive action is
in an HMAC-chained audit log you can verify yourself, and cloud calls are
fail-closed by default.

Pre-1.0, Rust, MIT/Apache. Verify-it-yourself path in the repo:
https://github.com/The-Geek-Freaks/NEOTH
```

---

## r/selfhosted

**Title:** `NEOTH: self-hosted personal AI with an audit log you can actually verify (fail-closed, local-first, Rust)`

**Body:**
```
If you self-host because you want the data boundary on your side, NEOTH is
built around that: local-first, fail-closed by default, and every sensitive
action lands in an append-only HMAC-chained log you can verify with one command
(`neoth verify`). `neoth privacy audit --last 30d` shows exactly what left the
device — in fully-local mode that's zero.

It's a personal AI buddy (GUI wizard, no YAML required) that also does serious
operator stuff: local models, WASM plugin sandbox, n8n automation, private mesh
over Tailscale/Hysteria, channels (Telegram/WhatsApp/Slack/Discord).

Single Rust daemon, MIT/Apache, pre-1.0.
https://github.com/The-Geek-Freaks/NEOTH
```

---

## Lobsters (tags: rust, ai)

`NEOTH: local-first personal AI in Rust with a verifiable audit log and a self-collapse predictor`

(Link the repo; Lobsters prefers a link post with a short authored comment
mirroring the Show HN first-comment above.)

---

## X / Twitter thread

```
1/ I built NEOTH: a personal AI that runs on your machine, remembers with
receipts, fails closed by default, and predicts its own collapse.

Local-first. Rust. MIT/Apache. And written to be verified, not trusted 🧵

2/ "Remembers with receipts" = every sensitive action lands in an append-only,
HMAC-chained log. `neoth verify` recomputes the chain. Tamper with one frame
and it fails. The trust anchor is a key on YOUR disk.

3/ "Fails closed" = cloud calls, profile-to-cloud extraction, channel egress
are denied until you grant them once, on purpose. Both grant and refusal are
logged. `neoth privacy audit --last 30d` shows what actually left the device.

4/ "Predicts its own collapse" = it scores its own event stream (retry storms,
agent loops, context death spirals) — 7 variables/window, warns before failure,
self-calibrates with a Brier score. Built on an open research framework.

5/ I'm a nobody with no track record. So there's a 15-minute path that has you
build from source and confirm every claim with a command. Don't trust me —
check it.

github.com/The-Geek-Freaks/NEOTH
```

---

## GitHub Discussions → Announcements (post + pin)

**Title:** `NEOTH is public — start here`

**Body:**
```
NEOTH is a local-first personal AI daemon in Rust: one memory, three brain
paths, five memory tiers + your vault, and a signed audit log for every
sensitive action.

New here? Three good first steps:
- Read the 15-minute verify-it-yourself path: docs/evaluation.md
- Skim why it holds up: the README "Why it holds up" section
- Try it: the source bootstrap in the README, then `neoth doctor`

This is the release where outside eyes matter most. What I'd most value:
- Tear apart the Babel-Index collapse model (docs/babel-index.md)
- Tell me where the DAU/pro split fails for you
- File any claim that doesn't reproduce — that's the highest-value issue here

Questions in Q&A, ideas in Ideas, show what you built in Show and tell.
```

---

## dev.to / Hashnode (evergreen, long-form)

**Title:** `I built an AI that predicts its own collapse`
Angle: the collapse-prediction idea (delta-kosmologie / Babel-Index) as the
hook, then the mechanisms (WAL audit, fail-closed, WASM sandbox) as proof the
project is serious. Link back to the repo and the evaluation page. This is the
piece that keeps pulling search traffic after the launch spike fades.

---

## awesome-list PRs (durable backlink SEO — do these properly, one at a time)

Target lists (only submit where NEOTH genuinely fits; follow each list's
CONTRIBUTING format, alphabetical order, one-line entry):
- rust-unofficial/awesome-rust → "Applications / Artificial Intelligence"
- awesome-selfhosted/awesome-selfhosted → "Automation" or "Personal AI"
- e2b-dev/awesome-ai-agents
- janhq/awesome-local-ai or vince-lam/awesome-local-llms

Entry line (adapt per list format):
```
[NEOTH](https://github.com/The-Geek-Freaks/NEOTH) — Local-first personal AI daemon in Rust: verifiable HMAC-chained audit log, fail-closed privacy, WASM plugin sandbox, and runtime self-diagnosis. `MIT OR Apache-2.0`
```
Note: some lists require a minimum star count or reject pre-1.0 — read the
rules first; a rejected PR for looking spammy hurts more than it helps.

---

## SEO notes (on-repo, mostly done)

- Topics set for search intent (jarvis, personal-assistant, self-hosted, rag,
  ai-memory, local-ai, …). ✅
- About description names the Babel-Index USP. ✅
- Social preview: render `.github/assets/neoth-social-preview.svg` to 1280x640
  PNG and upload via Settings → General → Social preview (no API; manual).
- After the docs settle, refresh DeepWiki so the indexed answer is current.
- The build badge is grey because CI runs are stuck queued — a green CI badge
  is a real credibility signal; fix Actions settings before the Show HN.
```
