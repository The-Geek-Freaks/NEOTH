# NEOTH — The Operator Journey

> DOC-02 — the seven stages of living with NEOTH, from the first five minutes to mastery.
> Every command below is a real `neoth` subcommand. For the exhaustive flag list see
> [cli-reference.md](./cli-reference.md); for first install see [getting-started.md](./getting-started.md).

NEOTH is a **self-contained sovereign-AI daemon**: one binary that runs on your hardware,
keeps an append-only audit log (the WAL) of everything it does, and routes your messages
through the LLM provider *you* choose — including a free local model. There is no cloud
account, no telemetry, and no per-token bill unless you deliberately pick a metered API
provider.

This guide is the map. You do not need to read it all at once — jump to the stage you are in.

---

## 1. First 5 minutes — "is this thing alive?"

**Goal:** a working chat on your own machine, zero accounts.

```bash
neoth init          # the wizard — pick a provider, autonomy level, optional channels
neoth chat "hello"  # your first turn
```

The wizard (`neoth init`) walks you through, in plain language, every choice that matters:

- **Provider.** `claude_cli` (uses your Claude subscription via the `claude` CLI — **no
  per-token billing**) is the recommended default. `local_qwen` runs a ~3 GB model entirely
  on your hardware (no key, no network, no bill). The metered API options (`anthropic_api`,
  `openai_api`, `gemini_api`, `cohere_api`) are clearly flagged **⚠ BILLED per-token** — pick
  one only if you specifically have an API key and no subscription.
- **Autonomy.** `Standard` is the safe default: NEOTH confirms before any paid call or
  destructive action. You can raise it later.
- **Channels** (optional). Telegram / Slack / Keet — skip them for now; add them in stage 5.

After the wizard, `neoth chat` is interactive. The first session prints a one-line
**"I remember N things from last time"** signal so you know the memory layer is live, and a
short first-tour banner.

> **💶 Two cost paths — know which one you're on.** NEOTH runs at one of two price points.
> **(A) Fully local:** `local_qwen` on your own hardware is **~0 EUR/month** — electricity
> only, no key, no network, no per-token bill, council or not. **(B) Subscription / metered:**
> `claude_cli` rides your existing Claude subscription (a **flat monthly floor**, no per-token
> charge); the `*_api` providers (`anthropic_api`, `openai_api`, `gemini_api`, `cohere_api`)
> bill **per token**. NEOTH never silently moves you from (A) to (B) — a metered call is
> flagged ⚠ in the wizard and confirmed before each turn at `Standard`/`Strict` autonomy.

> If anything looks off, `neoth doctor` runs a health sweep and `neoth status` shows what the
> daemon is doing right now.

---

## 2. Day 1 — "make it mine"

**Goal:** NEOTH knows who you are and answers in your register.

- **Tell it about you.** `neoth groundtruth` seeds durable facts (who you are, what you work
  on). These never decay — they are the bedrock the rest of memory leans on.
- **Pick a persona.** `neoth mode` / `neoth skill` expose response *registers* — `lowkey`
  (blunt, technical, no moralising), `deepdive`, `tutor`, `opsec`, and more. Set the one that
  matches how you actually want to be talked to.
- **Profile tuning.** `neoth profile knobs` shows the human-readable dials (verbosity,
  formality, ask-clarifying, trim-disclaimers) and how to change them. NEOTH also *passively*
  learns your style over time — see `neoth privacy audit` for exactly what it has inferred and
  where that data goes (spoiler: nowhere off-device unless you chose a cloud provider).
- **See the cost before you spend.** On a metered provider, NEOTH shows a euro estimate
  *before* each turn and confirms at `Standard`/`Strict` autonomy. `neoth cost` and
  `neoth usage` report what you have actually spent.

Everything NEOTH does is in the audit log from minute one: `neoth wal show` (and its
`--type` filter) is the source of truth.

---

## 3. Month 1–3 — "it starts to feel like an agent, not a chat box"

**Goal:** NEOTH is doing useful work between your messages.

- **Memory that pays off.** `neoth recall "<question>"` searches your full history across the
  hot / warm / cold / ground-truth tiers by relevance, not just keywords. Ask it
  "do you remember when…" mid-chat and it answers with the date + your own words.
- **Proactive nudges (opt-in).** Turn on `freedom.yaml::pattern_cron.enabled` and
  `proactive.enabled` and NEOTH watches your behaviour patterns — a long silence, the same
  question asked repeatedly, a topic you have suddenly focused on, a shift in your active
  hours — and surfaces a single "I noticed X, want me to do Y?" nudge (deduped to at most one
  per day per signal, delivered to your channel). `neoth proactive` manages the queue.
- **Reflection + dreaming.** A weekly reflection summarises what you worked on; the optional
  dreaming pipeline composes nightly themes into your Obsidian vault. Both are off by default
  (a proactive ping is intrusive) and explained in the wizard.
- **The coding buddy.** `neoth code "<build request>"` decomposes work across three
  hemispheres (a fast Left worker, a deep Right worker, a Cerebellum orchestrator) into a
  kanban board you watch live with `neoth kanban watch --follow`. NEOTH validates each write
  (`cargo check`), re-injects errors, and escalates Left→Right on a retry ceiling.

---

## 4. Power user — "bend it to my workflow"

**Goal:** automation, plugins, and tools wired to your stack.

- **Skills you author.** `neoth skills --create` is a YAML-only skill wizard — no Rust needed.
  NEOTH self-routes through your skill library (keyword match plus, if you configured an
  embedding provider, semantic re-rank).
- **WASM plugins, safely.** Drop a sandboxed `.wasm` plugin under `~/.neoth/plugins/<id>/`.
  Nothing runs until you `neoth plugin enable <id>` (default-inactive). Before that, gate it:
  - `neoth plugin verify <path>` checks the manifest **and** the operator integrity policy
    (SHA-256 pin / ed25519 author signature / revocation list) without instantiating —
    exit-non-zero on FAIL, so CI can gate on it.
  - `neoth plugin ledger [<id>]` shows, per plugin, exactly which capabilities it has
    exercised (memory reads via `recall_top`, writes via `emit_event`) — so a plugin that
    hammers your memory is visible, not silent.
- **n8n + cron.** NEOTH ships starter n8n workflows and a local cron; `neoth jobs` previews
  whether a job belongs in local cron or n8n.
- **Tools.** `neoth fetch` (SSRF-guarded URL fetch), `neoth search`, `neoth arxiv`,
  `neoth todo` (Todoist), `neoth paperless` (document OCR → Obsidian ground-truth),
  `neoth models` (auto-discovers new model versions so you never hand-patch a model id).
- **Mind the council multiplier** (ties back to the two cost paths in §1). A multi-provider
  council fans each turn out to `3^depth` provider calls (depth 1 = 3, depth 2 = 9, …).
  On **path (A) fully local** that is just more CPU/GPU time — still ~0 EUR. On a
  **subscription** (`claude_cli`) it stays a flat monthly floor: depth costs latency and
  rate-limit budget, not euros. On a **metered** provider (`*_api`) depth multiplies the
  per-token bill in lockstep. `freedom.yaml::inference.council_depth` is the dial, and
  `neoth cost` shows the running spend — deep councils on a metered provider are the one
  setting most worth watching.

---

## 5. Multi-device — "everywhere I am"

**Goal:** reach NEOTH from your phone, and share memory across your machines.

- **Channels.** `neoth connect` lists the messaging on-ramps (Telegram / Slack / WhatsApp /
  Keet) and walks you through wiring each. Inbound messages flow through the same
  prompt-injection sanitizer and consent gate as the CLI; a destructive command from a
  channel (raising autonomy, granting consent) is refused — those stay CLI + local-auth only.
- **Cluster.** `neoth cluster discover` finds your other NEOTH nodes over mDNS / Tailscale
  magic-DNS; `neoth cluster confirm` pairs them behind a consent gate, and
  `neoth cluster status` shows node health + the channel mesh. **Cross-device memory sync
  is not shipped yet:** matching the README's feature matrix, the private mesh today is
  **Partial** — discovery, pairing, the consent gate, and transport config work, but live
  shared memory across devices (tracked as SL-01) is still in progress. Until it lands each
  node keeps its own local memory; the cluster shares the channel mesh + node health, not
  recall.
- **Transport.** Optional Hysteria2 / Tailscale tunnels keep cluster + channel traffic
  private (`neoth hysteria`, the wizard's VPN step).

A metered provider bills per-token *per device*, so the local + subscription paths matter
more the more devices you run.

---

## 6. Failure recovery — "when something breaks"

**Goal:** diagnose, undo, and restore — without losing the audit trail.

- **Diagnose.** `neoth doctor` runs the full health sweep (HMAC key, WAL segment health,
  channel wiring, memory drift, provider posture, plugin integrity). `neoth status` shows live
  daemon state. `NEOTH_LOG=debug` surfaces the raw provider/WAL detail when you need it.
- **Undo.** `neoth undo` lists the last mutating WAL frames with the concrete command to
  reverse each; `neoth undo apply <n>` reverses a safe one (confirm-gated). The WAL is
  append-only, so undo writes a compensating action — it never edits history.
- **Security audit.** `neoth security audit` runs every gate at once. `neoth permissions audit`
  and `neoth refusal history` show the decision trail.
- **Backups + the HMAC key.** On Windows the WAL HMAC key is DPAPI-bound to your user +
  machine. `neoth security backup-hmac-key` writes a plaintext backup you store in a password
  manager; `neoth security rewrap-hmac-key --source <backup>` restores it on a new machine.
  The full playbook is `PLAN/RUNBOOK_dpapi_hmac_recovery.md`. `neoth backup` covers the rest.
- **Worst case.** `neoth verify` checks the audit chain's integrity; a corrupt config makes
  `neoth` bail loudly with the exact fix rather than running on a permissive default.

Nothing recovery-related is silent: every gate that blocks you, and every undo, lands in the
WAL where `neoth wal show` can find it.

---

## 7. Mastery — "I trust it, and I can prove what it did"

**Goal:** NEOTH is a teammate whose every action you can audit and steer.

- **Prove what happened.** The WAL is a tamper-evident, HMAC-chained log of every decision —
  every provider call, channel message, consent grant, plugin hostcall, memory write. Filter
  it by type, replay a council debate's structure with `neoth council replay <prompt_hash>`,
  and export windows for your own records.
- **Steer the brain.** `neoth council` tunes the multi-hemisphere debate (when it convenes,
  its budget, its dissent thresholds); `neoth hemispheres` binds a different provider to each
  hemisphere (e.g. a local model for sensitive profile extraction, a cloud model for the main
  reply). `neoth privacy audit` proves, per category, that nothing sensitive leaves the device
  unless you said so.
- **Self-development.** `neoth self-dev review` surfaces the adjustments NEOTH proposes for
  itself from your usage; you accept or decline — it never edits its own config behind your
  back. `neoth memory drift` flags beliefs fading toward the forget floor so you can reinforce
  them.
- **Make it yours, permanently.** ADRs (`neoth adr`), a tweakable theme, the full
  config-parity between CLI and GUI, and the model-version-agnostic provider layer mean NEOTH
  keeps working as models and your needs evolve — without you hand-patching anything.

By this stage the relationship is the point: NEOTH anticipates what you want, you can audit
every move it makes, and you own the whole thing — binary, memory, and audit trail — end to
end.

---

## The one-line map

| Stage | The command that defines it |
|-------|-----------------------------|
| First 5 min | `neoth init` → `neoth chat` |
| Day 1 | `neoth groundtruth`, `neoth mode`, `neoth profile knobs` |
| Month 1–3 | `neoth recall`, `neoth proactive`, `neoth code` |
| Power user | `neoth skills --create`, `neoth plugin verify`/`ledger`, `neoth jobs` |
| Multi-device | `neoth connect`, `neoth cluster` |
| Failure recovery | `neoth doctor`, `neoth undo`, `neoth security` |
| Mastery | `neoth council`, `neoth hemispheres`, `neoth wal show` |
