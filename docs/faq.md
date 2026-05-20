# FAQ

---

## Does Neoth send my data to the cloud?

Partially, by design. Here is the breakdown:

**What goes to cloud:** Your messages to Neoth and Neoth's responses. These are sent to the LLM
provider you configure (Claude by default). This is unavoidable — the LLM has to see the prompt
to answer it.

**What stays local by default:** Profile extraction (learning about you from your conversations)
runs on a local model (Qwen3-4B) on your machine. Your raw conversation text is not transmitted
to a third party for this purpose. The cloud LLM only sees the profile *summary* (a few hundred
tokens of high-confidence facts), not the raw conversations.

**The opt-in:** If your local model is unavailable and you set `inference.allow_cloud_fallback: true`
in freedom.yaml, extraction falls back to the cloud. That flag is `false` by default. Without it,
extraction is simply skipped when local inference is down.

Run `neoth privacy audit --last 30d` to see exactly where your requests went.

---

## How do I delete my profile?

```
neoth profile redact --all
```

This removes all profile claims from the active index immediately. WAL audit events record
that a redaction happened (for integrity), but the actual claim values are zeroed out during
the next compaction pass. After that pass, the values are gone and unrecoverable.

To prevent a specific field from ever being re-learned:

```
neoth profile redact identity.location
```

The redaction persists across restarts. Future mentions of your location won't be stored.

---

## Can I use Neoth without a Claude/OpenAI/Google subscription?

For response generation: No, you need at least one cloud LLM. Claude, Codex, or Gemini via
their CLI tools (which use OAuth with a subscription, or API keys if you prefer pay-per-use).

For profile extraction (Phase 2+): No subscription needed once you have the local model set up.
`neoth model fetch qwen3-4b-int4` downloads it. Profile learning then costs only electricity.

---

## Does it work offline?

Partially. If you have the local model downloaded (Phase 2+), profile extraction, embedding
generation, and recall queries all work offline.

Response generation requires a cloud LLM and therefore requires internet access. There is no
offline response generation in the current roadmap.

WAL, profile storage, and skill loading are all local and work without internet.

---

## Why Rust?

Performance, reliability, and safety — without a garbage collector. The WAL needs predictable
latency: a GC pause in the middle of writing an event is a problem. Rust gives deterministic
memory management.

The single-binary deployment is also simpler in Rust than in most alternatives. No runtime to
install, no version conflicts, no interpreter.

Rust's type system is also doing real work here: the permission system for plugins is enforced
at compile time, not just at runtime. A plugin that declares `ReadOnly` cannot call vault APIs
that require `Execute` — the code won't compile.

---

## How is Neoth different from Letta, Mem0, openclaw?

**Letta (formerly MemGPT):** Focuses on long-term memory via a paging metaphor. Python-based.
Cloud-hosted option. Neoth is Rust, single-binary, self-hosted only, with an event log as the
source of truth rather than an LLM-managed memory database.

**Mem0:** A memory layer you add to existing LLM apps. SDK-focused, not an agent. Neoth is a
complete agent runtime with channels, skills, council, and profile learning built in.

**openclaw:** A WhatsApp/Telegram gateway to Claude, built on Node.js (the predecessor to Neoth's
channel adapter design). Neoth takes the openclaw channel concept, rewrites it in Rust, and adds
persistent WAL memory, profile learning, local inference, and the multi-LLM council.

The openclaw conversation binding model (`{channel, accountId, conversationId}`) maps to Neoth's
`human_uuid` — a stable UUID assigned per user that persists across channels when you merge them.

---

## License?

Apache 2.0. See `LICENSE` in the repo root. You can use Neoth commercially, fork it, and
modify it without restriction. Attribution is appreciated but not required.

---

## Multi-user support?

Yes, within a single deployment. Each Telegram/Slack/WhatsApp user gets a separate `human_uuid`.
Their conversation history, profile, and recall are isolated from other users.

The `allowed_chat_ids` (Telegram) and equivalent allowlists in other channels define who can
interact with your Neoth instance. You can add multiple users; each gets their own profile and
recall index.

Full multi-user management with separate permission levels per user is a Phase 4 topic.

---

## Mobile app?

No native mobile app. Neoth runs on your server and connects to Telegram/WhatsApp/Slack — you
use those apps' native mobile clients to talk to it. That is intentional: those apps already
handle push notifications, offline message queuing, and encryption in transit.

A dedicated Neoth mobile app is not on the current roadmap.

---

## Can I run multiple Neoth instances?

One instance per bot token. Running two Neoth processes with the same Telegram bot token causes
a conflict — the second instance will fail to acquire the lock and exit with a clear error.

You can run multiple instances with different bot tokens for different use cases, pointing at
different WAL directories via `NEOTH_HOME` or `storage.wal_dir` in freedom.yaml.
