# Runbook — OMI (passive transcript ingest) privacy

OMI ingest (OM-01) lets NEOTH learn from a **self-hosted** [OMI](https://omi.me)
backend — the wearable that transcribes your day. It is the most sensitive power
surface NEOTH has (it can mirror everyday conversation), so it ships **off by
default** and is gated, audited, and local-only. This runbook answers the exact
questions an operator should ask before turning it on.

---

## TL;DR

| Question | Answer |
|---|---|
| Is it on by default? | **No.** `omi.enabled: false`. Nothing is ingested until you opt in. |
| Can it talk to a cloud OMI? | **No.** The daemon **refuses to start** (SC-14) if `omi.enabled` is on with a non-local endpoint (e.g. `api.omi.me`). |
| Are raw transcripts stored by NEOTH? | **No.** NEOTH never persists the raw transcript. |
| What leaves the machine? | **Nothing.** The local OMI backend → NEOTH is loopback; nothing is sent outward. |

---

## Where do raw transcripts live?

In **your self-hosted OMI backend**, not in NEOTH. The ingest task
(`daemon/omi_ingest_task.rs`) polls `GET {omi.endpoint}/v1/memories`, and for
each item it:

1. Runs it through the **StreamBatchSanitizer** (SC-18). A quarantined chunk
   (prompt-injection / oversize) is **dropped** — nothing is promoted.
2. Only items **at/above `omi.confidence_threshold`** (default `0.75`) are
   promoted to ground-truth (`idx_groundtruth`, tagged **`Source::Omi`**).
3. Action items (EN/DE markers) become kanban tasks.

So the only NEOTH-side persistence is: the **promoted ground-truth statement**
(text — this is the useful long-term memory you opted into), the **kanban action
items** (text), and the **audit frame** (hash only — see next).

## What is only hashed?

The **`0x9C OMI_ACTION_PROMOTED`** WAL audit frame is **metadata-only**: it
records `{statement_text_hash, confidence, ts}` — the **xxh3-64 hash** of the
promoted statement, never the statement itself. So the durable audit trail proves
*that* a promotion happened (and lets you correlate) **without** the WAL becoming
a transcript of your conversations.

The ground-truth + kanban rows DO hold the actual text — because that is the
memory you asked NEOTH to keep. Delete it as below.

## How do I delete OMI ground-truth?

OMI-promoted ground-truth carries the **`Source::Omi`** tag (`"omi"`), so it is
distinguishable from other memory. Erase a topic with:

```
neoth memory forget "<topic>"
```

This removes matching entries across the memory tiers. (Tip: inspect what is
stored first with `neoth memory --output json`; the source label tells you which
rows came from OMI.)

## How do I disable OMI completely?

Set it off in `freedom.yaml` (this is the default):

```yaml
omi:
  enabled: false
```

The daemon picks the change up on its next start / reload. With it off, **no
polling happens, nothing is ingested**, and the read-only diagnostics are inert.

## How is the local-only endpoint enforced?

By a **hard startup gate (SC-14)** in `cli/serve.rs`: if `omi.enabled` is `true`
the daemon validates `omi.endpoint` with `installers::omi::is_local_endpoint`. A
non-local address (`api.omi.me`, any public host) makes the daemon **refuse to
start** with:

> `SC-14 OMI hard rule: <reason>. Set freedom.yaml::omi.endpoint to a local
> address (e.g. http://127.0.0.1:8002) or disable it (omi.enabled: false).`

This is not advisory — a daemon **cannot run** OMI ingest against a cloud
backend. Your transcripts cannot leave the machine through this path.

## How do I confirm no cloud endpoint is active?

```
neoth security safe-mode
```

Look for the **`omi_ingest`** rail:

- **`[ENGAGED]  omi_ingest   off — no passive transcript ingest`** → it is off.
- **`[RELAXED]  omi_ingest   ENABLED — polling <endpoint> (LOCAL-only; SC-14
  refuses a cloud endpoint at startup)`** → it is on; the rail prints the exact
  endpoint so you can see it is a `127.0.0.1` / `localhost` address.

If the daemon is running, the SC-14 gate has **already** confirmed the endpoint
is local (the daemon would have refused to start otherwise).

---

## Pre-flight checklist before enabling OMI

- [ ] `omi.endpoint` is a loopback/self-hosted address you control.
- [ ] You have a retention plan (OMI ground-truth is real long-term memory).
- [ ] You know `neoth memory forget "<topic>"` to erase, and `neoth security
      safe-mode` to confirm state.
- [ ] You accept that promoted statements are stored as text (the audit is
      hash-only, but the memory is not — that is the point of opting in).
