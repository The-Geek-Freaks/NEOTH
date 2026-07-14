---
title: "I built an AI that predicts its own collapse"
published: false
tags: rust, ai, opensource, localfirst
canonical_url: https://github.com/The-Geek-Freaks/NEOTH
cover_image: https://raw.githubusercontent.com/The-Geek-Freaks/NEOTH/main/.github/assets/neoth-social-preview.png
---

*Paste-ready for dev.to / Hashnode. Set `published: true` when you post. This
is the evergreen piece — it keeps pulling search traffic after the launch-day
spike fades.*

---

Agent systems fail in shapes you can name. A retry storm. An agent stuck in a
loop overnight. A context window quietly filling until the model starts
answering a different question than you asked. Semantic drift, where the
outputs collapse toward the same bland sentence. Most tooling lets you discover
these in the post-mortem — you go read the logs *after* the run went sideways.

I wanted the opposite: an assistant that watches its own cognition and warns me
**before** it goes off the rails. That turned into a whole project, and it
pulled a bunch of other decisions along with it. This is the story of
[NEOTH](https://github.com/The-Geek-Freaks/NEOTH) — a local-first personal AI
daemon in Rust — told through the three ideas I'd defend to a skeptic.

I'll say the awkward part up front: I'm an unknown author with no track record.
So I'm not going to ask you to trust me. Every claim below is a mechanism you
can run on your own machine and check. There's even a
[15-minute "verify it yourself" path](https://github.com/The-Geek-Freaks/NEOTH/blob/main/docs/evaluation.md)
in the repo that has you build from source and confirm each one with a command.

## 1. It predicts its own collapse

This is the part I'm proudest of and least certain about, so let's lead with
it.

NEOTH keeps an internal event stream (every tool call, model request, agent
dispatch, fallback, retry). A background observer scores every rolling window
of that stream with seven variables — coupling between tools and agents,
semantic convergence pressure, resource/context pressure, agent density,
throughput headroom, and two "buffer" variables for diversity and fallback
redundancy. Amplifiers over buffers gives a collapse score.

When the score crosses a threshold, you get a warning. The failure definitions
(agent loop, retry storm, context-limit failure, semantic degradation, …) are
deterministic functions of the event stream, and they're **pre-registered** —
frozen before data collection, so this isn't hindsight curve-fitting. The
predictor even self-calibrates: it tunes its threshold against its own hits and
misses and reports a Brier score, so the accuracy claim is *measurable* instead
of asserted.

```bash
neoth babel status     # threshold, calibration, latest scores
neoth babel windows    # the actual measurements, window by window
```

The model behind it comes from an open research framework called
[delta-kosmologie](https://github.com/The-Geek-Freaks/delta-kosmologie), which
asks a genuinely falsifiable question: can one scalar family predict collapse
across very different complex systems? NEOTH is its first production instrument.
If you opt in (it's off by default, consent- and autonomy-gated), your instance
can federate anonymised, content-free, cryptographically-signed measurements
into a shared pool that tests the theory. If the math doesn't hold, that's a
result too — and I'd rather find out before 1.0.

## 2. Memory with receipts

An assistant that remembers you is only trustworthy if you can see *what* it
remembered and prove it wasn't quietly changed.

In NEOTH, every sensitive action — a profile write, a provider call, a channel
send, a plugin capability use — lands in an append-only, HMAC-chained
write-ahead log. The SQLite views you query are just rebuildable projections
over that log; the log is the source of truth.

```bash
neoth verify              # recompute the whole chain — tamper and it fails
neoth wal show --last 20  # every sensitive frame, in order
neoth profile pending     # nothing enters your profile without approval
```

The trust anchor is a key on your disk, not a sentence in a README. That's the
difference between "we take privacy seriously" and something you can actually
falsify.

## 3. Fail-closed by default

The last idea is a posture, not a feature. Crossing a trust boundary — a cloud
call, extracting your profile to a cloud model, sending to a channel, raising
autonomy, a plugin using a capability — is **denied by default** until you
grant it once, on purpose. Both the grant and the refusal are logged.

```bash
neoth preset activate fully-local
neoth privacy audit --last 30d   # exactly what left the device — zero, locally
```

For plugins specifically, this is a real sandbox: NEOTH runs WASM plugins
(wasmtime) with fuel and memory caps and no ambient filesystem or network. An
activation approval binds the exact manifest, WASM bytes, and requested
permission level. Every linked hostcall checks that approval-derived level at
runtime; an over-level call is refused and written to the audit log as a `0xC7
PLUGIN_CAP_DENIED` frame — never silent.

The v1 guest contract is explicit: plugins export `neoth_abi_version() -> i32`
returning `1` and `neoth_run() -> i32`; the daemon rejects a missing or
mismatched ABI before execution and instantiates each call with the approved
manifest's validated fuel and memory caps.

## Why Rust, and who it's for

NEOTH is a single Rust daemon. That bought me a few things that matter for this
kind of project: a WASM host with hard resource caps, a sealed
`PermissionToken<T>` typestate that catches permission-level mismatches in
native Rust APIs, and the general property that the audit-critical paths don't
have a garbage collector or a runtime surprising me. The typestate is API
guidance, not the sandbox: WASM capability enforcement happens in the runtime
hostcall gate described above.

It's deliberately built for two audiences at once, which is the hard bet:

- **Normal users** get a GUI wizard that asks plain questions. No YAML required.
- **Operators** get the CLI, local models, the WAL, policies, a plugin sandbox,
  n8n automation, and a private mesh over Tailscale/Hysteria.

That "both at once" goal is the single thing I most want held accountable, and
the [comparison table](https://github.com/The-Geek-Freaks/NEOTH#comparison) is
honest about it: unfinished things are marked *Partial* or *Goal*, not *Yes*.

## Try it, then try to break it

```bash
git clone https://github.com/The-Geek-Freaks/NEOTH
cd NEOTH/SRC && cargo install --path neothd
neoth doctor
```

It's pre-1.0, dual-licensed MIT/Apache. The most valuable thing you can do is
run the [verify-it-yourself path](https://github.com/The-Geek-Freaks/NEOTH/blob/main/docs/evaluation.md)
and file an issue for any claim that doesn't reproduce — especially on the
collapse-prediction model, which is the part I'm least sure generalises.

Repo: **https://github.com/The-Geek-Freaks/NEOTH**
