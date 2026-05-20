# Security Finding Verification — 2026-05-20

Auditor: Security Auditor Agent (claude-sonnet-4-6)
Scope: read-only, three targeted findings from prior audit report.

---

## Finding 1 — WASM memory cap not enforced

**Verdict: CONFIRMED**

Evidence:

- `SRC/neothd/src/wasm_plugin/engine.rs:51` declares `pub const DEFAULT_MEMORY_LIMIT_BYTES: usize = 64 * 1024 * 1024` and the doc comment at line 50 says "Operators can override per-plugin via `freedom.yaml::plugins.<id>.memory_limit_bytes`".
- `new_store()` at lines 180–187 creates the `Store`, calls `store.set_fuel(budget)`, and returns. There is no `Store::limiter()` call, no `ResourceLimiter` impl, no `StoreLimitsBuilder` anywhere in `SRC/neothd/src/`.
- `SRC/neothd/src/wasm_plugin/manifest.rs:108` defines `pub memory_limit_bytes: Option<usize>` and line 157 validates it against `MAX_MEMORY_LIMIT_BYTES`, but the value is never forwarded to the wasmtime `Store` as a resource limiter.
- The test `default_memory_limit_is_64_mib` (engine.rs:225) only asserts the constant's numeric value — it does not instantiate a module and verify memory growth is actually trapped.

Impact: A malicious plugin calls `memory.grow` in a loop. Wasmtime grants every page because no `ResourceLimiter` is registered. The daemon's RSS grows until OOM kill. The 64 MiB figure in the constant is documentation, not enforcement.

**Concrete fix — add to `engine.rs`:**

```rust
use wasmtime::ResourceLimiter;

struct MemLimiter {
    cap: usize,
}

impl ResourceLimiter for MemLimiter {
    fn memory_growing(&mut self, current: usize, desired: usize, _maximum: Option<usize>)
        -> anyhow::Result<bool>
    {
        Ok(desired <= self.cap)
    }
    fn table_growing(&mut self, _current: u32, _desired: u32, _maximum: Option<u32>)
        -> anyhow::Result<bool>
    {
        Ok(true)
    }
}
```

In `PluginStoreState` add `pub memory_limit_bytes: usize` (default `DEFAULT_MEMORY_LIMIT_BYTES`).

In `new_store()`, after `store.set_fuel(budget)`:

```rust
let cap = state.memory_limit_bytes;
store.limiter(move |_| &mut MemLimiter { cap } as &mut dyn ResourceLimiter);
```

The limiter is evaluated on every `memory.grow` instruction — exceeding `cap` returns `false`, which traps the instruction inside the sandbox without touching host memory.

Also wire `manifest.memory_limit_bytes` through to `PluginStoreState` at plugin-load time so the per-plugin override actually takes effect.

---

## Finding 2 — Webhook listener no concurrency backpressure

**Verdict: REFUTED**

Evidence from `SRC/neothd/src/channels/webhook_listener.rs`:

- The claim is DoS via request flood. The threat vector for a local-only listener is meaningful only from processes on the same host.
- Three mitigations are already in place:
  1. **Body cap enforced before buffering** (lines 300–309): `Limited::new(req.into_body(), MAX_BODY_BYTES)` stops reading at 1 MiB and returns an error. The comment at line 291–299 explicitly documents the prior unbounded-buffer bug and its fix (Agent 2 audit 2026-05-16).
  2. **127.0.0.1 binding only** (documented lines 9–14): the attack surface is confined to local processes. An internet-facing DDoS is not possible without a misconfigured reverse proxy that forwards to this port.
  3. **HTTP/1.1 only with short connection lifetime** (lines 17–19): no keepalive pipelining, no multiplexing. Each connection is accept→parse→route→respond→drop.
- A regression test `body_over_cap_is_rejected_without_buffering_whole_payload` (line 529) verifies the cap fires without OOM.

The finding is correct that there is no `tokio::sync::Semaphore` bounding simultaneous connections. However, for a localhost-only 127.0.0.1 listener in a single-operator daemon, the signature-verify cost per connection is HMAC-SHA256 of a body already capped at 1 MiB. The practical attack requires local code execution — at that point the attacker has broader primitives than flooding a loopback port.

If a Semaphore is desired anyway (defence-in-depth), the correct insertion point is `serve()` at line 92, between `listener.accept()` (line 114) and `tokio::spawn` (line 124):

```rust
let sem = Arc::new(tokio::sync::Semaphore::new(64)); // 64 concurrent
// inside the accept arm:
let permit = Arc::clone(&sem).acquire_owned().await?;
tokio::spawn(async move {
    let _permit = permit; // dropped when connection closes
    http1::Builder::new().serve_connection(io, svc).await.ok();
});
```

This is a hardening recommendation, not a confirmed vulnerability.

---

## Finding 3 — MCP allowlist not secure-by-default

**Verdict: CONFIRMED (P1, no P0)**

Evidence:

- `SRC/neothd/src/mcp/config.rs:57`: `pub allow_tools: Option<Vec<String>>` with `#[serde(default)]` — default is `None`.
- `SRC/neothd/src/mcp/gate.rs:183–198`: the gate reads `if let Some(list) = cfg.allow_tools.as_ref()`. When `allow_tools` is `None` the entire allowlist check is skipped and all tools from `tools/list` are reachable. The comment at line 183 documents this explicitly: "None = trust catalogue (legacy)".
- All test fixtures in config.rs (lines 258, 267, 289, 311, 331, 384) and client.rs (line 314) construct `McpServerConfig` with `allow_tools: None`.
- No `doctor` / startup validator hard-fails or warns on missing allowlist.

The claim is accurate. A compromised MCP server that injects new tools via `tools/list` faces no allowlist barrier when the operator hasn't set `allow_tools`. The operator must opt-in to security here — the safe default would be deny-all-unlisted.

Severity is P1, not P0. The attack requires a compromised MCP server subprocess (local process, operator-launched). It does not enable unauthenticated remote exploitation.

**Concrete fix — two parts:**

1. Change the semantic of `None` to deny-all for new servers. This is a breaking change for existing configs; use a migration sentinel instead:

In `McpServerConfig`, add:

```rust
/// When `true`, the operator has explicitly reviewed and accepted
/// the full tool catalogue (opt-out of allowlist). Default `false`
/// forces operators to either set `allow_tools` or set
/// `trust_all_tools: true` consciously.
#[serde(default)]
pub trust_all_tools: bool,
```

In `gate.rs` Layer 1:

```rust
match cfg.allow_tools.as_ref() {
    Some(list) => {
        if !list.iter().any(|t| t == tool) {
            // ... reject
        }
    }
    None if !cfg.trust_all_tools => {
        // No allowlist AND operator hasn't set trust_all_tools → reject.
        return Err(GateError::NotInAllowlist { ... });
    }
    None => {} // trust_all_tools = true → legacy pass-through
}
```

2. Add a `doctor` check in `SRC/neothd/src/cli/doctor.rs` (or equivalent startup validator):

```rust
for server in mcp_servers.enabled() {
    if server.allow_tools.is_none() && !server.trust_all_tools {
        warn!(
            server = %server.id,
            "MCP server has no allow_tools list and trust_all_tools is not set — \
             all tools from tools/list will be reachable after next release"
        );
    }
}
```

Emit as a `WARN` now, upgrade to a hard error in the next breaking-change release.

---

## Summary

| # | Finding | Verdict | Severity |
|---|---------|---------|----------|
| 1 | WASM memory cap unenforced (`ResourceLimiter` missing) | CONFIRMED | P0 |
| 2 | Webhook no concurrency backpressure | REFUTED (body cap already enforced; localhost-only) | — |
| 3 | MCP allowlist `None` = allow-all by default | CONFIRMED | P1 |

Overall risk: **Medium**. Finding 1 requires a loaded plugin to exploit — an attacker must first get a malicious `.wasm` past the plugin-load path. Finding 3 requires a compromised local MCP server subprocess. Neither is remotely exploitable without prior access. Both should be fixed before multi-operator or public-release builds.
