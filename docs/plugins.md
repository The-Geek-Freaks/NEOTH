# Plugins and Skills

Neoth is extensible in two ways: Skills (data) and Plugins (code).

---

## Skills vs Plugins

| | Skill | Plugin |
|---|-------|--------|
| What it is | A YAML file + optional Markdown templates | Compiled Rust code or a WASM module |
| What it does | Injects context into the LLM's prompt | Runs code at specific lifecycle hooks |
| How it loads | Hot-reload via `neoth reload-skills` or SIGHUP | Restart required (Phase 1) or WASM (Phase 2) |
| Who writes them | Anyone — no Rust required | Rust or WASM developers |
| Risk | Low — data only, no execution | Higher — runs arbitrary code within limits |

---

## Skills

A skill is a YAML file at `~/.neoth/skills/<skill_id>/skill.yaml` with an optional
Markdown template.

### Skill format

```yaml
skill_id: my_context         # Unique identifier, snake_case
version: 1.0.0
description: Context about my work environment

mount:
  target: block_b            # block_b = always-on context; block_d = per-request
                             # block_b for things Neoth always needs to know
                             # block_d for things relevant to specific queries

trigger:
  mode: keyword              # always | keyword | explicit
  keywords: [kubernetes, k8s, cluster, helm]
  hemisphere_filter: left    # left | right | both

content:
  template_file: templates/k8s_context.md
  max_tokens: 400

locality:
  sandboxed: true            # Must be true for user-created skills
```

The template file is plain Markdown. Neoth renders it and injects it into the LLM prompt
when the trigger fires.

### Installing a skill

```
neoth skill install ./my-skill-dir/
neoth reload-skills
```

Or manually copy to `~/.neoth/skills/<skill_id>/` and reload.

### Managing skills

```
neoth skill list
neoth skill enable my_context
neoth skill disable my_context
neoth skill inspect my_context    # show rendered template + token count
```

### Built-in skills (shipped at Day 23)

| Skill | When it fires | What it does |
|-------|--------------|-------------|
| `neoth_identity` | Always, Left Hemisphere | Core identity and voice from soul.md |
| `server_safety` | Keywords: reboot, shutdown, server IPs | Server safety constraints |
| `security_research` | Keywords: pentest, exploit, cve, payload | Security research context |
| `obsidian_context` | Keywords: vault, note, obsidian | Note-taking vault summary |
| `neoth_providers` | Keywords: provider, claude, gemini, llm | Provider cascade info |
| `neoth_tools` | Keywords: tool, pipeline, wal, recall | Tool registry for meta-queries |
| `freedom_scope` | Always, any hemisphere | Active permission scope summary |

---

## Plugins

Plugins run code at specific points in Neoth's lifecycle — before a recall query, after an
LLM response, on council verdicts, etc.

### Phase 1 — Compiled-in plugins

In v0.1.0 and early v0.x, plugins ship compiled into the Neoth binary via Rust's `inventory`
crate. There are no loadable `.so` or `.dll` files — the single-binary constraint is preserved.

To add a compiled-in plugin, you write a Rust crate, implement the relevant hook trait, register
it with `inventory::submit!()`, and rebuild Neoth. Plugins ship with the binary; operators choose
which to enable via config.

### Phase 2 — WASM plugins

From Phase 2 onwards, Neoth supports plugins as `.wasm` modules loaded at startup via `wasmtime`.
WASM plugins can be enabled and disabled without recompiling.

WASM plugin directory: `~/.neoth/plugins/<plugin_id>/`

Enable a WASM plugin in config:

```
neoth plugin enable my_plugin
neoth stop && neoth start
```

### Available hook points

| Hook | When it runs | What a plugin can do |
|------|-------------|---------------------|
| `pre_recall` | Before searching past conversations | Filter or expand the search parameters |
| `post_recall` | After recall results are assembled | Add additional context to results |
| `pre_provider_call` | Before sending to an LLM | Append context (read-only extension) |
| `post_provider_call` | After LLM responds | Inspect the response (audit, metrics) |
| `on_tool_invocation` | Before any tool runs | Audit log |
| `on_refusal` | When Neoth declines a request | Notification |
| `on_council_verdict` | After council debate completes | Notification |
| `on_wal_event` | After a WAL event is written | Metrics collection |

### Plugin permissions

Every plugin declares a permission level in its manifest. Neoth enforces this at compile time —
a plugin that declares `ReadOnly` cannot call APIs that require `Execute`, regardless of what its
code attempts. This is enforced by Rust's type system, not just a runtime check.

| Level | What it allows |
|-------|---------------|
| `None` | Receive hook context, return Continue/Abort |
| `ReadOnly` | Read past conversations and profile summary |
| `Write` | Write new data to WAL |
| `Execute` | Read secrets from vault |
| `Dangerous` | Execute shell commands (must be explicitly granted in freedom.yaml) |

Permission upgrades require a `FreedomGrant` — a move-only value issued by the permission
manager after reading freedom.yaml. You cannot forge one or reuse one.

### Plugin security model (simplified)

Vault reads (API keys, secrets) require `Execute` permission. If a plugin's manifest says
`ReadOnly`, it cannot read vault secrets — the code won't compile with that token level.

WASM plugins additionally: no filesystem access, no network access, no ambient capabilities.
They can only call explicitly allowed functions (log, recall read, embed, timestamp). Each
call is fuel-limited and time-limited.

Every vault access generates an audit event in the WAL: which plugin, which key path, when.
The secret value itself is never logged.

### Managing plugins

```
neoth plugin list
neoth plugin enable <id>
neoth plugin disable <id>
neoth plugin inspect <id>       # show manifest + hook registrations
```

Phase 1 plugins: after enable/disable, rebuild and restart are required.
Phase 2 WASM plugins: after enable/disable, restart only (`neoth stop && neoth start`).
