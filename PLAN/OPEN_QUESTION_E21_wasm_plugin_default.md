# E-21 — WASM plugin activation default

**SPEC ref:** `SPEC_skill_plugin_system.md` §13 Q4.
**Decision required:** when NEOTH is built with the `wasm-plugin-host`
cargo feature ON (release default per cargo-dist), should an operator-
installed `.wasm` plugin be **default-active** or **default-inactive**
on first discovery?

## The two options

### (A) Default-active

Every `.wasm` file the operator drops into `~/.neoth/plugins/` runs
on first daemon start after discovery. Operators opt OUT per-plugin
via `freedom.yaml::plugins.wasm.disabled: [<id>, ...]`.

| Pros | Cons |
| ---- | ---- |
| Operator "drag-and-drop" UX matches Obsidian / VS Code expectations | A malicious plugin (typo'd download URL) runs without explicit consent |
| Fewer wizard prompts | Operator may forget a plugin is loaded |
| Consistent with the `wizard auto-installs claude/gemini/codex` precedent | Plugin manifest schema must mature first; v0.1 schema is unfrozen |

### (B) Default-inactive

Every discovered plugin lands in a `pending` state. Operator runs
`neoth plugin enable <id>` (or clicks the GUI toggle) to activate.
First-launch wizard surfaces all pending plugins for one-click
bulk-enable.

| Pros | Cons |
| ---- | ---- |
| Honours the AGENTER hard rule "no destructive auto-action without operator GO per command" | Slight friction for power operators who trust their source-of-plugins |
| Plugin sandbox bug → blast radius is one operator-confirmed plugin, not every dropped file | First-launch wizard step required (more UX surface) |
| Schema can evolve without breaking auto-loaded plugins | "Drag-and-drop" UX gap vs Obsidian |

## My recommendation

**Pick (B) — default-inactive.**

Rationale:
1. The AGENTER hard rule already pinned the conservative default for
   every other "drop a file, magic happens" path (n8n workflows ship
   inactive per N-2; bootstrap obsidian plugins are a curated picker
   not an auto-install per O-3). Plugins should match.
2. WASM sandbox bugs are higher-stakes than data-only autoloads
   (workflows / vault notes) because plugins can call hostcalls.
3. The "first-launch wizard prompt to bulk-enable" UX cost is one
   screen; the "explain why a malicious plugin ran" UX cost is much
   higher for non-developer operators.

## What ships when Alex picks one

- **(A) verdict** → flip `PluginsConfig::wasm.enabled` default ON
  for individual discovered plugins (currently true for the host
  itself, false for each entry).
- **(B) verdict** → confirm the existing default + add the
  first-launch wizard step that lists pending plugins for one-click
  bulk-enable + the `neoth plugin enable <id>` CLI surface.

## What stays unchanged regardless

- The cargo feature `wasm-plugin-host` default (ON in release
  binaries, OFF in source builds — per `[[neoth-features-default-on-
  runtime-toggle]]` memory rule).
- `freedom.yaml::plugins.wasm.enabled` master switch (operator's
  emergency stop covers both default verdicts).
- WASM resource limits (fuel + memory caps; never disabled by
  either verdict).
