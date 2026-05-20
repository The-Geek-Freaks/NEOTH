# neoth-plugin-sdk

Public SDK for writing NEOTH skill plugins.

NEOTH is a personal AI gateway that bridges messaging apps (Telegram,
WhatsApp, Slack, Discord, Keet) to LLM providers (Claude, GPT, Gemini,
local Qwen3). Plugins extend the daemon's pipeline at well-defined hook
points — without ever holding more authority than they declared at
load time.

> **Status:** alpha (0.1.0-alpha.x). The plugin surface stabilises at
> 0.1.0 once the WASM plugin host (NEOTH v0.4 / GA blocker V10-04)
> ships and the surface has been exercised by ≥2 external authors.

## Why this crate

Skills inject context (markdown templates, profile data, repo maps)
into the pipeline. Plugins run code at hook points. Both need a
permission story that the host can enforce without trusting the
plugin's word — that's the sealed `PermissionToken<L>` typestate this
crate exposes:

```rust
use neoth_plugin_sdk::permission::{PermissionToken, ReadOnly};

pub fn read_recall_top_k(
    token: &PermissionToken<ReadOnly>,
    query: &str,
) -> Vec<String> {
    // ...
}
```

A plugin author can hold a `PermissionToken<ReadOnly>` but cannot
construct one — only the host (`neothd`) can mint tokens, gated behind
the `_host` Cargo feature that plugin crates MUST NOT enable.

## Quick start

```toml
[dependencies]
neoth-plugin-sdk = "0.1.0-alpha"
```

```rust
use neoth_plugin_sdk::{Hook, HookContext, HookOutput, PipelineStage};
use neoth_plugin_sdk::permission::{PermissionToken, ReadOnly};

pub struct ExamplePlugin;

impl Hook for ExamplePlugin {
    fn stage(&self) -> PipelineStage {
        PipelineStage::PreProvider
    }

    fn on_event(
        &self,
        ctx: &HookContext,
        _token: &PermissionToken<ReadOnly>,
    ) -> HookOutput {
        HookOutput::Continue
    }
}
```

## Permission ladder

```text
None  →  ReadOnly  →  Write  →  Execute  →  Dangerous
```

Each step needs a `FreedomGrant<L>` issued by the host — a plugin
cannot self-upgrade. The `AtLeast<T>` trait lets host APIs accept any
token at-or-above a required level without overloading every method.

## Security model

1. Plugins are sandboxed at the host layer (compiled-in today, WASM in
   the next phase) — this SDK provides the contract, not the sandbox.
2. The `_host` feature is the dividing line. Plugins building without
   it cannot construct `PermissionToken`, cannot call upgrade fns, and
   cannot mint `FreedomGrant`. The compile error is the security gate.
3. `inventory` registration (planned, opt-in via the `inventory`
   feature for the compiled-in flavour) keeps plugins discoverable
   without dynamic loading risk.

## Documentation

Full reference: <https://docs.rs/neoth-plugin-sdk>

Spec: `SPEC_skill_plugin_system.md` in the NEOTH repo.

## License

Dual-licensed under MIT and Apache-2.0 — pick whichever fits your
distribution. SPDX: `MIT OR Apache-2.0`.
