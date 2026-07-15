# neoth-plugin-sdk

Public Rust API for NEOTH Wasmtime plugins and native hook integrations. It
owns the versioned guest ABI, safe hostcall wrappers, export macro, and typed
permission-level markers consumed by plugin code.

NEOTH is a local-first personal AI runtime that connects surfaces such as
Telegram, WhatsApp, Slack, and Discord to local and cloud model providers.
Plugins extend the daemon's pipeline at well-defined hook points. The Wasmtime
host limits them to the exact capability and artifact the operator approved.

> **Status:** `0.1.0-alpha.0`. The WASM host and capability gates ship in the
> NEOTH 1.0 source tree, but this SDK has not been published to crates.io yet.
> The manual publication workflow publishes this exact SDK version before the
> `neoth` core crate, because Cargo must resolve the public dependency before it
> can package the core.

## Why this crate

Skills inject context (markdown templates, profile data, repo maps) into the
pipeline. Plugins run code at hook points. [`GuestHost<L>`](src/guest.rs)
provides the actual WASM import surface and only exposes hostcalls appropriate
for marker level `L`, so accidental level mismatches fail to compile:

```rust
use neoth_plugin_sdk::guest::{GuestHost, HostcallError};
use neoth_plugin_sdk::permission::ReadOnly;

fn inspect_recall(host: GuestHost<ReadOnly>, prompt_hash: u64) -> Result<u32, HostcallError> {
    host.recall_top(prompt_hash)
}
```

The default feature set does not expose token/grant constructors. The NEOTH
daemon enables `_host` for its integration code. Because Cargo features are
consumer-selectable, `_host` and these zero-sized types are API ergonomics, not
an access-control boundary; plugin crates should not enable `_host`.

## WASM quick start

```toml
[dependencies]
neoth-plugin-sdk = "0.1.0-alpha.0"
```

```rust
use neoth_plugin_sdk::guest::{GuestHost, HostcallError};
use neoth_plugin_sdk::permission::ReadOnly;

fn run(host: GuestHost<ReadOnly>) -> Result<(), HostcallError> {
    host.log(b"example plugin running")?;
    let _hits = host.recall_top(42)?;
    Ok(())
}

neoth_plugin_sdk::export_wasm_plugin!(ReadOnly, run);
```

Build the crate as a `cdylib` for `wasm32-unknown-unknown`. The macro exports
the complete ABI v1 contract:

- `neoth_abi_version() -> i32`
- `neoth_run() -> i32`

The host refuses a missing or mismatched version before calling `neoth_run`.
Guest imports are fixed under module `neoth`: `log`, `fuel_left`, `recall_top`,
and `emit_event`.

## Native hook surface

`Hook<L>` is the separate native Rust integration surface; it is not serialized
over the WASM ABI:

```rust
use neoth_plugin_sdk::permission::ReadOnly;
use neoth_plugin_sdk::{Hook, HookContext, HookOutput, HookResult, PipelineStage};

pub struct NativeHook;

impl Hook<ReadOnly> for NativeHook {
    fn id(&self) -> &'static str {
        "example"
    }

    fn stage(&self) -> PipelineStage {
        PipelineStage::PreProviderCall
    }

    fn run(&self, ctx: HookContext<'_, ReadOnly>) -> HookResult {
        let _message = ctx.message;
        Ok(HookOutput::Continue)
    }
}
```

## Permission ladder

```text
None  →  ReadOnly  →  Write  →  Execute  →  Dangerous
```

`GuestHost<None>` exposes diagnostics and fuel. `ReadOnly` adds `recall_top`;
`Write` and higher add `emit_event`. `PermissionToken<L>`, `FreedomGrant<L>`,
and `AtLeast<T>` remain available for native integration code. All marker types
are zero-sized API guidance: a plugin can select a higher marker, but that never
raises the operator-approved runtime grant.

## Security model

1. The security boundary is the `neoth` runtime: WASM plugins execute inside
   Wasmtime with an operator-approved `HostcallPermission` in per-plugin host
   state, checked on every hostcall, plus per-invocation fuel and per-instance
   memory limits.
2. `GuestHost<L>`, `PermissionToken<L>`, and `FreedomGrant<L>` provide compile-time
   API guidance. `_host` keeps native constructors out of the default API, but it
   is not a security boundary because consumers can enable Cargo features.
3. Capability declarations are validated by the host before activation, and the
   host checks the granted runtime level again on every hostcall. Loading a module
   does not grant undeclared authority.

## Documentation

Before publication, build the local reference with
`cargo doc -p neoth-plugin-sdk --open`. After publication it is also available
at <https://docs.rs/neoth-plugin-sdk>.

Spec: [PLAN/SPEC_skill_plugin_system.md](https://github.com/The-Geek-Freaks/NEOTH/blob/main/PLAN/SPEC_skill_plugin_system.md).

## License

Dual-licensed under MIT and Apache-2.0 — pick whichever fits your
distribution. SPDX: `MIT OR Apache-2.0`.
